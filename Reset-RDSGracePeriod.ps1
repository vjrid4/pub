# Reset-RDSGracePeriod.ps1
# Resets the RDS 120-day grace period by deleting the TimeBomb registry value.
# Run this from an elevated (Administrator) PowerShell prompt:
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\Reset-RDSGracePeriod.ps1

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  RDS Grace Period Reset Tool (SYSTEM Auto-Elevation)" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Current user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -ForegroundColor Gray

# --- Paths ---
$workerPath = "$env:TEMP\RDSGraceWorker.ps1"
$logPath    = "$env:TEMP\RDSGraceWorker.log"

Remove-Item $logPath -Force -ErrorAction SilentlyContinue
Remove-Item $workerPath -Force -ErrorAction SilentlyContinue

# --- Worker script: runs as SYSTEM, writes its own log file ---
# SYSTEM has implicit full access to most registry keys, so we skip
# the problematic AdjustTokenPrivileges entirely and go straight to
# RegOpenKeyEx with WRITE_OWNER | WRITE_DAC | KEY_ALL_ACCESS.

$workerScript = @"
`$ErrorActionPreference = 'Stop'
`$logFile = "$logPath"

function Log(`$msg) {
    `$msg | Out-File -FilePath `$logFile -Append -Encoding UTF8
}

try {
    Log "=== RDS Grace Period Worker ==="
    Log "Running as: `$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    Log "Timestamp: `$(Get-Date)"
    Log ""

    `$regKeyPath = "SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\GracePeriod"

    # --- Load P/Invoke (no struct needed - avoids alignment issues) ---
    `$code = @'
using System;
using System.Runtime.InteropServices;
public class RegHelper
{
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr h, uint acc, out IntPtr t);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool LookupPrivilegeValue(string sys, string name, out long luid);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr t, bool d, IntPtr newState, uint b, IntPtr p, IntPtr r);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern void SetLastError(uint e);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern int RegOpenKeyEx(IntPtr hk, string sub, uint opt, uint sam, out IntPtr res);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern int RegCloseKey(IntPtr hk);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern int SetSecurityInfo(IntPtr h, uint t, uint si, byte[] own, byte[] grp, IntPtr dacl, IntPtr sacl);

    // Manually marshal TOKEN_PRIVILEGES as raw bytes to avoid struct alignment bugs
    public static int EnablePriv(string priv)
    {
        IntPtr tok;
        if (!OpenProcessToken(GetCurrentProcess(), 0x0020 | 0x0008, out tok)) return -1;
        long luid;
        if (!LookupPrivilegeValue(null, priv, out luid)) return -2;

        // TOKEN_PRIVILEGES layout: Count(4 bytes) + LUID(8 bytes) + Attributes(4 bytes) = 16 bytes
        byte[] tp = new byte[16];
        // PrivilegeCount = 1
        BitConverter.GetBytes((uint)1).CopyTo(tp, 0);
        // LUID at offset 4
        BitConverter.GetBytes(luid).CopyTo(tp, 4);
        // SE_PRIVILEGE_ENABLED = 2 at offset 12
        BitConverter.GetBytes((uint)2).CopyTo(tp, 12);

        IntPtr tpPtr = Marshal.AllocHGlobal(16);
        Marshal.Copy(tp, 0, tpPtr, 16);

        SetLastError(0);
        bool ok = AdjustTokenPrivileges(tok, false, tpPtr, 0, IntPtr.Zero, IntPtr.Zero);
        int err = Marshal.GetLastWin32Error();
        Marshal.FreeHGlobal(tpPtr);

        if (!ok) return -3;
        return err;
    }

    static readonly IntPtr HKLM = new IntPtr(unchecked((int)0x80000002));

    public static int TakeOwn(string path, byte[] sid)
    {
        // WRITE_OWNER = 0x80000
        IntPtr hk;
        int e = RegOpenKeyEx(HKLM, path, 0, 0x00080000, out hk);
        if (e != 0) return 10000 + e;
        e = SetSecurityInfo(hk, 4, 1, sid, null, IntPtr.Zero, IntPtr.Zero);
        RegCloseKey(hk);
        if (e != 0) return 20000 + e;
        return 0;
    }

    public static int SetDacl(string path, byte[] sid)
    {
        // WRITE_DAC = 0x40000
        IntPtr hk;
        int e = RegOpenKeyEx(HKLM, path, 0, 0x00040000, out hk);
        if (e != 0) return 30000 + e;
        // DACL_SECURITY_INFORMATION = 4
        e = SetSecurityInfo(hk, 4, 4, null, null, IntPtr.Zero, IntPtr.Zero);
        RegCloseKey(hk);
        // We don't fail on DACL reset - we'll set ACL via .NET after
        return 0;
    }

    public static int OpenFull(string path)
    {
        // KEY_ALL_ACCESS = 0xF003F
        IntPtr hk;
        int e = RegOpenKeyEx(HKLM, path, 0, 0xF003F, out hk);
        if (e == 0) RegCloseKey(hk);
        return e;
    }
}
'@

    try { Add-Type -TypeDefinition `$code -Language CSharp -ErrorAction Stop } catch {
        if (`$_.Exception.Message -notlike '*already exists*') { throw }
    }
    Log "OK: P/Invoke loaded"

    # --- Step 1: Enable privileges using raw byte marshaling ---
    Log "Step 1: Enabling privileges..."
    `$r = [RegHelper]::EnablePriv("SeTakeOwnershipPrivilege")
    Log "  SeTakeOwnershipPrivilege result: `$r"
    if (`$r -ne 0) {
        Log "  WARNING: Could not enable SeTakeOwnershipPrivilege (error `$r)"
        Log "  Continuing anyway - SYSTEM may have implicit access..."
    } else {
        Log "  OK: SeTakeOwnershipPrivilege enabled"
    }

    `$r2 = [RegHelper]::EnablePriv("SeRestorePrivilege")
    Log "  SeRestorePrivilege result: `$r2"

    # --- Step 2: Take ownership ---
    Log ""
    Log "Step 2: Taking ownership..."
    `$sid = New-Object System.Security.Principal.SecurityIdentifier(
        [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, `$null)
    `$bytes = New-Object byte[] `$sid.BinaryLength
    `$sid.GetBinaryForm(`$bytes, 0)

    `$r = [RegHelper]::TakeOwn(`$regKeyPath, `$bytes)
    if (`$r -ne 0) {
        Log "  WARNING: TakeOwnership via WRITE_OWNER returned `$r"
        Log "  Trying direct full access instead..."

        # SYSTEM might already have full access - try opening directly
        `$r3 = [RegHelper]::OpenFull(`$regKeyPath)
        if (`$r3 -ne 0) {
            Log "FAIL: Cannot access key at all (TakeOwn=`$r, FullAccess=`$r3)"
            exit 1
        }
        Log "  OK: SYSTEM has direct full access to key"
    } else {
        Log "  OK: Ownership set to Administrators"
    }

    # --- Step 3: Grant Full Control ---
    Log ""
    Log "Step 3: Granting Full Control..."
    try {
        `$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(`$regKeyPath,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            [System.Security.AccessControl.RegistryRights]::ChangePermissions -bor
            [System.Security.AccessControl.RegistryRights]::TakeOwnership -bor
            [System.Security.AccessControl.RegistryRights]::ReadKey)

        if (`$null -eq `$key) {
            Log "  Trying alternate open method..."
            `$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(`$regKeyPath, `$true)
        }

        if (`$null -eq `$key) { Log "FAIL: Could not open key"; exit 1 }

        `$acl = `$key.GetAccessControl(
            [System.Security.AccessControl.AccessControlSections]::All)

        # Set owner first
        `$acl.SetOwner(`$sid)

        `$rule1 = New-Object System.Security.AccessControl.RegistryAccessRule(
            `$sid, "FullControl", "ContainerInherit", "None", "Allow")
        `$acl.SetAccessRule(`$rule1)

        `$rule2 = New-Object System.Security.AccessControl.RegistryAccessRule(
            "sadmin", "FullControl", "ContainerInherit", "None", "Allow")
        `$acl.SetAccessRule(`$rule2)

        `$key.SetAccessControl(`$acl)
        `$key.Close()
        Log "  OK: Owner set + Full Control granted to Administrators and sadmin"
    } catch {
        Log "  EXCEPTION in permissions: `$(`$_.Exception.Message)"
        Log "  Trying to continue with deletion anyway..."
    }

    # --- Step 4: Delete TimeBomb ---
    Log ""
    Log "Step 4: Deleting TimeBomb..."
    `$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(`$regKeyPath, `$true)
    if (`$null -eq `$key) { Log "FAIL: Could not open key for write"; exit 1 }

    `$allValues = `$key.GetValueNames()
    Log "  Found `$(`$allValues.Count) values in key: `$(`$allValues -join ', ')"

    `$deleted = 0
    foreach (`$v in `$allValues) {
        # Delete ALL values except the default
        if (`$v -ne '') {
            try {
                `$key.DeleteValue(`$v)
                Log "  OK: Deleted value '`$v'"
                `$deleted++
            } catch {
                Log "  WARN: Could not delete '`$v': `$(`$_.Exception.Message)"
            }
        }
    }
    if (`$deleted -eq 0) { Log "  INFO: No values to delete" }
    `$key.Close()

    Log ""
    Log "SUCCESS: RDS Grace Period has been reset"
} catch {
    Log "EXCEPTION: `$(`$_.Exception.Message)"
    Log "AT: `$(`$_.InvocationInfo.PositionMessage)"
    exit 1
}
"@

# Write worker script
$workerScript | Out-File -FilePath $workerPath -Encoding ASCII -Force

Write-Host "Worker script written to: $workerPath" -ForegroundColor Gray
Write-Host ""

# --- Create and run scheduled task as SYSTEM ---
$taskName = "RDSGraceReset_$(Get-Random)"

Write-Host "Creating scheduled task '$taskName' as SYSTEM..." -ForegroundColor Yellow

$taskCmd = "cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -File `"$workerPath`""

schtasks.exe /Create /TN $taskName /TR $taskCmd /SC ONCE /ST 00:00 /RU SYSTEM /RL HIGHEST /F 2>&1 | ForEach-Object { Write-Host "  schtasks: $_" -ForegroundColor Gray }

if ($LASTEXITCODE -ne 0) {
    Write-Host "FAILED to create scheduled task. Are you running as Administrator?" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "Starting task..." -ForegroundColor Yellow
schtasks.exe /Run /TN $taskName 2>&1 | ForEach-Object { Write-Host "  schtasks: $_" -ForegroundColor Gray }

Write-Host "Waiting for SYSTEM task to complete..." -ForegroundColor Yellow
$maxWait = 45
$waited = 0
while ($waited -lt $maxWait) {
    Start-Sleep -Seconds 3
    $waited += 3
    Write-Host "  ...waited ${waited}s" -ForegroundColor Gray

    if (Test-Path $logPath) {
        $content = Get-Content $logPath -Raw -ErrorAction SilentlyContinue
        if ($content -match "SUCCESS" -or $content -match "FAIL" -or $content -match "EXCEPTION") {
            Write-Host "  Task completed." -ForegroundColor Green
            break
        }
    }
}

# Cleanup task
schtasks.exe /Delete /TN $taskName /F 2>$null | Out-Null

# Show results
Write-Host ""
Write-Host "============ SYSTEM Execution Log ============" -ForegroundColor Cyan

if (Test-Path $logPath) {
    $output = Get-Content $logPath -Raw
    Write-Host $output

    Remove-Item $logPath -Force -ErrorAction SilentlyContinue
    Remove-Item $workerPath -Force -ErrorAction SilentlyContinue

    if ($output -match "SUCCESS") {
        Write-Host "==============================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "  Grace Period Reset Complete!" -ForegroundColor Green
        Write-Host "  A reboot is required." -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Green
        Write-Host ""
        Read-Host "Press Enter to reboot now (or Ctrl+C to cancel)"
        Restart-Computer -Force
    } else {
        Write-Host "==============================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Task ran but encountered errors. See log above." -ForegroundColor Red
        Read-Host "Press Enter to exit"
    }
} else {
    Write-Host "NO LOG FILE FOUND at: $logPath" -ForegroundColor Red
    Write-Host ""
    Write-Host "The scheduled task may not have started. Possible causes:" -ForegroundColor Yellow
    Write-Host "  - Task Scheduler service not running" -ForegroundColor Gray
    Write-Host "  - SYSTEM account restricted by policy" -ForegroundColor Gray
    Write-Host "  - Antivirus blocked the script" -ForegroundColor Gray
    Write-Host ""

    Remove-Item $workerPath -Force -ErrorAction SilentlyContinue
    Read-Host "Press Enter to exit"
}
