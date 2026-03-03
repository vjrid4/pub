# Reset-RDSGracePeriod.ps1
# Resets the RDS 120-day grace period by deleting the TimeBomb registry value.
# Run from an elevated (Administrator) PowerShell prompt:
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\Reset-RDSGracePeriod.ps1

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  RDS Grace Period Reset Tool (SYSTEM Auto-Elevation)" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Current user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -ForegroundColor Gray

$workerPath = "$env:TEMP\RDSGraceWorker.ps1"
$logPath    = "$env:TEMP\RDSGraceWorker.log"

Remove-Item $logPath -Force -ErrorAction SilentlyContinue
Remove-Item $workerPath -Force -ErrorAction SilentlyContinue

# --- Worker script: runs as SYSTEM ---
# Does EVERYTHING via Win32 API: open key, take ownership, set ACL, enum values, delete values.
# Never uses .NET OpenSubKey which can silently open read-only.

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
    Log "64-bit process: `$([Environment]::Is64BitProcess)"
    Log ""

    `$regKeyPath = "SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\GracePeriod"

    `$code = @'
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

public class RegHelper
{
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr h, uint acc, out IntPtr t);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LookupPrivilegeValue(string sys, string name, out long luid);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr t, bool d, IntPtr newState, uint b, IntPtr p, IntPtr r);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern void SetLastError(uint e);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern int RegOpenKeyEx(IntPtr hk, string sub, uint opt, uint sam, out IntPtr res);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern int RegCloseKey(IntPtr hk);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern int RegDeleteValue(IntPtr hk, string valueName);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern int RegEnumValue(IntPtr hk, uint index, StringBuilder name, ref uint nameLen,
        IntPtr reserved, IntPtr type, IntPtr data, IntPtr dataLen);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern int SetSecurityInfo(IntPtr h, uint objType, uint secInfo,
        byte[] owner, byte[] group, IntPtr dacl, IntPtr sacl);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern int SetNamedSecurityInfo(string objectName, uint objType, uint secInfo,
        byte[] owner, byte[] group, IntPtr dacl, IntPtr sacl);

    static readonly IntPtr HKLM = new IntPtr(unchecked((int)0x80000002));

    public static int EnablePriv(string priv)
    {
        IntPtr tok;
        if (!OpenProcessToken(GetCurrentProcess(), 0x0028, out tok)) return -1;
        long luid;
        if (!LookupPrivilegeValue(null, priv, out luid)) return -2;

        byte[] tp = new byte[16];
        BitConverter.GetBytes((uint)1).CopyTo(tp, 0);
        BitConverter.GetBytes(luid).CopyTo(tp, 4);
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

    // Take ownership using SetNamedSecurityInfo (no handle needed)
    public static int TakeOwnership(string fullKeyPath, byte[] ownerSid)
    {
        // SE_REGISTRY_KEY = 4, OWNER_SECURITY_INFORMATION = 1
        return SetNamedSecurityInfo(fullKeyPath, 4, 1, ownerSid, null, IntPtr.Zero, IntPtr.Zero);
    }

    // Open key, enumerate all value names, close key
    public static string[] EnumValues(string subKeyPath, out int error)
    {
        IntPtr hk;
        // KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS = 0x0019
        error = RegOpenKeyEx(HKLM, subKeyPath, 0, 0x20019, out hk);
        if (error != 0) return new string[0];

        var names = new System.Collections.Generic.List<string>();
        uint index = 0;
        while (true)
        {
            StringBuilder name = new StringBuilder(1024);
            uint nameLen = 1024;
            int r = RegEnumValue(hk, index, name, ref nameLen, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (r != 0) break; // ERROR_NO_MORE_ITEMS = 259
            names.Add(name.ToString());
            index++;
        }
        RegCloseKey(hk);
        error = 0;
        return names.ToArray();
    }

    // Open key with full access and delete a value
    public static int DeleteValue(string subKeyPath, string valueName)
    {
        IntPtr hk;
        // KEY_ALL_ACCESS = 0xF003F
        int e = RegOpenKeyEx(HKLM, subKeyPath, 0, 0xF003F, out hk);
        if (e != 0) return 10000 + e;
        e = RegDeleteValue(hk, valueName);
        RegCloseKey(hk);
        if (e != 0) return 20000 + e;
        return 0;
    }

    // Open with KEY_SET_VALUE and delete
    public static int DeleteValueWrite(string subKeyPath, string valueName)
    {
        IntPtr hk;
        // KEY_SET_VALUE = 0x0002
        int e = RegOpenKeyEx(HKLM, subKeyPath, 0, 0x0002, out hk);
        if (e != 0) return 30000 + e;
        e = RegDeleteValue(hk, valueName);
        RegCloseKey(hk);
        if (e != 0) return 40000 + e;
        return 0;
    }
}
'@

    try { Add-Type -TypeDefinition `$code -Language CSharp -ErrorAction Stop } catch {
        if (`$_.Exception.Message -notlike '*already exists*') { throw }
    }
    Log "OK: P/Invoke loaded"

    # --- Step 1: Enable ALL useful privileges ---
    Log "Step 1: Enabling privileges..."
    foreach (`$priv in @("SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege", "SeSecurityPrivilege")) {
        `$r = [RegHelper]::EnablePriv(`$priv)
        Log "  `$priv = `$r (0=OK)"
    }

    # --- Step 2: Take ownership using SetNamedSecurityInfo ---
    # This uses the registry path format MACHINE\path instead of a handle
    Log ""
    Log "Step 2: Taking ownership..."

    `$sid = New-Object System.Security.Principal.SecurityIdentifier(
        [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, `$null)
    `$sidBytes = New-Object byte[] `$sid.BinaryLength
    `$sid.GetBinaryForm(`$sidBytes, 0)

    `$namedPath = "MACHINE\`$regKeyPath"
    `$r = [RegHelper]::TakeOwnership(`$namedPath, `$sidBytes)
    Log "  SetNamedSecurityInfo result: `$r (0=OK)"

    # --- Step 3: Set permissions (Administrators + sadmin + SYSTEM) ---
    Log ""
    Log "Step 3: Setting permissions..."
    try {
        `$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(`$regKeyPath,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            [System.Security.AccessControl.RegistryRights]::ChangePermissions -bor
            [System.Security.AccessControl.RegistryRights]::TakeOwnership -bor
            [System.Security.AccessControl.RegistryRights]::ReadKey)

        if (`$null -ne `$key) {
            `$acl = `$key.GetAccessControl()
            `$acl.SetOwner(`$sid)

            # Administrators Full Control
            `$acl.SetAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule(
                `$sid, "FullControl", "ContainerInherit", "None", "Allow")))

            # SYSTEM Full Control (so SYSTEM doesn't lose access!)
            `$systemSid = New-Object System.Security.Principal.SecurityIdentifier(
                [System.Security.Principal.WellKnownSidType]::LocalSystemSid, `$null)
            `$acl.SetAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule(
                `$systemSid, "FullControl", "ContainerInherit", "None", "Allow")))

            # sadmin Full Control
            `$acl.SetAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule(
                "sadmin", "FullControl", "ContainerInherit", "None", "Allow")))

            `$key.SetAccessControl(`$acl)
            `$key.Close()
            Log "  OK: Permissions set (Administrators + SYSTEM + sadmin = FullControl)"
        } else {
            Log "  WARNING: Could not open key via .NET for permissions"
        }
    } catch {
        Log "  WARNING: .NET permissions failed: `$(`$_.Exception.Message)"
    }

    # --- Step 4: Enumerate values ---
    Log ""
    Log "Step 4: Enumerating values..."
    `$enumErr = 0
    `$values = [RegHelper]::EnumValues(`$regKeyPath, [ref]`$enumErr)
    Log "  EnumValues result: err=`$enumErr, count=`$(`$values.Count)"
    foreach (`$v in `$values) { Log "  Found value: '`$v'" }

    # --- Step 5: Delete ALL values via Win32 API ---
    Log ""
    Log "Step 5: Deleting values via Win32 RegDeleteValue..."
    `$deleted = 0
    foreach (`$v in `$values) {
        if (`$v -eq '') { continue }  # skip default value

        # Try KEY_ALL_ACCESS first
        `$r = [RegHelper]::DeleteValue(`$regKeyPath, `$v)
        if (`$r -ne 0) {
            Log "  DeleteValue (full) for '`$v' returned `$r, trying KEY_SET_VALUE..."
            `$r = [RegHelper]::DeleteValueWrite(`$regKeyPath, `$v)
        }
        if (`$r -eq 0) {
            Log "  OK: Deleted '`$v'"
            `$deleted++
        } else {
            Log "  FAIL: Could not delete '`$v' (error `$r)"
        }
    }

    if (`$deleted -eq 0 -and `$values.Count -le 1) {
        Log "  INFO: No values to delete (key is empty)"
    }

    # --- Verify deletion ---
    Log ""
    Log "Step 6: Verifying..."
    `$values2 = [RegHelper]::EnumValues(`$regKeyPath, [ref]`$enumErr)
    Log "  Values remaining: `$(`$values2.Count)"
    foreach (`$v in `$values2) { Log "  Remaining: '`$v'" }

    Log ""
    if (`$deleted -gt 0) {
        Log "SUCCESS: Deleted `$deleted value(s). RDS Grace Period has been reset."
    } elseif (`$values.Count -le 1) {
        Log "SUCCESS: Key was already clean (no TimeBomb values found)."
    } else {
        Log "FAIL: Could not delete values. See errors above."
    }
} catch {
    Log "EXCEPTION: `$(`$_.Exception.Message)"
    Log "AT: `$(`$_.InvocationInfo.PositionMessage)"
    exit 1
}
"@

$workerScript | Out-File -FilePath $workerPath -Encoding ASCII -Force

Write-Host "Worker script written to: $workerPath" -ForegroundColor Gray
Write-Host ""

$taskName = "RDSGraceReset_$(Get-Random)"

Write-Host "Creating scheduled task as SYSTEM..." -ForegroundColor Yellow

$taskCmd = "cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -File `"$workerPath`""

schtasks.exe /Create /TN $taskName /TR $taskCmd /SC ONCE /ST 00:00 /RU SYSTEM /RL HIGHEST /F 2>&1 | ForEach-Object { Write-Host "  schtasks: $_" -ForegroundColor Gray }

if ($LASTEXITCODE -ne 0) {
    Write-Host "FAILED to create scheduled task." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "Starting task..." -ForegroundColor Yellow
schtasks.exe /Run /TN $taskName 2>&1 | ForEach-Object { Write-Host "  schtasks: $_" -ForegroundColor Gray }

Write-Host "Waiting for SYSTEM task to complete..." -ForegroundColor Yellow
$maxWait = 60
$waited = 0
while ($waited -lt $maxWait) {
    Start-Sleep -Seconds 3
    $waited += 3
    Write-Host "  ...waited ${waited}s" -ForegroundColor Gray

    if (Test-Path $logPath) {
        $content = Get-Content $logPath -Raw -ErrorAction SilentlyContinue
        if ($content -match "SUCCESS" -or $content -match "FAIL:" -or $content -match "EXCEPTION") {
            Write-Host "  Task completed." -ForegroundColor Green
            break
        }
    }
}

schtasks.exe /Delete /TN $taskName /F 2>$null | Out-Null

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
    Remove-Item $workerPath -Force -ErrorAction SilentlyContinue
    Read-Host "Press Enter to exit"
}
