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
# The worker handles ALL logging internally via Start-Transcript
# so we don't depend on shell redirection from schtasks.

$workerScript = @"
`$ErrorActionPreference = 'Stop'
`$logFile = "$logPath"

# Internal logging function - writes to both console and log file
function Log(`$msg) {
    `$msg | Out-File -FilePath `$logFile -Append -Encoding UTF8
}

try {
    Log "=== RDS Grace Period Worker ==="
    Log "Running as: `$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    Log "Timestamp: `$(Get-Date)"
    Log ""

    `$regKeyPath = "SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\GracePeriod"

    # --- Load P/Invoke ---
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
    static extern bool AdjustTokenPrivileges(IntPtr t, bool d, ref TP n, uint b, IntPtr p, IntPtr r);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern void SetLastError(uint e);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern int RegOpenKeyEx(IntPtr hk, string sub, uint opt, uint sam, out IntPtr res);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern int RegCloseKey(IntPtr hk);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern int SetSecurityInfo(IntPtr h, uint t, uint si, byte[] own, byte[] grp, IntPtr dacl, IntPtr sacl);

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct TP { public uint Count; public long Luid; public uint Attr; }

    public static int EnablePriv(string priv)
    {
        IntPtr tok; if (!OpenProcessToken(GetCurrentProcess(), 0x28, out tok)) return -1;
        long luid; if (!LookupPrivilegeValue(null, priv, out luid)) return -2;
        TP tp; tp.Count = 1; tp.Luid = luid; tp.Attr = 2;
        SetLastError(0);
        if (!AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) return -3;
        return Marshal.GetLastWin32Error();
    }

    public static int TakeOwn(string path, byte[] sid)
    {
        IntPtr hk; int e = RegOpenKeyEx(new IntPtr(unchecked((int)0x80000002)), path, 0, 0x00080000, out hk);
        if (e != 0) return e;
        e = SetSecurityInfo(hk, 4, 1, sid, null, IntPtr.Zero, IntPtr.Zero);
        RegCloseKey(hk); return e;
    }
}
'@

    try { Add-Type -TypeDefinition `$code -Language CSharp -ErrorAction Stop } catch {
        if (`$_.Exception.Message -notlike '*already exists*') { throw }
    }
    Log "OK: P/Invoke loaded"

    # --- Step 1: Enable privileges ---
    `$r = [RegHelper]::EnablePriv("SeTakeOwnershipPrivilege")
    if (`$r -ne 0) { Log "FAIL: SeTakeOwnershipPrivilege error `$r"; exit 1 }
    Log "OK: SeTakeOwnershipPrivilege enabled"

    [RegHelper]::EnablePriv("SeRestorePrivilege") | Out-Null
    Log "OK: SeRestorePrivilege enabled"

    # --- Step 2: Take ownership ---
    `$sid = New-Object System.Security.Principal.SecurityIdentifier(
        [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, `$null)
    `$bytes = New-Object byte[] `$sid.BinaryLength
    `$sid.GetBinaryForm(`$bytes, 0)

    `$r = [RegHelper]::TakeOwn(`$regKeyPath, `$bytes)
    if (`$r -ne 0) { Log "FAIL: TakeOwnership error `$r (2=NotFound, 5=AccessDenied)"; exit 1 }
    Log "OK: Ownership set to Administrators"

    # --- Step 3: Grant Full Control ---
    `$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(`$regKeyPath,
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]::ChangePermissions)

    if (`$null -eq `$key) { Log "FAIL: Could not open key for ChangePermissions"; exit 1 }

    `$acl = `$key.GetAccessControl()

    `$rule1 = New-Object System.Security.AccessControl.RegistryAccessRule(
        `$sid, "FullControl", "ContainerInherit", "None", "Allow")
    `$acl.SetAccessRule(`$rule1)

    `$rule2 = New-Object System.Security.AccessControl.RegistryAccessRule(
        "sadmin", "FullControl", "ContainerInherit", "None", "Allow")
    `$acl.SetAccessRule(`$rule2)

    `$key.SetAccessControl(`$acl)
    `$key.Close()
    Log "OK: Full Control granted to Administrators and sadmin"

    # --- Step 4: Delete TimeBomb ---
    `$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(`$regKeyPath, `$true)
    if (`$null -eq `$key) { Log "FAIL: Could not open key for write"; exit 1 }

    `$deleted = 0
    foreach (`$v in `$key.GetValueNames()) {
        if (`$v -like 'L`$RTMTIMEBOMB*') {
            `$key.DeleteValue(`$v)
            Log "OK: Deleted value `$v"
            `$deleted++
        }
    }
    if (`$deleted -eq 0) { Log "INFO: No TimeBomb values found (already clean)" }
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

# Use cmd /c to launch powershell — schtasks needs a simple command string
$taskCmd = "cmd.exe /c powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -File `"$workerPath`""

schtasks.exe /Create /TN $taskName /TR $taskCmd /SC ONCE /ST 00:00 /RU SYSTEM /RL HIGHEST /F 2>&1 | ForEach-Object { Write-Host "  schtasks: $_" -ForegroundColor Gray }

if ($LASTEXITCODE -ne 0) {
    Write-Host "FAILED to create scheduled task. Are you running as Administrator?" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "Starting task..." -ForegroundColor Yellow
schtasks.exe /Run /TN $taskName 2>&1 | ForEach-Object { Write-Host "  schtasks: $_" -ForegroundColor Gray }

# Wait for completion (check for log file to appear and stabilize)
Write-Host "Waiting for SYSTEM task to complete..." -ForegroundColor Yellow
$maxWait = 45
$waited = 0
while ($waited -lt $maxWait) {
    Start-Sleep -Seconds 3
    $waited += 3
    Write-Host "  ...waited ${waited}s" -ForegroundColor Gray

    # Check if log file exists and contains SUCCESS or FAIL
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

    # Cleanup temp files
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
    Write-Host "Debug: Check if worker exists at: $workerPath" -ForegroundColor Yellow

    Remove-Item $workerPath -Force -ErrorAction SilentlyContinue
    Read-Host "Press Enter to exit"
}
