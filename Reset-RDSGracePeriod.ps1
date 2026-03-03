# Reset-RDSGracePeriod.ps1
# Resets the RDS 120-day grace period by deleting the TimeBomb registry value.
# Run this from an elevated (Administrator) PowerShell prompt.
#
# SYSTEM auto-elevation: Creates a temp worker script and runs it as SYSTEM
# via scheduled task, because Group Policy may strip SeTakeOwnershipPrivilege
# from admin tokens on RDS servers. SYSTEM always has all privileges.

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  RDS Grace Period Reset Tool (SYSTEM Auto-Elevation)" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Current user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -ForegroundColor Gray

# --- Write the worker script that will run as SYSTEM ---
$workerPath = Join-Path $env:TEMP "RDSGraceWorker.ps1"
$logPath    = Join-Path $env:TEMP "RDSGraceWorker.log"

Remove-Item $logPath -Force -ErrorAction SilentlyContinue

$workerScript = @'
$regKeyPath = "SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\GracePeriod"

$code = @"
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

    [StructLayout(LayoutKind.Sequential)]
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
"@

try { Add-Type -TypeDefinition $code -Language CSharp -EA Stop } catch {
    if ($_.Exception.Message -notlike '*already exists*') { throw }
}

Write-Output "Running as: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"

# Enable privileges
$r = [RegHelper]::EnablePriv("SeTakeOwnershipPrivilege")
if ($r -ne 0) { Write-Output "FAIL: SeTakeOwnershipPrivilege error $r"; exit 1 }
Write-Output "OK: SeTakeOwnershipPrivilege enabled"

[RegHelper]::EnablePriv("SeRestorePrivilege") | Out-Null
Write-Output "OK: SeRestorePrivilege enabled"

# Take ownership
$sid = New-Object System.Security.Principal.SecurityIdentifier(
    [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
$bytes = New-Object byte[] $sid.BinaryLength
$sid.GetBinaryForm($bytes, 0)

$r = [RegHelper]::TakeOwn($regKeyPath, $bytes)
if ($r -ne 0) { Write-Output "FAIL: TakeOwnership error $r"; exit 1 }
Write-Output "OK: Ownership set to Administrators"

# Grant Full Control
$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($regKeyPath,
    [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
    [System.Security.AccessControl.RegistryRights]::ChangePermissions)
$acl = $key.GetAccessControl()

$rule1 = New-Object System.Security.AccessControl.RegistryAccessRule(
    $sid, "FullControl", "ContainerInherit", "None", "Allow")
$acl.SetAccessRule($rule1)

$rule2 = New-Object System.Security.AccessControl.RegistryAccessRule(
    "sadmin", "FullControl", "ContainerInherit", "None", "Allow")
$acl.SetAccessRule($rule2)

$key.SetAccessControl($acl)
$key.Close()
Write-Output "OK: Full Control granted to Administrators and sadmin"

# Delete TimeBomb
$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($regKeyPath, $true)
$deleted = 0
foreach ($v in $key.GetValueNames()) {
    if ($v -like "L`$RTMTIMEBOMB*") {
        $key.DeleteValue($v)
        Write-Output "OK: Deleted $v"
        $deleted++
    }
}
if ($deleted -eq 0) { Write-Output "INFO: No TimeBomb values found (already clean)" }
$key.Close()

Write-Output "SUCCESS: RDS Grace Period has been reset"
'@

# Write worker to temp
$workerScript | Out-File -FilePath $workerPath -Encoding UTF8 -Force

Write-Host "Worker script written to: $workerPath" -ForegroundColor Gray
Write-Host ""

# --- Create and run scheduled task as SYSTEM ---
$taskName = "RDSGraceReset_$(Get-Random)"

Write-Host "Creating scheduled task as SYSTEM..." -ForegroundColor Yellow

schtasks.exe /Create /TN $taskName /TR "powershell.exe -ExecutionPolicy Bypass -NoProfile -File `"$workerPath`" > `"$logPath`" 2>&1" /SC ONCE /ST 00:00 /RU SYSTEM /RL HIGHEST /F | Out-Null

if ($LASTEXITCODE -ne 0) {
    Write-Host "FAILED to create scheduled task. Are you running as Administrator?" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "Running task as SYSTEM..." -ForegroundColor Yellow

schtasks.exe /Run /TN $taskName | Out-Null

# Wait for completion
$maxWait = 30
$waited = 0
while ($waited -lt $maxWait) {
    Start-Sleep -Seconds 2
    $waited += 2
    $status = schtasks.exe /Query /TN $taskName /FO CSV /NH 2>$null
    if ($status -match "Ready" -or $status -match "Could not start") { break }
}

# Cleanup task
schtasks.exe /Delete /TN $taskName /F 2>$null | Out-Null

# Show results
Write-Host ""
Write-Host "--- SYSTEM Execution Results ---" -ForegroundColor Cyan

if (Test-Path $logPath) {
    $output = Get-Content $logPath -Raw
    Write-Host $output

    # Cleanup temp files
    Remove-Item $logPath -Force -ErrorAction SilentlyContinue
    Remove-Item $workerPath -Force -ErrorAction SilentlyContinue

    if ($output -match "SUCCESS") {
        Write-Host "--- End Results ---" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "  Grace Period Reset Complete!" -ForegroundColor Green
        Write-Host "  A reboot is required." -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Green
        Write-Host ""
        Read-Host "Press Enter to reboot now (or Ctrl+C to cancel)"
        Restart-Computer -Force
    } else {
        Write-Host "--- End Results ---" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Something went wrong. Check the output above." -ForegroundColor Red
        Read-Host "Press Enter to exit"
    }
} else {
    Write-Host "No output captured. The task may have failed to start." -ForegroundColor Red
    Write-Host "Try running this command manually to test:" -ForegroundColor Yellow
    Write-Host "  schtasks /Create /TN TestTask /TR ""cmd /c whoami > C:\temp\test.txt"" /SC ONCE /ST 00:00 /RU SYSTEM /RL HIGHEST /F" -ForegroundColor Gray
    Remove-Item $workerPath -Force -ErrorAction SilentlyContinue
    Read-Host "Press Enter to exit"
}
