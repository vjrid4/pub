#Requires -RunAsAdministrator
# Reset-RDSGracePeriod.ps1
# Resets the RDS 120-day grace period by deleting the TimeBomb registry value.
# Must be run as Administrator (elevated prompt).
#
# Strategy: Group Policy may strip SeTakeOwnershipPrivilege from admin tokens.
# SYSTEM always has all privileges, so we auto-elevate to SYSTEM using a
# scheduled task if the current token lacks the privilege.

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

$regKeyPath = "SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\GracePeriod"

# =============================================================================
# SYSTEM AUTO-ELEVATION: If not running as SYSTEM, re-launch via scheduled task
# =============================================================================
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$isSystem = $currentUser.IsSystem

if (-not $isSystem) {
    Write-Host "Current user: $($currentUser.Name)" -ForegroundColor Cyan
    Write-Host "Not running as SYSTEM. Elevating via scheduled task..." -ForegroundColor Yellow

    $scriptPath = $MyInvocation.MyCommand.Path
    if (-not $scriptPath) {
        # If run via paste or ISE, save to a temp file
        $scriptPath = Join-Path $env:TEMP "Reset-RDSGracePeriod_temp.ps1"
        Copy-Item -Path $PSCommandPath -Destination $scriptPath -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path $scriptPath)) {
            # Last resort: write self to temp
            $MyInvocation.MyCommand.ScriptBlock.ToString() | Out-File -FilePath $scriptPath -Encoding UTF8 -Force
        }
    }

    $taskName = "ResetRDSGracePeriod_$(Get-Random)"
    $logFile  = Join-Path $env:TEMP "RDSGraceReset.log"

    # Remove old log if exists
    Remove-Item $logFile -Force -ErrorAction SilentlyContinue

    Write-Host "  Creating scheduled task '$taskName'..." -ForegroundColor Gray

    # Create a scheduled task that runs this same script as SYSTEM
    $action  = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-ExecutionPolicy Bypass -NoProfile -File `"$scriptPath`" *> `"$logFile`""
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal `
        -Settings $settings -Force | Out-Null

    Write-Host "  Starting task as SYSTEM..." -ForegroundColor Gray
    Start-ScheduledTask -TaskName $taskName

    # Wait for the task to complete (up to 60 seconds)
    $timeout = 60
    $elapsed = 0
    do {
        Start-Sleep -Seconds 2
        $elapsed += 2
        $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
        $taskState = (Get-ScheduledTask -TaskName $taskName).State
    } while ($taskState -eq "Running" -and $elapsed -lt $timeout)

    # Cleanup the scheduled task
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

    # Show the results from the SYSTEM execution
    Write-Host "`n--- Output from SYSTEM execution ---" -ForegroundColor Cyan
    if (Test-Path $logFile) {
        Get-Content $logFile | ForEach-Object { Write-Host $_ }
        Remove-Item $logFile -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "  (No output log found - task may have failed to start)" -ForegroundColor Red
    }
    Write-Host "--- End of SYSTEM output ---`n" -ForegroundColor Cyan

    # Prompt for reboot (from the user's session)
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Script completed." -ForegroundColor Green
    Write-Host "  A reboot is required for changes to take effect." -ForegroundColor Yellow
    Write-Host "========================================`n" -ForegroundColor Cyan

    Read-Host "Press Enter to reboot now (or Ctrl+C to cancel)"
    Restart-Computer -Force
    exit
}

# =============================================================================
# BELOW RUNS AS SYSTEM
# =============================================================================
Write-Host "Running as SYSTEM - full privileges available." -ForegroundColor Green

# --- P/Invoke class ---
$nativeCode = @'
using System;
using System.Runtime.InteropServices;

public class NativeRegistry
{
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public long Luid;
        public uint Attributes;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle, bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState, uint BufferLength,
        IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    static extern void SetLastError(uint dwErrCode);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern int RegOpenKeyEx(
        IntPtr hKey, string subKey, uint options, uint samDesired, out IntPtr phkResult);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern int RegCloseKey(IntPtr hKey);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern int SetSecurityInfo(
        IntPtr handle, uint ObjectType, uint SecurityInfo,
        byte[] psidOwner, byte[] psidGroup, IntPtr pDacl, IntPtr pSacl);

    const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const uint TOKEN_QUERY = 0x0008;
    const uint SE_PRIVILEGE_ENABLED = 0x00000002;

    static readonly IntPtr HKLM = new IntPtr(unchecked((int)0x80000002));

    const uint WRITE_OWNER = 0x00080000;
    const uint SE_REGISTRY_KEY = 4;
    const uint OWNER_SECURITY_INFORMATION = 0x00000001;

    public static int EnablePrivilege(string privilege)
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token))
            return -1;

        long luid;
        if (!LookupPrivilegeValue(null, privilege, out luid))
            return -2;

        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        tp.PrivilegeCount = 1;
        tp.Luid = luid;
        tp.Attributes = SE_PRIVILEGE_ENABLED;

        SetLastError(0);
        if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
            return -3;

        return Marshal.GetLastWin32Error();
    }

    public static int TakeOwnership(string subKeyPath, byte[] ownerSid)
    {
        IntPtr hKey;
        int err = RegOpenKeyEx(HKLM, subKeyPath, 0, WRITE_OWNER, out hKey);
        if (err != 0)
            return err;

        err = SetSecurityInfo(hKey, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION,
            ownerSid, null, IntPtr.Zero, IntPtr.Zero);

        RegCloseKey(hKey);
        return err;
    }
}
'@

try {
    Add-Type -TypeDefinition $nativeCode -Language CSharp -ErrorAction Stop
} catch {
    if ($_.Exception.Message -notlike '*already exists*') { throw }
}

# Step 1: Enable privileges (SYSTEM always has them)
Write-Host "Step 1: Enabling privileges..." -ForegroundColor Yellow

$result = [NativeRegistry]::EnablePrivilege("SeTakeOwnershipPrivilege")
if ($result -ne 0) {
    Write-Host "FAILED SeTakeOwnershipPrivilege (error: $result)." -ForegroundColor Red
    exit 1
}
Write-Host "  -> SeTakeOwnershipPrivilege enabled." -ForegroundColor Green

[NativeRegistry]::EnablePrivilege("SeRestorePrivilege") | Out-Null
Write-Host "  -> SeRestorePrivilege enabled." -ForegroundColor Green

# Step 2: Take ownership via Win32 API
Write-Host "`nStep 2: Taking ownership of GracePeriod key..." -ForegroundColor Yellow

$adminSid = New-Object System.Security.Principal.SecurityIdentifier(
    [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null
)
$sidBytes = New-Object byte[] $adminSid.BinaryLength
$adminSid.GetBinaryForm($sidBytes, 0)

$err = [NativeRegistry]::TakeOwnership($regKeyPath, $sidBytes)
if ($err -ne 0) {
    Write-Host "FAILED to take ownership (Win32 error: $err)." -ForegroundColor Red
    exit 1
}
Write-Host "  -> Ownership set to Administrators." -ForegroundColor Green

# Step 3: Grant Full Control
Write-Host "`nStep 3: Granting Full Control permissions..." -ForegroundColor Yellow
try {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        $regKeyPath,
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]::ChangePermissions
    )

    if ($null -eq $key) {
        Write-Host "FAILED: Could not open key for permission change." -ForegroundColor Red
        exit 1
    }

    $acl = $key.GetAccessControl()

    # Full Control for Administrators group
    $adminRule = New-Object System.Security.AccessControl.RegistryAccessRule(
        $adminSid,
        [System.Security.AccessControl.RegistryRights]::FullControl,
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $acl.SetAccessRule($adminRule)

    # Full Control for sadmin user
    $sadminRule = New-Object System.Security.AccessControl.RegistryAccessRule(
        "sadmin",
        [System.Security.AccessControl.RegistryRights]::FullControl,
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $acl.SetAccessRule($sadminRule)

    $key.SetAccessControl($acl)
    $key.Close()
    Write-Host "  -> Full Control granted to Administrators and sadmin." -ForegroundColor Green
} catch {
    Write-Host "FAILED to set permissions: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Step 4: Delete the TimeBomb value(s)
Write-Host "`nStep 4: Deleting TimeBomb value(s)..." -ForegroundColor Yellow
try {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($regKeyPath, $true)

    if ($null -eq $key) {
        Write-Host "FAILED: Could not open key for deletion." -ForegroundColor Red
        exit 1
    }

    $values = $key.GetValueNames()
    $deleted = 0

    foreach ($val in $values) {
        if ($val -like "L`$RTMTIMEBOMB*") {
            $key.DeleteValue($val)
            Write-Host "  -> Deleted: $val" -ForegroundColor Green
            $deleted++
        }
    }

    if ($deleted -eq 0) {
        Write-Host "  -> No TimeBomb values found (already clean)." -ForegroundColor Cyan
    }

    $key.Close()
} catch {
    Write-Host "FAILED to delete TimeBomb: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  SUCCESS! TimeBomb deleted as SYSTEM." -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
