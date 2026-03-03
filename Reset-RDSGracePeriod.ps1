#Requires -RunAsAdministrator
# Reset-RDSGracePeriod.ps1
# Resets the RDS 120-day grace period by deleting the TimeBomb registry value.
# Must be run as Administrator (elevated prompt).

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# --- Step 1: Enable SeTakeOwnershipPrivilege via P/Invoke ---
# Standard PowerShell can't take ownership of protected keys without this.
# Uses SetLastError on DllImport + kernel32 SetLastError to clear stale errors.

$privilegeCode = @'
using System;
using System.Runtime.InteropServices;

public class TokenPrivilege
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

    const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const uint TOKEN_QUERY = 0x0008;
    const uint SE_PRIVILEGE_ENABLED = 0x00000002;

    public static int EnablePrivilege(string privilege)
    {
        // Returns: 0 = success, -1 = OpenProcessToken failed,
        //          -2 = LookupPrivilegeValue failed, -3 = AdjustTokenPrivileges failed,
        //          >0 = Win32 error from AdjustTokenPrivileges (e.g. 1300 = not held)
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

        // Clear last error so we get a clean read after AdjustTokenPrivileges
        SetLastError(0);
        if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
            return -3;

        return Marshal.GetLastWin32Error();
    }
}
'@

try {
    Add-Type -TypeDefinition $privilegeCode -Language CSharp -ErrorAction Stop
} catch {
    if ($_.Exception.Message -notlike '*already exists*') {
        throw
    }
}

Write-Host "Enabling SeTakeOwnershipPrivilege..." -ForegroundColor Yellow
$result = [TokenPrivilege]::EnablePrivilege("SeTakeOwnershipPrivilege")
if ($result -ne 0) {
    Write-Host "FAILED to enable SeTakeOwnershipPrivilege (error code: $result)." -ForegroundColor Red
    Write-Host "  -1 = OpenProcessToken failed" -ForegroundColor Gray
    Write-Host "  -2 = LookupPrivilegeValue failed" -ForegroundColor Gray
    Write-Host "  -3 = AdjustTokenPrivileges failed" -ForegroundColor Gray
    Write-Host "  1300 = Privilege not held by token" -ForegroundColor Gray
    Write-Host "Make sure you are running as Administrator." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "  -> SeTakeOwnershipPrivilege enabled." -ForegroundColor Green

$result2 = [TokenPrivilege]::EnablePrivilege("SeRestorePrivilege")
if ($result2 -eq 0) {
    Write-Host "  -> SeRestorePrivilege enabled." -ForegroundColor Green
} else {
    Write-Host "  -> SeRestorePrivilege not available (code: $result2), continuing anyway..." -ForegroundColor Yellow
}

# --- Step 2: Take ownership of the GracePeriod key ---
$regKeyPath = "SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\GracePeriod"

Write-Host "`nTaking ownership of GracePeriod key..." -ForegroundColor Yellow
try {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        $regKeyPath,
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]::TakeOwnership
    )

    if ($null -eq $key) {
        Write-Host "FAILED: Could not open GracePeriod key. Verify the path exists:" -ForegroundColor Red
        Write-Host "  HKLM\$regKeyPath" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }

    $adminSid = New-Object System.Security.Principal.SecurityIdentifier(
        [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null
    )
    $acl = $key.GetAccessControl()
    $acl.SetOwner($adminSid)
    $key.SetAccessControl($acl)
    $key.Close()
    Write-Host "  -> Ownership set to Administrators." -ForegroundColor Green
} catch {
    Write-Host "FAILED to take ownership: $($_.Exception.Message)" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# --- Step 3: Grant Full Control to Administrators and sadmin ---
Write-Host "`nGranting Full Control permissions..." -ForegroundColor Yellow
try {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        $regKeyPath,
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]::ChangePermissions
    )

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
    Read-Host "Press Enter to exit"
    exit 1
}

# --- Step 4: Delete the TimeBomb value(s) ---
Write-Host "`nDeleting TimeBomb value(s)..." -ForegroundColor Yellow
try {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($regKeyPath, $true)

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
    Read-Host "Press Enter to exit"
    exit 1
}

# --- Step 5: Reboot prompt ---
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  RDS Grace Period has been reset!" -ForegroundColor Green
Write-Host "  A reboot is required." -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Cyan

Read-Host "Press Enter to reboot now (or Ctrl+C to cancel)"
Restart-Computer -Force
