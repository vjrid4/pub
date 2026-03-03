#Requires -RunAsAdministrator
# Reset-RDSGracePeriod.ps1
# Resets the RDS 120-day grace period by deleting the TimeBomb registry value.
# Must be run as Administrator (elevated prompt).

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# --- Step 1: Enable SeTakeOwnershipPrivilege via P/Invoke ---
# Standard PowerShell can't take ownership of protected keys without this.

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

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetCurrentProcess();

    const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const uint TOKEN_QUERY = 0x0008;
    const uint SE_PRIVILEGE_ENABLED = 0x00000002;

    public static bool EnablePrivilege(string privilege)
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token))
            return false;

        long luid;
        if (!LookupPrivilegeValue(null, privilege, out luid))
            return false;

        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        tp.PrivilegeCount = 1;
        tp.Luid = luid;
        tp.Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
            return false;

        return Marshal.GetLastWin32Error() == 0;
    }
}
'@

try {
    Add-Type -TypeDefinition $privilegeCode -Language CSharp -ErrorAction Stop
} catch {
    # Type may already be loaded in this session
    if ($_.Exception.Message -notlike '*already exists*') {
        throw
    }
}

Write-Host "Enabling SeTakeOwnershipPrivilege..." -ForegroundColor Yellow
$result = [TokenPrivilege]::EnablePrivilege("SeTakeOwnershipPrivilege")
if (-not $result) {
    Write-Host "FAILED to enable SeTakeOwnershipPrivilege. Are you running as Administrator?" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "  -> Privilege enabled." -ForegroundColor Green

# Also enable SeRestorePrivilege (needed to set owner to a group you belong to)
$result2 = [TokenPrivilege]::EnablePrivilege("SeRestorePrivilege")
if ($result2) {
    Write-Host "  -> SeRestorePrivilege enabled." -ForegroundColor Green
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
        Write-Host "FAILED: Could not open GracePeriod key. Verify the path exists." -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }

    $adminSid = [System.Security.Principal.SecurityIdentifier]::new(
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
    $adminRule = [System.Security.AccessControl.RegistryAccessRule]::new(
        $adminSid,
        [System.Security.AccessControl.RegistryRights]::FullControl,
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $acl.SetAccessRule($adminRule)

    # Full Control for sadmin user
    $sadminRule = [System.Security.AccessControl.RegistryAccessRule]::new(
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
