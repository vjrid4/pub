#Requires -RunAsAdministrator
# Reset-RDSGracePeriod.ps1
# Resets the RDS 120-day grace period by deleting the TimeBomb registry value.
# Must be run as Administrator (elevated prompt).
#
# Uses raw Win32 API calls (RegOpenKeyEx, SetSecurityInfo) to bypass .NET's
# OpenSubKey ACL check which blocks access even with SeTakeOwnershipPrivilege.

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# --- Combined P/Invoke class for privilege elevation + registry operations ---

$nativeCode = @'
using System;
using System.Runtime.InteropServices;

public class NativeRegistry
{
    // --- Token privilege APIs ---
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

    // --- Registry APIs ---
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern int RegOpenKeyEx(
        IntPtr hKey, string subKey, uint options, uint samDesired, out IntPtr phkResult);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern int RegCloseKey(IntPtr hKey);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern int SetSecurityInfo(
        IntPtr handle, uint ObjectType, uint SecurityInfo,
        byte[] psidOwner, byte[] psidGroup, IntPtr pDacl, IntPtr pSacl);

    // --- Constants ---
    const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    const uint TOKEN_QUERY = 0x0008;
    const uint SE_PRIVILEGE_ENABLED = 0x00000002;

    // HKEY_LOCAL_MACHINE
    static readonly IntPtr HKLM = new IntPtr(unchecked((int)0x80000002));

    // Registry access rights
    const uint WRITE_OWNER   = 0x00080000;
    const uint WRITE_DAC     = 0x00040000;
    const uint KEY_READ      = 0x20019;
    const uint KEY_ALL_ACCESS = 0xF003F;

    // SetSecurityInfo constants
    const uint SE_REGISTRY_KEY   = 4;
    const uint OWNER_SECURITY_INFORMATION = 0x00000001;

    // --- Methods ---

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
        // Open the key with WRITE_OWNER access using Win32 API directly.
        // This bypasses .NET's OpenSubKey which does its own ACL check and fails.
        IntPtr hKey;
        int err = RegOpenKeyEx(HKLM, subKeyPath, 0, WRITE_OWNER, out hKey);
        if (err != 0)
            return err;

        // Set the owner using SetSecurityInfo
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
    if ($_.Exception.Message -notlike '*already exists*') {
        throw
    }
}

# =============================================
# Step 1: Enable privileges
# =============================================
Write-Host "Step 1: Enabling privileges..." -ForegroundColor Yellow

$result = [NativeRegistry]::EnablePrivilege("SeTakeOwnershipPrivilege")
if ($result -ne 0) {
    Write-Host "FAILED to enable SeTakeOwnershipPrivilege (error: $result)." -ForegroundColor Red
    Write-Host "  -1=OpenProcessToken -2=LookupPrivilege -3=AdjustToken 1300=NotHeld" -ForegroundColor Gray
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "  -> SeTakeOwnershipPrivilege enabled." -ForegroundColor Green

$result2 = [NativeRegistry]::EnablePrivilege("SeRestorePrivilege")
if ($result2 -eq 0) {
    Write-Host "  -> SeRestorePrivilege enabled." -ForegroundColor Green
} else {
    Write-Host "  -> SeRestorePrivilege skipped (code: $result2), continuing..." -ForegroundColor Yellow
}

# =============================================
# Step 2: Take ownership via Win32 API
# =============================================
$regKeyPath = "SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\GracePeriod"

Write-Host "`nStep 2: Taking ownership of GracePeriod key (Win32 API)..." -ForegroundColor Yellow

# Get the Administrators SID as a byte array
$adminSid = New-Object System.Security.Principal.SecurityIdentifier(
    [System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null
)
$sidBytes = New-Object byte[] $adminSid.BinaryLength
$adminSid.GetBinaryForm($sidBytes, 0)

$err = [NativeRegistry]::TakeOwnership($regKeyPath, $sidBytes)
if ($err -ne 0) {
    Write-Host "FAILED to take ownership (Win32 error: $err)." -ForegroundColor Red
    Write-Host "  2 = Key not found, 5 = Access denied" -ForegroundColor Gray
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "  -> Ownership set to Administrators." -ForegroundColor Green

# =============================================
# Step 3: Grant Full Control (now that we own it, .NET works)
# =============================================
Write-Host "`nStep 3: Granting Full Control permissions..." -ForegroundColor Yellow
try {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        $regKeyPath,
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]::ChangePermissions
    )

    if ($null -eq $key) {
        Write-Host "FAILED: Could not open key for permission change." -ForegroundColor Red
        Read-Host "Press Enter to exit"
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
    Read-Host "Press Enter to exit"
    exit 1
}

# =============================================
# Step 4: Delete the TimeBomb value(s)
# =============================================
Write-Host "`nStep 4: Deleting TimeBomb value(s)..." -ForegroundColor Yellow
try {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($regKeyPath, $true)

    if ($null -eq $key) {
        Write-Host "FAILED: Could not open key for deletion." -ForegroundColor Red
        Read-Host "Press Enter to exit"
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
    Read-Host "Press Enter to exit"
    exit 1
}

# =============================================
# Step 5: Reboot
# =============================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  RDS Grace Period has been reset!" -ForegroundColor Green
Write-Host "  A reboot is required." -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Cyan

Read-Host "Press Enter to reboot now (or Ctrl+C to cancel)"
Restart-Computer -Force
