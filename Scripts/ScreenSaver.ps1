# Requires running as an administrator
function Get-ScreensaverStatus {
    $userProfiles = Get-WmiObject -Class Win32_UserProfile | Where-Object { $_.Special -eq $false }

    foreach ($profile in $userProfiles) {
        $sid = $profile.SID
        $ntuserPath = $profile.LocalPath + "\NTUSER.DAT"
        
        $regPath = "Registry::HKEY_USERS\$sid\Control Panel\Desktop"
        try {
            # Load the user's NTUSER.DAT registry hive
            if (Test-Path $ntuserPath) {
                REG LOAD "HKU\$sid" $ntuserPath >$null 2>&1
            }

            # Read screensaver settings
            $screensaverActive = Get-ItemProperty -Path $regPath -Name "SCRNSAVE.EXE" -ErrorAction SilentlyContinue
            $screensaverTimeout = Get-ItemProperty -Path $regPath -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue
            $screensaverSecure = Get-ItemProperty -Path $regPath -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue

            # Output results
            [PSCustomObject]@{
                User = $profile.LocalPath.Split('\')[-1]
                Screensaver = if ($screensaverActive.SCRNSAVE.EXE) { "Enabled" } else { "Disabled" }
                Timeout = $screensaverTimeout.ScreenSaveTimeOut
                IsSecure = switch ($screensaverSecure.ScreenSaverIsSecure) {
                    "1" { "Yes" }
                    "0" { "No" }
                    default { "Unknown" }
                }
            }
        }
        finally {
            # Unload the hive to prevent locking the user profile
            REG UNLOAD "HKU\$sid" >$null 2>&1
        }
    }
}

# Execute the function
Get-ScreensaverStatus
