# Set the name of the screensaver
$screensaverName = "Revention.scr"

# Set the path to the screensaver
$screensaverPath = "C:\Windows\System32\$screensaverName"

# Check if the screensaver exists
if (Test-Path $screensaverPath) {
    # Set the screensaver settings in the registry
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -Value 1
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "SCRNSAVE.EXE" -Value $screensaverPath

    # Inform the user
    Write-Host "Screensaver has been set to $screensaverName."
} else {
    Write-Host "Could not find screensaver $screensaverName at $screensaverPath."
}
# Define SendMessage function from user32.dll
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class WinAPI {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr SendMessage(
        IntPtr hWnd,
        uint Msg,
        IntPtr wParam,
        IntPtr lParam
    );
}
"@

# Constants
$HWND_BROADCAST = [IntPtr]0xffff; # 0xffff = HWND_BROADCAST
$WM_SYSCOMMAND = 0x0112; # 0x0112 = WM_SYSCOMMAND
$SC_SCREENSAVE = 0xF140; # 0xF140 = SC_SCREENSAVE

# Send message to all windows to start screensaver
[WinAPI]::SendMessage($HWND_BROADCAST, $WM_SYSCOMMAND, $SC_SCREENSAVE, [IntPtr]::Zero);
