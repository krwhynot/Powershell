# Bypass Execution Policy
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Add legacy shortcuts
Write-Host
Write-host "Adding Legacy Shortcuts"-ForegroundColor Cyan

$TargetPath = "C:\Revention\ReventionPOS.exe"

$ShortcutPaths = @(
    "$env:USERPROFILE\Desktop\Revention POS.lnk",
    "C:\Users\Revention\Desktop\Revention POS.lnk",
    "C:\Users\Revention\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Revention POS.lnk"
    "C:\Users\Manager\Desktop\Revention POS.lnk",
    "C:\Users\Owner\Desktop\Revention POS.lnk"

)

foreach ($ShortcutPath in $ShortcutPaths) {
    try {
        $WshShell = New-Object -ComObject WScript.Shell -ErrorAction Stop
        $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
        $Shortcut.TargetPath = $TargetPath
        $Shortcut.Save()
        Write-Host "Shortcut created: $ShortcutPath"
    }
    catch {
        Write-Host "Failed to create shortcut: $ShortcutPath" -ForegroundColor Yellow
    }
}