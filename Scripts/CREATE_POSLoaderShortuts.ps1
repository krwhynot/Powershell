# Bypass Execution Policy
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Adding POSLoader shortcuts
Write-Host
Write-host "Adding POSLoader Shortcuts"-ForegroundColor Cyan

$TargetPath = "C:\Revention\POSLoader.exe"

$ShortcutPaths = @(
    "$env:USERPROFILE\Desktop\POSLoader.lnk",
    "C:\Users\Revention\Desktop\POSLoader.lnk",
    "C:\Users\Revention\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\POSLoader.lnk"
    "C:\Users\Manager\Desktop\POSLoader.lnk",
    "C:\Users\Owner\Desktop\POSLoader.lnk",
	"C:\Users\Administrator\Desktop\POSLoader.lnk"

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

    # Removes shortcuts for Revention links
    Write-Host
    Write-Host
    Write-host "Removing Old Revention Shortcuts" -ForegroundColor Cyan
    
    $shortcutPaths = @(
        "$env:USERPROFILE\Desktop\HungerRush POS.lnk",
        "C:\Users\Revention\Desktop\HungerRush POS.lnk",
        "C:\Users\Revention\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\HungerRush POS.lnk",
        "C:\Users\Manager\Desktop\HungerRush POS.lnk",
        "C:\Users\Owner\Desktop\HungerRush POS.lnk",
        "C:\Users\Revadmin\Desktop\Revention.lnk",
        "C:\Users\Revention\Desktop\ReventionPOS.exe - Shortcut.lnk"
        "$env:USERPROFILE\Desktop\ReventionPOS.exe - Shortcut.lnk",
        "C:\Users\Revention\Desktop\+.lnk",
        "C:\Users\Revadmin\Desktop\+.lnk",
        "C:\Users\Administrator\Desktop\ReventionPO.lnk"
    )
    
    $removedShortcuts = @()
    $failedShortcuts = @()
    
    foreach ($shortcutPath in $shortcutPaths) {
        try {
            Remove-Item $shortcutPath -ErrorAction Stop
            $removedShortcuts += $shortcutPath
        }
        catch {
            $failedShortcuts += $shortcutPath
        }
    }
    
    Write-Host "HungerRush shortcuts removed:`n$($removedShortcuts -join "`n")"
    if ($failedShortcuts) {
        Write-Host "Failed to remove shortcuts:`n$($failedShortcuts -join "`n")" -ForegroundColor Yellow
    }
