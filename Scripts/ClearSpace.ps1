# Get the current date for the log file name
$Date = Get-Date -Format "yyyyMMddHHmmss"

# Set the name and location of the log file
$LogFilePath = "$env:USERPROFILE\TempFileCleanupLog_$Date.txt"

# Get initial disk space
$InitialDiskSpace = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object -ExpandProperty FreeSpace

# Define temp folders
$TempFolders = @("$env:WINDIR\Temp\*", "$env:TEMP\*")

# Delete temp files
foreach ($TempFolder in $TempFolders) {
    try {
        Get-ChildItem -Path $TempFolder -Recurse -ErrorAction Stop | Remove-Item -Force -Recurse -ErrorAction Stop
        Write-Output "Successfully deleted temp files in $TempFolder" | Out-File -FilePath $LogFilePath -Append
    } catch {
        Write-Output "Failed to delete temp files in $TempFolder. Error: $_" | Out-File -FilePath $LogFilePath -Append
    }
}

# Remove Windows Update files
try {
    Stop-Service -Name wuauserv -Force -ErrorAction Stop
    Remove-Item -Path "$env:WINDIR\SoftwareDistribution\Download\*" -Force -Recurse -ErrorAction Stop
    Start-Service -Name wuauserv -ErrorAction Stop
    Write-Output "Successfully deleted Windows Update files" | Out-File -FilePath $LogFilePath -Append
} catch {
    Write-Output "Failed to delete Windows Update files. Error: $_" | Out-File -FilePath $LogFilePath -Append
}

# Run Disk Cleanup silently
try {
    Start-Process cleanmgr -ArgumentList "/sagerun:1" -Wait -ErrorAction Stop
    Write-Output "Successfully ran Disk Cleanup" | Out-File -FilePath $LogFilePath -Append
} catch {
    Write-Output "Failed to run Disk Cleanup. Error: $_" | Out-File -FilePath $LogFilePath -Append
}

# Empty the Recycle Bin
try {
    $Shell = New-Object -ComObject Shell.Application
    $Shell.Namespace(10).Items() | % { Remove-Item $_.Path -Recurse -Confirm:$false }
    Write-Output "Successfully emptied the Recycle Bin" | Out-File -FilePath $LogFilePath -Append
} catch {
    Write-Output "Failed to empty the Recycle Bin. Error: $_" | Out-File -FilePath $LogFilePath -Append
}

# Get final disk space
$FinalDiskSpace = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object -ExpandProperty FreeSpace

# Calculate disk space saved
$DiskSpaceSaved = $FinalDiskSpace - $InitialDiskSpace
$DiskSpaceSavedInGB = [Math]::Round(($DiskSpaceSaved / 1GB), 2)

# Log disk space saved
Write-Output "Disk space saved: $DiskSpaceSavedInGB GB" | Out-File -FilePath $LogFilePath -Append
Write-Host "Disk space saved: $DiskSpaceSavedInGB GB"

