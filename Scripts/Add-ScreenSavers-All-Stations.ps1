# Ask for the number of stations
$stationCount = Read-Host "Enter the number of stations"

# Define the source path for the ScreenSaver
$screenSaverSource = "C:\Revention\revention.scr"

# Check if the screensaver file exists
if (-not (Test-Path $screenSaverSource)) {
    Write-Host "The file $screenSaverSource is not found. Exiting."
    return
}

# Define the destination paths for the ScreenSaver
$screenSaverDestinations = @(
    "C$\Windows\SysWOW64\revention.scr",
    "C$\Windows\System32\revention.scr"
)

# Loop through each station based on the provided count
1..$stationCount | ForEach-Object {
    $stationName = "Revent$_"
    Write-Host "Processing $stationName..."

    # Copy the ScreenSaver file to each destination
    $successCount = 0
    $screenSaverDestinations | ForEach-Object {
        $destPath = "\\$stationName\$_"
        try {
            Copy-Item -Path $screenSaverSource -Destination $destPath -Force -ErrorAction Stop
            $successCount++
        } catch {
            Write-Host "`tFailed to copy to $destPath. Error: $($_.Exception.Message)"
        }
    }

    if ($successCount -eq $screenSaverDestinations.Count) {
        Write-Host "`tAll files successfully copied to $stationName."
    }
}
