param (
    [int]$StationCount = $(Read-Host "Enter the number of stations"),
    [string[]]$LogosSource = @(
        "C:\Revention\SmallLogo.png",
        "C:\Revention\logo.png",
        "C:\Revention\rptlogo.bmp",
        "C:\Revention\plogo.bmp"
    ),
    [string]$LogoDestination = "C:\Revention",
    [string]$PsExecPath = "C:\Windows\System32\PsExec.exe"
)

$downloadedPsExec = $false

function Download-PsExec {
    param (
        [string]$DestinationPath
    )
    $url = "https://download.sysinternals.com/files/PSTools.zip"
    $zipPath = "$env:TEMP\PSTools.zip"
    $extractPath = "$env:TEMP\PSTools"

    Invoke-WebRequest -Uri $url -OutFile $zipPath
    Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
    Copy-Item -Path "$extractPath\PsExec.exe" -Destination $DestinationPath -Force

    Remove-Item -Path $zipPath -Force
    Remove-Item -Path $extractPath -Recurse -Force

    $downloadedPsExec = $true
}

function Start-Cleanup {
    if ($downloadedPsExec -and (Test-Path $PsExecPath)) {
        Remove-Item -Path $PsExecPath -Force
        Write-Host "Cleaned up downloaded PsExec.exe."
    }
}

if (-Not (Test-Path $PsExecPath)) {
    Write-Host "PsExec.exe not found at $PsExecPath. Downloading..."
    Download-PsExec -DestinationPath $PsExecPath
    if (-Not (Test-Path $PsExecPath)) {
        Write-Host "Failed to download PsExec.exe. Please verify the path or download it manually."
        exit
    }
}

function Stop-ProcessRemotely {
    param (
        [string]$StationName,
        [string]$ProcessName
    )
    $output = & $PsExecPath \\$StationName -accepteula cmd /c "taskkill /IM $ProcessName /F" 2>&1
    if ($output -match "SUCCESS") {
        Write-Host "Successfully stopped $ProcessName on $StationName."
    }
    else {
        Write-Host "Failed to stop $ProcessName on $StationName. Output: $output"
    }
}

function Copy-Logos {
    param (
        [string]$StationName,
        [string[]]$LogosSource,
        [string]$LogoDestination
    )
    $LogosSource | ForEach-Object {
        $logoPath = $_
        $destPath = "\\$StationName\C$\Revention\$(Split-Path $logoPath -Leaf)"
        try {
            Copy-Item -Path $logoPath -Destination $destPath -Force
            Write-Host "Successfully copied $logoPath to $destPath on $StationName."
        }
        catch {
            Write-Host "Failed to copy $logoPath to $destPath on $StationName. Error: $_"
        }
    }
}

function Copy-SlideshowLogo {
    param (
        [string]$StationName
    )
    $slideshowDestPath = "\\$StationName\C$\Revention\Slideshow\Logo.png"
    try {
        Copy-Item -Path "\\$StationName\C$\Revention\logo.png" -Destination $slideshowDestPath -Force
        Write-Host "Successfully copied C:\Revention\logo.png to $slideshowDestPath on $StationName."
    }
    catch {
        Write-Host "Failed to copy C:\Revention\logo.png to $slideshowDestPath on $StationName. Error: $_"
    }
}

1..$StationCount | ForEach-Object {
    $stationName = "Revent$_"
    
    if ($stationName -eq $env:COMPUTERNAME) {
        Write-Host "Skipping operations for localhost ($stationName)."
        return
    }

    Stop-ProcessRemotely -StationName $stationName -ProcessName "ReventionPOS.exe"
    Stop-ProcessRemotely -StationName $stationName -ProcessName "RevScreenMgr.exe"
    Copy-Logos -StationName $stationName -LogosSource $LogosSource -LogoDestination $LogoDestination
    Copy-SlideshowLogo -StationName $stationName
}

Start-Cleanup

