
Measure-Command {
$logPath = "C:\Revention\Old\ScriptLog_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
Start-Transcript -Path $logPath 

# Bypass Execution Policy
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

#Function to Update Revcloud & RevControl
function Update-Service {
    param(
        [string]$ServiceName,
        [string]$DownloadUrl,
        [string]$ZipFilePath,
        [string]$DestinationPath,
        [string]$SuccessMessage,
        [string]$ErrorMessage
    )
# Pull from SharePoint Server 
Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipFilePath

# Get the number of files in the destination directory before extracting the archive
$beforeCount = @((Get-ChildItem $DestinationPath -File -Recurse).Count)

# Extract the archive to the destination directory, overwriting any existing files
$errorList = @()
$VerbosePreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"

Expand-Archive -Path $ZipFilePath -DestinationPath $DestinationPath -Force -ErrorVariable errorList
    $errorCount = ($errorList | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }).Count
    if ($errorCount -gt 0) {
        Write-Host "Encountered $errorCount errors while updating $ServiceName files"
    } else {
        Write-Host $SuccessMessage -ForegroundColor Green
    }

}

$services = @("RevCloudSvc", "RevControlSvc", "RevPrtSrv")

foreach ($service in $services) {
    try {
        Stop-Service -Name $service -Force -ErrorAction Stop
        Write-Host "Stopping $service..."
        
        $status = Get-Service -Name $service -ErrorAction Stop | Select-Object -ExpandProperty Status
        while ($status -ne 'Stopped') {
            Write-Host "$service status: $status"
            Start-Sleep -Seconds 1
            $status = Get-Service -Name $service -ErrorAction Stop | Select-Object -ExpandProperty Status
        }
        Write-Host "$service stopped successfully." -ForegroundColor Green

        Set-Service -Name $service -StartupType Disable -ErrorAction Stop
        Write-Host "Setting $service startup type to Disable..."
    }
    catch [System.ServiceProcess.ServiceCommandException] {
        Write-Host "Service $service not found. Skipping..." -ForegroundColor Yellow
        continue
    }
}
Start-Sleep -Seconds 2
Write-Host
Write-Host
Write-Host
Write-Host "Starting to download Revcontrol........"

#Update RevControl
Update-Service `
        -ServiceName "RevControlSvc" `
        -DownloadUrl "https://revention.sharepoint.com/:u:/s/Installers/EbeLCAe5XVhJq9vuMfQ0wcoB-rxon7OJ8NRZsbqFX1B3Mw?e=LfGz48&download=1" `
        -ZipFilePath "C:\Revention\New\RevControlSvc_20230519.1.zip" `
        -DestinationPath "C:\Revention" `
        -SuccessMessage "RevControl update was successful" `
        -ErrorMessage "Encountered errors while updating RevControl"
Write-Host "Starting to download RevCloud........"

#Update Revcloud
Update-Service -WarningAction `
        -ServiceName "RevCloudSvc" `
        -DownloadUrl "https://revention.sharepoint.com/:u:/s/Installers/ERKUwFAeRRRFqhMpGYbbpKMBV4ITygpITsj-ZZR92E1k5w?e=fGsvRR&download=1" `
        -ZipFilePath "C:\Revention\New\RevCloudSvc_0411.zip" `
        -DestinationPath "C:\Revention\RevCloudSvc" `
        -SuccessMessage "RevCloud update was successful" `
        -ErrorMessage "Encountered errors while updating Revcloud"
Write-Host "Starting to download Revention POS ........"

#Update Revention POS
Update-Service -WarningAction  `
        -ServiceName "RevControlSvc" `
        -DownloadUrl "https://revention.sharepoint.com/:u:/s/Installers/EYCOdWd8A09Au6WqKtWyqqEBI8uQ1f7TVo49Y9UhldrqRw?e=0dDNHF&download=1" `
        -ZipFilePath "C:\Revention\New\ReventionPOS_20230519.1.zip" `
        -DestinationPath "C:\Revention" `
        -SuccessMessage "Revention POS update was successful" `
        -ErrorMessage "Encountered errors while updating Revention POS"



# Removes shortcuts for 360
Write-Host
Write-Host
Write-host "Removing HR360 Shortcuts" -ForegroundColor Cyan

$shortcutPaths = @(
    "$env:USERPROFILE\Desktop\HungerRush POS.lnk",
    "C:\Users\Revention\Desktop\HungerRush POS.lnk",
    "C:\Users\Revention\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\HungerRush POS.lnk",
    "C:\Users\Manager\Desktop\HungerRush POS.lnk",
    "C:\Users\Owner\Desktop\HungerRush POS.lnk",
    "C:\Users\Revadmin\Desktop\Revention.lnk",
    "C:\Users\Revention\Desktop\ReventionPOS.exe - Shortcut.lnk"
    "$env:USERPROFILE\Desktop\ReventionPOS.exe - Shortcut.lnk"
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


# Check for Crystal Reports, then install if it does not exist
$crystalReportsRegistryKeyPath = "HKLM:\Software\WOW6432Node\SAP BusinessObjects\Crystal Reports for .NET Framework 4.0\Crystal Reports"

function Check-CrystalReportsInstallation {
    return Test-Path -Path $crystalReportsRegistryKeyPath
}

function Download-And-Install-CRRuntime {
    param(
        [string]$DownloadUrl,
        [string]$InstallerFilePath,
        [string]$SuccessMessage,
        [string]$ErrorMessage
    )

    # Download the MSI file
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $InstallerFilePath

    if (Test-Path -Path $InstallerFilePath) {
        # Install the MSI file quietly
        $installerArguments = "/passive /norestart /log C:\Revention\Old\install_log.txt"
        $installProcess = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$InstallerFilePath`" $installerArguments" -Wait -NoNewWindow -PassThru

        if ($installProcess.ExitCode -eq 0) {
            Write-Host $SuccessMessage -ForegroundColor Green
        } else {
            Write-Host $ErrorMessage -ForegroundColor Red
        }
    } else {
        Write-Host "Failed to download the MSI file" -ForegroundColor Red
    }
}

$crystalReportsInstalled = Check-CrystalReportsInstallation

if ($crystalReportsInstalled) {
    Write-Host "SAP Crystal Reports is installed."
} else {
    Write-Host "SAP Crystal Reports is NOT installed. Attempting to download and install now..."
    Download-And-Install-CRRuntime `
        -DownloadUrl "https://revention.sharepoint.com/:u:/s/Installers/Eaxs6oQ8GUVKojmTEFJz4gMBRcIjtvx3FPA-GGup_TlRVw?e=UshMXq&download=1" `
        -InstallerFilePath "C:\Revention\New\CRRuntime_32bit_13_0_33.msi" `
        -SuccessMessage "Crystal Reports installation was successful" `
        -ErrorMessage "Encountered errors while installing Crystal Reports"
}



# Check if WebView2 is installed, if not, then install it
Write-Host
Write-Host "Checking if WebView2 is installed, if not, then installing it..."
try {
    if (!(Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}')) {
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile("https://go.microsoft.com/fwlink/?linkid=2124703", "$env:TEMP\MicrosoftEdgeWebview2Setup.exe")
        Start-Process -FilePath "$env:TEMP\MicrosoftEdgeWebview2Setup.exe" -Args '/silent /install' -Wait
    }

    if (Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}') {
        Write-Host "WebView2 is installed" -ForegroundColor Green
        Write-Host
    }
} catch {
    Write-Host "An error occurred while installing Webview2: $_"
    Write-Host
}


# Set service startup types and control services
try {
    Set-Service -Name HungerRushSyncSvc -StartupType Disabled -ErrorAction Stop
    Stop-Service -Name HungerRushSyncSvc -Force -ErrorAction Stop
} catch [System.ServiceProcess.ServiceCommandException] {
    Write-Host "Service HungerRushSyncSvc does not exist." -ForegroundColor Yellow
}

# Set startup type to Automatic (Delayed Start) for services
$servicesToDelay = @("RevCloudSvc", "RevControlSvc", "RevPrtSrv")
foreach ($service in $servicesToDelay) {
    Set-Service -Name $service -StartupType Automatic
    sc.exe config $service start=delayed-auto | Out-Null
}

Write-Host
Start-Sleep -Seconds 7
$HRservices = "RevCloudSvc", "RevPrtSrv", "RevControlSvc"

foreach ($HRservice in $HRservices) {
    $service = Get-Service -Name $HRservice -ErrorAction SilentlyContinue
    if ($service) {
        Start-Service -Name $HRservice
        Write-Host "Starting $HRservice..."
        $status = $service.Status
        while ($status -ne 'Running') {
            Write-Host "$HRservice status: $status"
            Start-Sleep -Seconds 1
            $status = (Get-Service -Name $HRservice -ErrorAction SilentlyContinue).Status
        }
        Write-Host "$HRservice started successfully." -ForegroundColor Green
    }
    else {
        Write-Host "$HRservice does not exist." -ForegroundColor Yellow
    }
}

Write-Host
Write-Host
Start-Sleep -Seconds 2

$serviceNames = @("HungerRushSyncSvc", "RevCloudSvc", "RevControlSvc", "RevPrtSrv")

foreach ($serviceName in $serviceNames) {
    try {
        $service = Get-Service -Name $serviceName -ErrorAction Stop
        $startType = (Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'").StartMode
        $delayed = if ($startType -eq "Automatic") { "(Delayed)" } else { "" }
        $statusColor = if ($service.Status -eq "Stopped") { "Red" } else { "Green" }
        
        Write-Host $service.Name ": " $startType $delayed "---" $service.Status -ForegroundColor $statusColor
    } catch [System.ServiceProcess.ServiceCommandException] {
        Write-Host "$serviceName does not exist." -ForegroundColor Yellow
    }
}

Write-Host
Write-Host

# Get computer name
$computerName = (Get-WmiObject -Class Win32_ComputerSystem).Name

# Extract the number from the computer name
$number = $computerName -replace "\D+" # Replace all non-digits with an empty string

# Load the XML file
$configFile = "C:\Revention\ReventionPOS.exe.config"
[xml]$xmlContent = Get-Content $configFile

# Find the "ComputerName" element and update its value
$computerNameElement = $xmlContent.configuration.appSettings.add | Where-Object { $_.key -eq "ComputerName" }
$computerNameElement.value = "Station$number"

# Save the updated XML file
$xmlContent.Save($configFile)

# Adds GUI line to the Revention Config File
$filePath = "C:\Revention\ReventionPOS.exe.config"
$content = Get-Content -Path $filePath
$lineToAdd = '    <add key="UIUplift" value="1" />'
$lineToSearch = '</appSettings>'
$lineIndex = -1

for ($i = 0; $i -lt $content.Length; $i++) {
    if ($content[$i].Trim() -eq $lineToSearch) {
        $lineIndex = $i
        break
    }
}
Write-Host

if ($lineIndex -ne -1) {
    if ($content -notcontains $lineToAdd) {
        $content = $content[0..($lineIndex - 1)] + $lineToAdd + $content[$lineIndex..($content.Length - 1)]
        $content | Set-Content -Path $filePath
        Write-Host "The GUI line was added successfully to Config File:" -ForegroundColor Green
        Write-Host $lineToAdd
    } else {
        Write-Host "The GUI line already exists in Config file. Skipping." -ForegroundColor Yellow
    }
} else {
    Write-Host "Line to search not found in the file." -ForegroundColor Red
}
Write-Host

#Display RevCloud Date##
  $RevCloudFile = Get-ChildItem -Path "C:\Revention\RevCloudSvc\RevCloudSvc.exe"
  $date = $RevCloudfile.LastWriteTime.ToString("MM-dd-yyyy")
  Write-Host "Revcloud"
  Write-Host "Last Update: $date"-ForegroundColor Magenta
  Write-Host
  Write-Host

#Display RevControl Date##
    $RevCtrlFile = Get-ChildItem -Path "C:\Revention\RevControlSvc.exe"
    $RevCtrldate = $RevCtrlFile.LastWriteTime.ToString("MM-dd-yyyy")
    Write-Host "Revcontrol"
    Write-Host "Last Update: $RevCtrldate"-ForegroundColor Magenta
    Write-Host

#Display Revention POS Date##
  $RevPOSFile = Get-ChildItem -Path "C:\Revention\ReventionPOS.exe"
  $date = $RevPOSfile.LastWriteTime.ToString("MM-dd-yyyy")
  Write-Host "Revention POS"
  Write-Host "Last Update: $date"-ForegroundColor Magenta

    Write-Host
    Write-Host
    Write-Host

}


   Stop-Transcript
pause



 




