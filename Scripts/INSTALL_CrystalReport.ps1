# Bypass Execution Policy
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

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
        -DownloadUrl "https://revention.sharepoint.com/:u:/s/Installers/Eaxs6oQ8GUVKojmTEFJz4gMBRcIjtvx3FPA-GGup_TlRVw?e=oFfuxu&download=1" `
        -InstallerFilePath "C:\Revention\New\CRRuntime_32bit_13_0_33.msi" `
        -SuccessMessage "Crystal Reports installation was successful" `
        -ErrorMessage "Encountered errors while installing Crystal Reports"
}

