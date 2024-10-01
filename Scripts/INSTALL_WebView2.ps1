# Bypass Execution Policy
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

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