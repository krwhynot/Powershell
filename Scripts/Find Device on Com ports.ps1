# Query WMI for all PnP entities and filter for COM ports
$allComPorts = Get-WmiObject -Class Win32_PnPEntity | Where-Object { $_.Name -match 'COM\d' }

# Check if any COM ports are available
if ($allComPorts -eq $null) {
    Write-Host "No COM ports found."
} else {
    # Display information for each COM port
    foreach ($port in $allComPorts) {
        Write-Host ("Name: " + $port.Name)
        Write-Host ("DeviceID: " + $port.DeviceID)
        Write-Host ("Status: " + $port.Status)
        Write-Host ("--------------------------------------------------")
    }
}
