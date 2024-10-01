# Ask user for number of printers
$NPrinters = Read-Host "How many IP Station printers do you need to setup."

# Loop through each printer
for ($i = 1; $i -le $NPrinters; $i++) {
    # Create printer port name and IP address
    $PortName = "IP_192.168.192.$($i+100)"
    $IPAddress = "192.168.192.$($i+100)"

    # Create printer port
    & cscript C:\Windows\System32\Printing_Admin_Scripts\en-US\prnport.vbs -a -r $PortName -h $IPAddress -o raw

    # Add printer
    $PrinterName = "Station$i"
    $InfPath = "$env:windir\inf\prnge001.inf"

    # Check if printer already exists
    $ExistingPrinter = Get-Printer | Where-Object Name -eq $PrinterName

    if ($null -eq $ExistingPrinter) {
        & rundll32 printui.dll,PrintUIEntry /if /b $PrinterName /f $InfPath /r $PortName /m "Generic / Text Only"
    } else {
        Write-Host "Printer $PrinterName already exists, skipping..."
    }
}

# List all printers
Get-Printer | Format-Table -AutoSize
