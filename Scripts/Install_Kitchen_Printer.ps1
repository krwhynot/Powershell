# Configure kitchen printer(s) on station one
Write-Host "How many kitchen printers do you need to setup. (will not do the Epson side of this)"
$NPrinters = Read-Host

# Loop through number of printers
for ($i=1; $i -le $NPrinters; $i++)
{
    $printerName = "Printer$i"
    $IP = 210 + $i
    $printerExists = Get-WmiObject -Query "SELECT * FROM Win32_Printer WHERE Name = '$printerName'"
    
    # Check if printer already exists
    if ($null -eq $printerExists)
    {
        Write-Host "$printerName"
        cscript C:\Windows\System32\Printing_Admin_Scripts\en-US\prnport.vbs -a -r "IP_192.168.192.$IP" -h "192.168.192.$IP" -o raw
        & rundll32 printui.dll,PrintUIEntry /if /b "$printerName" /f "$env:windir\inf\prnge001.inf" /r "IP_192.168.192.$IP" /m "Generic / Text Only"
    }
    else 
    {
        Write-Host "$printerName already exists. Skipping..."
    }
}

# Display all printers in a table format
Get-WmiObject -Query "SELECT * FROM Win32_Printer" | Format-Table Name, DriverName, PortName
