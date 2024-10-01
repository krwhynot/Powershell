# Get list of all installed printers
$printers = Get-WmiObject -Query "Select * From Win32_Printer"

# Loop through each printer and remove it
foreach ($printer in $printers) {
    Write-Output "Removing printer: $($printer.Name)"
    Remove-Printer -Name $printer.Name
}
