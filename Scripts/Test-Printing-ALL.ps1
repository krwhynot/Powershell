$printers = Get-WmiObject -Query "Select * From Win32_Printer"

foreach ($printer in $printers) {
    $printerName = $printer.Name
    Write-Host "Printing test page for printer: $printerName"
    
    try {
        $printer.InvokeMethod("PrintTestPage", $null)
        Write-Host "Test page sent to printer: $printerName"
    } catch {
        Write-Host "Error printing test page for printer: $printerName"
        Write-Host $_.Exception.Message
    }
}
