# Stop the Print Spooler service
Stop-Service -Name Spooler -Force

# Clear the print queue
Get-WmiObject -Query "Select * From Win32_PrintJob" | ForEach-Object {
    $_.Delete()
}

# Restart the Print Spooler service
Start-Service -Name Spooler
