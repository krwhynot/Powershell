# Configure label printer(s)
Invoke-Expression "regedit.exe /S C:\Revention\New\Install\Zebra.reg"

$NPrinters = Read-Host "How many Label printers do you need to setup. (YOU STILL NEED TO UPLOAD THE CONFIG)"

for ($i=1; $i -le $NPrinters; $i++) {
    $printerName = "Label Printer$i"
    $IP = 230 + $i
    $printerExists = (Get-WmiObject -Query "SELECT * FROM Win32_Printer WHERE Name = '$printerName'") -ne $null

    if ($printerExists) {
        Write-Output "$printerName already exists. Skipping..."
        continue
    }

    Write-Output "Setting up $printerName..."
    & cscript C:\Windows\System32\Printing_Admin_Scripts\en-US\prnport.vbs -a -r "IP_192.168.192.$IP" -h "192.168.192.$IP" -o raw
    & rundll32 printui.dll,PrintUIEntry /if /b "$printerName" /f "$env:windir\inf\prnge001.inf" /r "IP_192.168.192.$IP" /m "Generic / Text Only"
}
