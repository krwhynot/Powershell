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
