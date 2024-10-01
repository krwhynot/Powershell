#Ensure proper powershell security policy and modules are installed
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser
If(-not(Get-InstalledModule SQLServer -ErrorAction silentlycontinue))
{
Set-PSRepository PSGallery -InstallationPolicy Trusted
Install-Module SQLServer -Confirm:$False -Force -AllowClobber
}


$SQLConfig = Get-Content -Path "C:\Revention\ReventionPOS.exe.config" | Select-String -Pattern '"SQLServer"'
$SQLServer = $SQLConfig -Replace '    <add key="SQLServer" value="','' -Replace '" />',''

#Query for 300 Days CC Batch
$Businessinfo = @'
Select AboveStoreID, BusinessName, StoreNum
FROM Business
'@

$CCBatch30Days = @'
SELECT top 300 CCBatchKey, BizDate, CloseTime, IsOpen
FROM CCBatches
ORDER BY BizDate DESC
'@

 
Invoke-Sqlcmd -Query $Businessinfo  -ServerInstance "$sqlServer" -Username "Revention" -Password "Astr0s" -Database "Revention" |Format-Table | Out-File  -filePath "C:\Revention\Backup\Query-300-Days-CC-Batch.txt"
Invoke-Sqlcmd -Query $CCBatch30Days  -ServerInstance "$sqlServer" -Username "Revention" -Password "Astr0s" -Database "Revention" |Format-Table | Out-File -Append -filePath "C:\Revention\Backup\Query-30-Days-CC-Batch.txt"


#Business Info for Email Title
$BusinessName = @'
Select BusinessName
FROM Business
'@

$BusinessID = @'
Select AboveStoreID
FROM Business
'@

$BusinessName_Results =  Invoke-Sqlcmd -Query $BusinessName  -ServerInstance "$sqlServer" -Username "Revention" -Password "Astr0s" -Database "Revention"
$BusinessID_Results =  Invoke-Sqlcmd -Query $BusinessID  -ServerInstance "$sqlServer" -Username "Revention" -Password "Astr0s" -Database "Revention"


$oBusinessName_Results = $BusinessName_Results.Item(0)
$oBusinessID_Results = $BusinessID_Results.Item(0)

