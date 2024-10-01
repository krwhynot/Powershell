# Load the required assembly
Add-Type -AssemblyName System.Windows.Forms

# Set the variables
$SqlServerInstance = "Revent1\REVENTION" # Replace with your SQL Server instance
$DatabaseName = "REVENTION" # Replace with your database name

# Create OpenFileDialog and configure it
$OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
$OpenFileDialog.Title = "Select a .zip file"
$OpenFileDialog.Filter = "Zip files (*.zip)|*.zip"
$OpenFileDialog.InitialDirectory = "C:\Revention\Backup"

# Show the OpenFileDialog and store the result
$DialogResult = $OpenFileDialog.ShowDialog()

if ($DialogResult -eq "OK") {
    $ZipFilePath = $OpenFileDialog.FileName

    # Create a unique extraction folder using a timestamp
    $TimeStamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $ExtractionFolder = "C:\Revention\Extraction\$TimeStamp"
    New-Item -ItemType Directory -Path $ExtractionFolder | Out-Null

    # Extract the .bak file from the .zip file
    Expand-Archive -Path $ZipFilePath -DestinationPath $ExtractionFolder

    # Find the extracted .bak file
    $BackupFilePath = (Get-ChildItem -Path $ExtractionFolder -Filter "*.bak").FullName

    # Debugging information
    Write-Host "Zip file path: $ZipFilePath"
    Write-Host "Extraction folder: $ExtractionFolder"
    Write-Host "Backup file path: $BackupFilePath"

    # Build the SQL commands
    $CloseConnectionsSql = @"
USE [master];
ALTER DATABASE [$DatabaseName] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
"@

    $RestoreDatabaseSql = @"
USE [master];
RESTORE DATABASE [$DatabaseName] FROM DISK = N'$BackupFilePath' WITH REPLACE;
ALTER DATABASE [$DatabaseName] SET MULTI_USER;
"@

    # Execute the SQL commands using sqlcmd
    Invoke-Expression "sqlcmd -S $SqlServerInstance -Q `"$CloseConnectionsSql`""
    Invoke-Expression "sqlcmd -S $SqlServerInstance -Q `"$RestoreDatabaseSql`""

    # Clean up the extracted .bak file and the unique extraction folder
    if ($BackupFilePath) {
        Remove-Item -Path $BackupFilePath
    }
    Remove-Item -Path $ExtractionFolder -Recurse

    Write-Host "Database restored successfully."
} else {
    Write-Host "No .zip file was selected."
}

# Query the database
$Query = @"
SELECT AboveStoreID, BusinessName, StoreNum
FROM Business
"@

$Results = Invoke-Sqlcmd -ServerInstance $SqlServerInstance -Database $DatabaseName -Query $Query

# Display the query results
$Results | Format-Table -AutoSize

# Ask the user if they want to change the AboveStoreID
$UserResponse = Read-Host -Prompt "Do you want to change the AboveStoreID? (yes/no)"

if ($UserResponse.ToLower() -eq "yes") {
    # Get the new AboveStoreID from the user
    $NewAboveStoreID = Read-Host -Prompt "Enter the new AboveStoreID"

    # Update the AboveStoreID in the database
    $UpdateSql = @"
UPDATE Business
SET AboveStoreID = '$NewAboveStoreID'
"@

    Invoke-Sqlcmd -ServerInstance $SqlServerInstance -Database $DatabaseName -Query $UpdateSql
    Write-Host "AboveStoreID updated successfully."
} else {
    Write-Host "AboveStoreID not changed."
}
