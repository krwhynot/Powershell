﻿# Load the required assembly
Add-Type -AssemblyName System.Windows.Forms

# Set the variables
$SqlServerInstance = "Revent1\REVENTION" # Replace with your SQL Server instance
$DatabaseName = "REVENTION" # Replace with your database name
$SqlServerUsername = "Revention" # Replace with your SQL Server username

# Prompt the user for the password
$SqlServerPassword = Read-Host -Prompt "Enter your SQL Server password" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SqlServerPassword)
$SqlServerPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

# Create SqlConnection and SqlCommand objects
$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
$SqlConnection.ConnectionString = "Server=$SqlServerInstance;Database=master;User ID=$SqlServerUsername;Password=$SqlServerPassword;"
$SqlCommand = New-Object System.Data.SqlClient.SqlCommand
$SqlCommand.Connection = $SqlConnection

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

    # Execute the SQL commands
    $SqlCommand.CommandText = $CloseConnectionsSql
    $SqlConnection.Open()
    $SqlCommand.ExecuteNonQuery()
    $SqlConnection.Close()

    $SqlCommand.CommandText = $RestoreDatabaseSql
    $SqlConnection.Open()
    $SqlCommand.ExecuteNonQuery()
    $SqlConnection.Close()

    # Clean up the extracted .bak file and the unique extraction folder
    if ($BackupFilePath) {
        Remove-Item -Path $BackupFilePath
    }
    Remove-Item -Path $ExtractionFolder -Recurse

    Write-Host "Database restored successfully."
}

# Ask the user if they want to change the AboveStoreID
$UserResponse = Read-Host -Prompt "Do you want to change the AboveStoreID? (y/n)"

if ($UserResponse.ToLower() -eq "y") {
    # Get the new AboveStoreID from the user
    $NewAboveStoreID = Read-Host -Prompt "Enter the new AboveStoreID"

    # Update the AboveStoreID in the database
    $UpdateSql = @"
USE [$DatabaseName];
UPDATE Business
SET AboveStoreID = '$NewAboveStoreID'
"@

    $SqlCommand.CommandText = $UpdateSql
    $SqlConnection.Open()
    $SqlCommand.ExecuteNonQuery()
    $SqlConnection.Close()

    Write-Host "AboveStoreID updated successfully."
}
else {
    Write-Host "AboveStoreID not changed."
}

# Execute a SQL command to retrieve the updated records
$SelectSql = @"
USE [$DatabaseName];
SELECT AboveStoreID, BusinessName, StoreNum
FROM Business
"@

$SqlCommand.CommandText = $SelectSql
$SqlConnection.Open()
$DataAdapter = New-Object System.Data.SqlClient.SqlDataAdapter($SqlCommand)
$DataSet = New-Object System.Data.DataSet
$DataAdapter.Fill($DataSet) | Out-Null
$SqlConnection.Close()

# Display the results in a table format
$DataSet.Tables[0] | Format-Table
