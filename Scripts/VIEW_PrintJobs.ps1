# Load the required assembly
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
$SqlConnection.ConnectionString = "Server=$SqlServerInstance;Database=$DatabaseName;User ID=$SqlServerUsername;Password=$SqlServerPassword;"
$SqlCommand = New-Object System.Data.SqlClient.SqlCommand
$SqlCommand.Connection = $SqlConnection

# Execute a SQL command to retrieve the records
$SelectSql = @"
SELECT TOP 10 [MenuCategory]
      ,[EntSync]
      ,[SyncStatus]
      ,[EntID]
      ,[MenuCategoryKey]
  FROM [Revention].[dbo].[MenuCategory]
"@

try {
    $SqlCommand.CommandText = $SelectSql
    $SqlConnection.Open()
    $DataAdapter = New-Object System.Data.SqlClient.SqlDataAdapter($SqlCommand)
    $DataSet = New-Object System.Data.DataSet
    $DataAdapter.Fill($DataSet) | Out-Null
    $SqlConnection.Close()

    # Display the results in a table format
    $DataSet.Tables[0] | Format-Table
} catch {
    Write-Host $_.Exception.Message
    $SqlConnection.Close()
}
