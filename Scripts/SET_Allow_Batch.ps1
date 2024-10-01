# SET Allow Batch on Station 1 Only


$SqlServerInstance = "Revent1\REVENTION" # Replace with your SQL Server instance
$DatabaseName = "REVENTION" # Replace with your database name
$Username = "Revention" # Replace with your SQL Server username
$Password = "Astr0s" # Replace with your SQL Server password

$connectionString = "Server=$SqlServerInstance;Database=$DatabaseName;User ID=$Username;Password=$Password;"
$connection = New-Object System.Data.SqlClient.SqlConnection $connectionString
$connection.Open()

# SET Allow Batch
$updateComputerCCOptsQuery = "UPDATE ComputerCCOpts SET AllowBatch = 'False' WHERE ComputerName <> 'Station1';"
$updateComputerCCOptsCommand = New-Object System.Data.SqlClient.SqlCommand $updateComputerCCOptsQuery, $connection
$updateComputerCCOptsCommand.ExecuteNonQuery() | Out-Null

# Define SQL query to merge Computer and ComputerCCOpts
$query = @"
SELECT Computer.ComputerName, Computer.IPAddr, Computer.osComputerName, Computer.AllowCloseDay, ComputerCCOpts.AllowBatch
FROM Computer
INNER JOIN ComputerCCOpts ON Computer.ComputerName = ComputerCCOpts.ComputerName
"@

$command = New-Object System.Data.SqlClient.SqlCommand $query, $connection
$reader = $command.ExecuteReader()

$dataTable = New-Object System.Data.DataTable
$dataTable.Load($reader)

$reader.Close()
$dataTable | Format-Table -AutoSize

$connection.Close()
