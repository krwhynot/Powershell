# SET Close Day on Station 1 Only


$SqlServerInstance = "Revent1\REVENTION" # Replace with your SQL Server instance
$DatabaseName = "REVENTION" # Replace with your database name
$Username = "Revention" # Replace with your SQL Server username
$Password = "{PASSWORD}" # Replace with your SQL Server password

$connectionString = "Server=$SqlServerInstance;Database=$DatabaseName;User ID=$Username;Password=$Password;"
$connection = New-Object System.Data.SqlClient.SqlConnection $connectionString
$connection.Open()

# Update AllowCloseDay in Computer table
$updateComputerQuery = "UPDATE Computer SET AllowCloseDay = 'False' WHERE ComputerName <> 'Station1';"
$updateComputerCommand = New-Object System.Data.SqlClient.SqlCommand $updateComputerQuery, $connection
$updateComputerCommand.ExecuteNonQuery() | Out-Null

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
