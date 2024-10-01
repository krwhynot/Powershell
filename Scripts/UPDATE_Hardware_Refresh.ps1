
$SqlServerInstance = "{Server Instance}" # Replace with your SQL Server instance
$DatabaseName = "{DATABASE}" # Replace with your database name
$Username = "{USERNAME}" # Replace with your SQL Server username
$Password = "{PASSWORD}" # Replace with your SQL Server password

$connectionString = "Server=$SqlServerInstance;Database=$DatabaseName;User ID=$Username;Password=$Password;"
$connection = New-Object System.Data.SqlClient.SqlConnection $connectionString
$connection.Open()

# Update Computer table
$updateComputerQuery = "UPDATE Computer SET AllowCloseDay = 'False' WHERE ComputerName <> 'Station1';"
$updateComputerCommand = New-Object System.Data.SqlClient.SqlCommand $updateComputerQuery, $connection
$updateComputerCommand.ExecuteNonQuery() | Out-Null

# Update ComputerCCOpts table
$updateComputerCCOptsQuery = "UPDATE ComputerCCOpts SET AllowBatch = 'False' WHERE ComputerName <> 'Station1';"
$updateComputerCCOptsCommand = New-Object System.Data.SqlClient.SqlCommand $updateComputerCCOptsQuery, $connection
$updateComputerCCOptsCommand.ExecuteNonQuery() | Out-Null

# Define SQL query to select PaymentType table
$selectPaymentTypeQuery = "SELECT PaymentType, IsActive, OpenDrawer FROM PaymentType;"
$selectPaymentTypeCommand = New-Object System.Data.SqlClient.SqlCommand $selectPaymentTypeQuery, $connection
$paymentTypeReader = $selectPaymentTypeCommand.ExecuteReader()

$paymentTypeDataTable = New-Object System.Data.DataTable
$paymentTypeDataTable.Load($paymentTypeReader)

$paymentTypeReader.Close()
$paymentTypeDataTable | Format-Table -AutoSize

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
