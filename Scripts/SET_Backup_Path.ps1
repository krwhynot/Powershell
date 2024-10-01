# Get computer name
$computerName = (Get-ComputerInfo).CsName

if ($computerName -eq 'Revent1') {
    # Validate each path
    $paths = @("C:\Revention\Backup", "E:\","D:\", "\\REVENT2\Revention\Backup", "\\REVENT3\Revention\Backup", "\\REVENT4\Revention\Backup", "R:\Backup", "C:\Revention\New")
    $validatedPaths = @()

    foreach ($path in $paths) {
        if (Test-Path $path) {
            $validatedPaths += $path
        }
    }

    # Assign first three validated paths to variables
    $Path1 = $validatedPaths[0]
    $Path2 = $validatedPaths[1]
    $Path3 = $validatedPaths[2]

    # Connect to SQL Server and update the record with BackupSchedKey = 1
    $SqlServerInstance = "Revent1\REVENTION" # Replace with your SQL Server instance
    $DatabaseName = "REVENTION" # Replace with your database name
    $Username = "Revention" # Replace with your SQL Server username
    $Password = "{PASSWORD}" # Replace with your SQL Server password

    $connectionString = "Server=$SqlServerInstance;Database=$DatabaseName;User Id=$Username;Password=$Password;"
    $connection = New-Object System.Data.SqlClient.SqlConnection $connectionString
    $connection.Open()
    $query = @"
UPDATE BackupSched
SET Path1 = '$Path1', Path2 = '$Path2', Path3 = '$Path3'
WHERE BackupSchedKey = 1
"@
    $command = New-Object System.Data.SqlClient.SqlCommand $query, $connection
    $command.ExecuteNonQuery()

    # Retrieve and display the updated paths
    $query = @"
SELECT Path1, Path2, Path3
FROM BackupSched
WHERE BackupSchedKey = 1
"@
    $command = New-Object System.Data.SqlClient.SqlCommand $query, $connection
    $reader = $command.ExecuteReader()

    if ($reader.Read()) {
        $Path1 = $reader["Path1"]
        $Path2 = $reader["Path2"]
        $Path3 = $reader["Path3"]
        Write-Host

        Write-Host "Paths updated in the database:"
        Write-Host "Path1: $Path1" -Foreground green
        Write-Host "Path2: $Path2" -Foreground green
        Write-Host "Path3: $Path3" -Foreground green
    } else {
        Write-Host "No paths were found in the database."
    }

    $connection.Close()
    Write-Host
    pause
} else {
    Write-Host "Script only runs on 'Revent1'"
}
