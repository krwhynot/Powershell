$comPort = "COM9"
$query = "SELECT * FROM Win32_PnPEntity WHERE Name LIKE '%$comPort%'"

$device = Get-WmiObject -Query $query

if ($device) {
    $idMatch = $device.PNPDeviceID -match '\d+$'
    $id = if ($idMatch) { $matches[0] } else { "ID not found" }
    
    [PSCustomObject]@{
        "Device Instance Path" = $id
        "Device Description"   = $device.Description
    }
} else {
    "Device not found."
}
