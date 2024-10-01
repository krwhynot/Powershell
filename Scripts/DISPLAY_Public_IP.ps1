# Create a WebClient object
$webclient = New-Object System.Net.WebClient

# Get public IP
$public_ip = $webclient.DownloadString("http://ifconfig.me/ip")

# Trim the response to remove unwanted leading/trailing white spaces
$public_ip = $public_ip.Trim()

# Display the IP
Write-Output "Your public IP is: $public_ip"
