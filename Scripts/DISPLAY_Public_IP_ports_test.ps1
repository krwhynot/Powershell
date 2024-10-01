﻿# Function to safely get public IP address using AWS or OpenDNS
function Get-PublicIP {
    try {
        # Using AWS's reliable service to get public IP
        $ip = Invoke-RestMethod -Uri "http://checkip.amazonaws.com/"
        return $ip.Trim()  # Ensure any whitespace is removed
    }
    catch {
        # Fallback to using OpenDNS as an alternative
        Write-Warning "AWS service failed, trying OpenDNS..."
        try {
            $ip = Invoke-RestMethod -Uri "https://diagnostic.opendns.com/myip"
            return $ip.Trim()
        }
        catch {
            throw "Failed to retrieve public IP from all sources."
        }
    }
}

# Function to test if a port is open using Test-NetConnection
function Test-Port {
    param (
        [string]$hostname,
        [int]$port
    )
    try {
        $result = Test-NetConnection -ComputerName $hostname -Port $port
        return $result.TcpTestSucceeded
    }
    catch {
        return $false
    }
}

try {
    # Get public IP address using the safer method
    $public_ip = Get-PublicIP
    Write-Output "Your public IP address is: $public_ip"

    # Test specific ports on your public IP
    $ports = @(7777, 12230)
    foreach ($port in $ports) {
        if (Test-Port -hostname $public_ip -port $port) {
            Write-Output "Port $port is open."
        }
        else {
            Write-Output "Port $port is closed."
        }
    }
}
catch {
    Write-Error $_.Exception.Message
}
