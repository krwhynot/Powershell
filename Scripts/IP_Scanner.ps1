function Find-LANHosts {
    [Cmdletbinding()]

    Param (
        [Parameter(Mandatory, Position=1)]
        [string]$StartIP,

        [Parameter(Mandatory, Position=2)]
        [string]$EndIP,

        [Parameter(Mandatory=$false, Position=3)]
        [ValidateRange(0,15000)]
        [int]$DelayMS = 2,

        [ValidateScript({
            $IsAdmin = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
            if ($IsAdmin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                $True
            } 
            else {
                Throw "Must be running an elevated prompt to use ClearARPCache"
            }
        })]
        [switch]$ClearARPCache
    )

    $ASCIIEncoding = New-Object System.Text.ASCIIEncoding
    $Bytes = $ASCIIEncoding.GetBytes("a")
    $UDP = New-Object System.Net.Sockets.Udpclient

    if ($ClearARPCache) {
        arp -d
    }

    $StartRange = [System.Net.IPAddress]::Parse($StartIP).GetAddressBytes()
    [Array]::Reverse($StartRange)
    $EndRange = [System.Net.IPAddress]::Parse($EndIP).GetAddressBytes()
    [Array]::Reverse($EndRange)

    $StartRange = [BitConverter]::ToUInt32($StartRange, 0)
    $EndRange = [BitConverter]::ToUInt32($EndRange, 0)

    $IP = @()

    for($i = $StartRange; $i -le $EndRange; $i++)
    {
        $TargetIP = ([System.Net.IPAddress]::Parse($i)).IPAddressToString
        $IP += $TargetIP
    }

    $Timer = [System.Diagnostics.Stopwatch]::StartNew()

    $IP | ForEach-Object {
        $UDP.Connect($_,1)
        [void]$UDP.Send($Bytes,$Bytes.length)
        if ($DelayMS) {
            [System.Threading.Thread]::Sleep($DelayMS)
        }
    }

    $Hosts = arp -a

    $Timer.Stop()
    if ($Timer.Elapsed.TotalSeconds -gt 15) {
        Write-Warning "Scan took longer than 15 seconds, ARP entries may have been flushed. Recommend lowering DelayMS parameter"
    }

    $Hosts = $Hosts | Where-Object {$_ -match "dynamic"} | % {($_.trim() -replace " {1,}",",") | ConvertFrom-Csv -Header "IP","MACAddress"}
    $Hosts = $Hosts | Where-Object {$_.IP -in $IP}

    $HostsWithNames = $Hosts | ForEach-Object {
        $HostName = $null
        try {
            $HostName = [System.Net.Dns]::GetHostEntry($_.IP).HostName
        }
        catch {
            $HostName = "N/A"
        }
        $_ | Add-Member -Type NoteProperty -Name "HostName" -Value $HostName -PassThru
    }

    Write-Output $HostsWithNames
}

Find-LANHosts -StartIP "192.168.192.1" -EndIP "192.168.192.254" -DelayMS 2 -ClearARPCache
