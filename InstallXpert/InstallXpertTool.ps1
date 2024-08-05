#========================================================================
# Name		: InstallXpert
# Author 	: Kyle Ramsy
#
# History Version
# 	1.0		202310  Version
#========================================================================
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser



#----------------------------------------------
#region Import Assemblies
#----------------------------------------------
[void][Reflection.Assembly]::Load('System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
[void][Reflection.Assembly]::Load('System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
[void][Reflection.Assembly]::Load('System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
[void][Reflection.Assembly]::Load('mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
[void][Reflection.Assembly]::Load('System.Data, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
#endregion Import Assemblies

function Main {
	Param ([String]$Commandline)
	
	if (Get-MainForm_pff -eq 'OK') {
		
	}
	$script:ExitCode = 0 
}

# Function to hide PowerShell console window
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();

[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'
#region Hide-Console
function Hide-Console {
	$consolePtr = [Console.Window]::GetConsoleWindow()
	# 0 = SW_HIDE
	[Console.Window]::ShowWindow($consolePtr, 0)
}

Hide-Console
#endregion

#--------------------------------------------
#region Declare Global Variables and Functions here
#--------------------------------------------
$Form_StateCorrection_Load =
{
	$form_MainForm.WindowState = [System.Windows.Forms.FormWindowState]::Minimized
}

#region Get-ComputerTxtBox
function Get-ComputerTxtBox
{	$global:ComputerName = $textbox_computername.Text }
#endregion

#region Add-RichTextBox
$global:stringBuilder = New-Object System.Text.StringBuilder

function Add-RichTextBox {
    [CmdletBinding()]
    param ($text)
    
    [void]$stringBuilder.AppendLine($text)
    [void]$stringBuilder.AppendLine("`n# # # # # # # # # #`n")

    $richtextbox_output.Text = $stringBuilder.ToString()
}
#endregion
	
#region Get-DateSortable
function Get-datesortable {
	$global:datesortable = Get-Date -Format "yyyyMMdd-HH':'mm':'ss"
	return $global:datesortable
}
#endregion 
	
#region Add-Logs
function Add-Logs {
    [CmdletBinding()]
    param ($text)

    Get-datesortable
    $logText = "[$global:datesortable] - $text"
    $richtextbox_logs.AppendText($logText)

    # Only add a newline if the rich text box content doesn't already end with one.
    if (-not $richtextbox_logs.Text.EndsWith([Environment]::NewLine)) {
        $richtextbox_logs.AppendText([Environment]::NewLine)
    }

    Set-Alias alogs Add-Logs -Description 'Add content to the RichTextBoxLogs'
}
#endregion 
	
#region Clear-RichTextBox
# Function - Clear the RichTextBox
function Clear-RichTextBox { $richtextbox_output.Text = '' }
#endregion
	
#region Add-ClipBoard
function Add-ClipBoard ($text) {
	Add-Type -AssemblyName System.Windows.Forms
	$tb = New-Object System.Windows.Forms.TextBox
	$tb.Multiline = $true
	$tb.Text = $text
	$tb.SelectAll()
	$tb.Copy()	
}
#endregion
		
#region Get-IP 
	
function Get-IP {
	           
	[Cmdletbinding()]
	Param(
		[alias('dnsHostName')]
		[Parameter(ValueFromPipelineByPropertyName = $true,ValueFromPipeline = $true)]
		[string]$ComputerName = $Env:COMPUTERNAME
	)
	Process {
		$NICs = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled='$True'" -ComputerName $ComputerName
		foreach ($Nic in $NICs) {
			$myobj = @{
				Name          = $Nic.Description
				MacAddress    = $Nic.MACAddress
				IP4           = $Nic.IPAddress | Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+' }
				IP6           = $Nic.IPAddress | Where-Object { $_ -match '\:\:' }
				IP4Subnet     = $Nic.IPSubnet | Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+' }
				DefaultGWY    = $Nic.DefaultIPGateway | Select-Object -First 1
				DNSServer     = $Nic.DNSServerSearchOrder
				WINSPrimary   = $Nic.WINSPrimaryServer
				WINSSecondary = $Nic.WINSSecondaryServer
			}
			$obj = New-Object PSObject -Property $myobj
			$obj.PSTypeNames.Clear()
			$obj.PSTypeNames.Add('BSonPosh.IPInfo')
			$obj
		}
	}
}
			
#endregion 

#region Invoke-IPv4NetworkScan
function Invoke-IPv4NetworkScan {
	[CmdletBinding(DefaultParameterSetName = 'CIDR')]
	Param(
		[Parameter(
			ParameterSetName = 'Range',
			Position = 0,
			Mandatory = $true,
			HelpMessage = 'Start IPv4-Address like 192.168.192.200')]
		[IPAddress]$StartIPv4Address,
		
		[Parameter(
			ParameterSetName = 'Range',
			Position = 1,
			Mandatory = $true,
			HelpMessage = 'End IPv4-Address like 192.168.1.254')]
		[IPAddress]$EndIPv4Address,
			
		[Parameter(
			ParameterSetName = 'CIDR',
			Position = 0,
			Mandatory = $true,
			HelpMessage = 'IPv4-Address which is in the subnet')]
		[Parameter(
			ParameterSetName = 'Mask',
			Position = 0,
			Mandatory = $true,
			HelpMessage = 'IPv4-Address which is in the subnet')]
		[IPAddress]$IPv4Address,
		
		[Parameter(
			ParameterSetName = 'CIDR',        
			Position = 1,
			Mandatory = $true,
			HelpMessage = 'CIDR like /24 without "/"')]
		[ValidateRange(0, 31)]
		[Int32]$CIDR,
		
		[Parameter(
			ParameterSetName = 'Mask',
			Position = 1,
			Mandatory = $true,
			Helpmessage = 'Subnetmask like 255.255.255.0')]
		[ValidateScript({
				if ($_ -match '^(254|252|248|240|224|192|128).0.0.0$|^255.(254|252|248|240|224|192|128|0).0.0$|^255.255.(254|252|248|240|224|192|128|0).0$|^255.255.255.(254|252|248|240|224|192|128|0)$') {
					return $true
				} else {
					throw 'Enter a valid subnetmask (like 255.255.255.0)!'    
				}
			})]
		[String]$Mask,
		
		[Parameter(
			Position = 2,
			HelpMessage = 'Maxmium number of ICMP checks for each IPv4-Address (Default=2)')]
		[Int32]$Tries = 2,
		
		[Parameter(
			Position = 3,
			HelpMessage = 'Maximum number of threads at the same time (Default=256)')]
		[Int32]$Threads = 256,
			
		[Parameter(
			Position = 4,
			HelpMessage = 'Resolve DNS for each IP (Default=Enabled)')]
		[Switch]$DisableDNSResolving,
		
		[Parameter(
			Position = 5,
			HelpMessage = 'Resolve MAC-Address for each IP (Default=Disabled)')]
		[Switch]$EnableMACResolving,
		
		[Parameter(
			Position = 6,
			HelpMessage = 'Get extendend informations like BufferSize, ResponseTime and TTL (Default=Disabled)')]
		[Switch]$ExtendedInformations,
		
		[Parameter(
			Position = 7,
			HelpMessage = 'Include inactive devices in result')]
		[Switch]$IncludeInactive
	)
		
	Begin {
		Write-Verbose -Message "Script started at $(Get-Date)"
			
		$OUIListPath = 'C:\Revention\Utilities\oui.txt'
		
		function Convert-Subnetmask {
			[CmdLetBinding(DefaultParameterSetName = 'CIDR')]
			param( 
				[Parameter( 
					ParameterSetName = 'CIDR',       
					Position = 0,
					Mandatory = $true,
					HelpMessage = 'CIDR like /24 without "/"')]
				[ValidateRange(0, 32)]
				[Int32]$CIDR,
		
				[Parameter(
					ParameterSetName = 'Mask',
					Position = 0,
					Mandatory = $true,
					HelpMessage = 'Subnetmask like 255.255.255.0')]
				[ValidateScript({
						if ($_ -match '^(254|252|248|240|224|192|128).0.0.0$|^255.(254|252|248|240|224|192|128|0).0.0$|^255.255.(254|252|248|240|224|192|128|0).0$|^255.255.255.(255|254|252|248|240|224|192|128|0)$') {
							return $true
						} else {
							throw 'Enter a valid subnetmask (like 255.255.255.0)!'    
						}
					})]
				[String]$Mask
			)
		
			Begin {
		
			}
		
			Process {
				switch ($PSCmdlet.ParameterSetName) {
					'CIDR' {                          
						# Make a string of bits (24 to 11111111111111111111111100000000)
						$CIDR_Bits = ('1' * $CIDR).PadRight(32, '0')
							
						# Split into groups of 8 bits, convert to Ints, join up into a string
						$Octets = $CIDR_Bits -split '(.{8})' -ne ''
						$Mask = ($Octets | ForEach-Object -Process { [Convert]::ToInt32($_, 2) }) -join '.'
					}
		
					'Mask' {
						# Convert the numbers into 8 bit blocks, join them all together, count the 1
						$Octets = $Mask.ToString().Split('.') | ForEach-Object -Process { [Convert]::ToString($_, 2) }
						$CIDR_Bits = ($Octets -join '').TrimEnd('0')
		
						# Count the "1" (111111111111111111111111 --> /24)                     
						$CIDR = $CIDR_Bits.Length             
					}               
				}
		
				[pscustomobject] @{
					Mask = $Mask
					CIDR = $CIDR
				}
			}
		
			End {
					
			}
		}
		
		# Helper function to convert an IPv4-Address to Int64 and vise versa
		function Convert-IPv4Address {
			[CmdletBinding(DefaultParameterSetName = 'IPv4Address')]
			param(
				[Parameter(
					ParameterSetName = 'IPv4Address',
					Position = 0,
					Mandatory = $true,
					HelpMessage = 'IPv4-Address as string like "192.168.1.1"')]
				[IPaddress]$IPv4Address,
		
				[Parameter(
					ParameterSetName = 'Int64',
					Position = 0,
					Mandatory = $true,
					HelpMessage = 'IPv4-Address as Int64 like 2886755428')]
				[long]$Int64
			) 
		
			Begin {
		
			}
		
			Process {
				switch ($PSCmdlet.ParameterSetName) {
					# Convert IPv4-Address as string into Int64
					'IPv4Address' {
						$Octets = $IPv4Address.ToString().Split('.') 
						$Int64 = [long]([long]$Octets[0] * 16777216 + [long]$Octets[1] * 65536 + [long]$Octets[2] * 256 + [long]$Octets[3]) 
					}
				
					# Convert IPv4-Address as Int64 into string 
					'Int64' {            
						$IPv4Address = (([System.Math]::Truncate($Int64 / 16777216)).ToString() + '.' + ([System.Math]::Truncate(($Int64 % 16777216) / 65536)).ToString() + '.' + ([System.Math]::Truncate(($Int64 % 65536) / 256)).ToString() + '.' + ([System.Math]::Truncate($Int64 % 256)).ToString())
					}      
				}
		
				[pscustomobject] @{   
					IPv4Address = $IPv4Address
					Int64       = $Int64
				}
			}
		
			End {
		
			}
		}
		
		# Helper function to create a new Subnet
		function Get-IPv4Subnet {
			[CmdletBinding(DefaultParameterSetName = 'CIDR')]
			param(
				[Parameter(
					Position = 0,
					Mandatory = $true,
					HelpMessage = 'IPv4-Address which is in the subnet')]
				[IPAddress]$IPv4Address,
		
				[Parameter(
					ParameterSetName = 'CIDR',
					Position = 1,
					Mandatory = $true,
					HelpMessage = 'CIDR like /24 without "/"')]
				[ValidateRange(0, 31)]
				[Int32]$CIDR,
		
				[Parameter(
					ParameterSetName = 'Mask',
					Position = 1,
					Mandatory = $true,
					Helpmessage = 'Subnetmask like 255.255.255.0')]
				[ValidateScript({
						if ($_ -match '^(254|252|248|240|224|192|128).0.0.0$|^255.(254|252|248|240|224|192|128|0).0.0$|^255.255.(254|252|248|240|224|192|128|0).0$|^255.255.255.(254|252|248|240|224|192|128|0)$') {
							return $true
						} else {
							throw 'Enter a valid subnetmask (like 255.255.255.0)!'    
						}
					})]
				[String]$Mask
			)
		
			Begin {
				
			}
		
			Process {
				# Convert Mask or CIDR - because we need both in the code below
				switch ($PSCmdlet.ParameterSetName) {
					'CIDR' {                          
						$Mask = (Convert-Subnetmask -CIDR $CIDR).Mask            
					}
					'Mask' {
						$CIDR = (Convert-Subnetmask -Mask $Mask).CIDR          
					}                  
				}
					
				# Get CIDR Address by parsing it into an IP-Address
				$CIDRAddress = [System.Net.IPAddress]::Parse([System.Convert]::ToUInt64(('1' * $CIDR).PadRight(32, '0'), 2))
				
				# Binary AND ... this is how subnets work.
				$NetworkID_bAND = $IPv4Address.Address -band $CIDRAddress.Address
		
				# Return an array of bytes. Then join them.
				$NetworkID = [System.Net.IPAddress]::Parse([System.BitConverter]::GetBytes([UInt32]$NetworkID_bAND) -join ('.'))
					
				# Get HostBits based on SubnetBits (CIDR) // Hostbits (32 - /24 = 8 -> 00000000000000000000000011111111)
				$HostBits = ('1' * (32 - $CIDR)).PadLeft(32, '0')
					
				# Convert Bits to Int64
				$AvailableIPs = [Convert]::ToInt64($HostBits, 2)
		
				# Convert Network Address to Int64
				$NetworkID_Int64 = (Convert-IPv4Address -IPv4Address $NetworkID.ToString()).Int64
		
				# Convert add available IPs and parse into IPAddress
				$Broadcast = [System.Net.IPAddress]::Parse((Convert-IPv4Address -Int64 ($NetworkID_Int64 + $AvailableIPs)).IPv4Address)
					
				# Change useroutput ==> (/27 = 0..31 IPs -> AvailableIPs 32)
				$AvailableIPs += 1
		
				# Hosts = AvailableIPs - Network Address + Broadcast Address
				$Hosts = ($AvailableIPs - 2)
						
				# Build custom PSObject
				[pscustomobject] @{
					NetworkID = $NetworkID
					Broadcast = $Broadcast
					IPs       = $AvailableIPs
					Hosts     = $Hosts
				}
			}
		
			End {
		
			}
		}     
	}
		
	Process {
		# Calculate Subnet (Start and End IPv4-Address)
		if ($PSCmdlet.ParameterSetName -eq 'CIDR' -or $PSCmdlet.ParameterSetName -eq 'Mask') {
			# Convert Subnetmask
			if ($PSCmdlet.ParameterSetName -eq 'Mask') {
				$CIDR = (Convert-Subnetmask -Mask $Mask).CIDR     
			}
		
			# Create new subnet
			$Subnet = Get-IPv4Subnet -IPv4Address $IPv4Address -CIDR $CIDR
		
			# Assign Start and End IPv4-Address
			$StartIPv4Address = $Subnet.NetworkID
			$EndIPv4Address = $Subnet.Broadcast
		}
		
		# Convert Start and End IPv4-Address to Int64
		$StartIPv4Address_Int64 = (Convert-IPv4Address -IPv4Address $StartIPv4Address.ToString()).Int64
		$EndIPv4Address_Int64 = (Convert-IPv4Address -IPv4Address $EndIPv4Address.ToString()).Int64
		
		# Check if range is valid
		if ($StartIPv4Address_Int64 -gt $EndIPv4Address_Int64) {
			Write-Error -Message 'Invalid IP-Range... Check your input!' -Category InvalidArgument -ErrorAction Stop
		}
		
		# Calculate IPs to scan (range)
		$IPsToScan = ($EndIPv4Address_Int64 - $StartIPv4Address_Int64)
			
		Write-Verbose -Message "Scanning range from $StartIPv4Address to $EndIPv4Address ($($IPsToScan + 1) IPs)"
		Write-Verbose -Message "Running with max $Threads threads"
		Write-Verbose -Message "ICMP checks per IP: $Tries"
		
		# Properties which are displayed in the output
		$PropertiesToDisplay = @()
		$PropertiesToDisplay += 'IPv4Address', 'Status'
		
		if ($DisableDNSResolving -eq $false) {
			$PropertiesToDisplay += 'Hostname'
		}
		
		if ($EnableMACResolving) {
			$PropertiesToDisplay += 'MAC'
		}
		
		# Check if it is possible to assign vendor to MAC --> import CSV-File 
		if ($EnableMACResolving) {
			if (Test-Path -Path $OUIListPath -PathType Leaf) {
				$OUIHashTable = @{ }
		
				Write-Verbose -Message 'Read oui.txt and fill hash table...'
		
				foreach ($Line in Get-Content -Path $OUIListPath) {
					if (-not([String]::IsNullOrEmpty($Line))) {
						try {
							$HashTableData = $Line.Split('|')
							$OUIHashTable.Add($HashTableData[0], $HashTableData[1])
						} catch [System.ArgumentException] { } # Catch if mac is already added to hash table
					}
				}
		
				$AssignVendorToMAC = $true
		
				$PropertiesToDisplay += 'Vendor'
			} else {
				$AssignVendorToMAC = $false
		
				Write-Warning -Message 'No OUI-File to assign vendor with MAC-Address found! Execute the script "Create-OUIListFromWeb.ps1" to download the latest version. This warning does not affect the scanning procedure.'
			}
		}  
			
		if ($ExtendedInformations) {
			$PropertiesToDisplay += 'BufferSize', 'ResponseTime', 'TTL'
		}
		
		# Scriptblock --> will run in runspaces (threads)...
		[System.Management.Automation.ScriptBlock]$ScriptBlock = {
			Param(
				$IPv4Address,
				$Tries,
				$DisableDNSResolving,
				$EnableMACResolving,
				$ExtendedInformations,
				$IncludeInactive
			)
			# +++ Send ICMP requests +++
			$Status = [String]::Empty
		
			for ($i = 0; $i -lt $Tries; i++) {
				try {
					$PingObj = New-Object System.Net.NetworkInformation.Ping
						
					$Timeout = 1000
					$Buffer = New-Object Byte[] 32
						
					$PingResult = $PingObj.Send($IPv4Address, $Timeout, $Buffer)
		
					if ($PingResult.Status -eq 'Success') {
						$Status = 'Up'
						break # Exit loop, if host is reachable
					} else {
						$Status = 'Down'
					}
				} catch {
					$Status = 'Down'
					break # Exit loop, if there is an error
				}
			}
					
			# +++ Resolve DNS +++
			$Hostname = [String]::Empty     
		
			if ((-not($DisableDNSResolving)) -and ($Status -eq 'Up' -or $IncludeInactive)) {   	
				try { 
					$Hostname = ([System.Net.Dns]::GetHostEntry($IPv4Address).HostName)
				} catch { } # No DNS      
			}
			
			# +++ Get MAC-Address +++
			$MAC = [String]::Empty 
		
			if (($EnableMACResolving) -and (($Status -eq 'Up') -or ($IncludeInactive))) {
				$Arp_Result = (arp -a).ToUpper().Trim()
		
				foreach ($Line in $Arp_Result) {                
					if ($Line.Split(' ')[0] -eq $IPv4Address) {                    
						$MAC = [Regex]::Matches($Line, '([0-9A-F][0-9A-F]-){5}([0-9A-F][0-9A-F])').Value
					}
				}
			}
		
			# +++ Get extended informations +++
			$BufferSize = [String]::Empty 
			$ResponseTime = [String]::Empty 
			$TTL = $null
		
			if ($ExtendedInformations -and ($Status -eq 'Up')) {
				try {
					$BufferSize = $PingResult.Buffer.Length
					$ResponseTime = $PingResult.RoundtripTime
					$TTL = $PingResult.Options.Ttl
				} catch { } # Failed to get extended informations
			}	
			
			# +++ Result +++        
			if (($Status -eq 'Up') -or ($IncludeInactive)) {
				[pscustomobject] @{
					IPv4Address  = $IPv4Address
					Status       = $Status
					Hostname     = $Hostname
					MAC          = $MAC   
					BufferSize   = $BufferSize
					ResponseTime = $ResponseTime
					TTL          = $TTL
				}
			} else {
				$null
			}
		} 
		
		Write-Verbose -Message 'Setting up RunspacePool...'
		
		# Create RunspacePool and Jobs
		$RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Threads, $Host)
		$RunspacePool.Open()
		[System.Collections.ArrayList]$Jobs = @()
		
		Write-Verbose -Message 'Setting up jobs...'
		
		# Set up jobs for each IP...
		for ($i = $StartIPv4Address_Int64; $i -le $EndIPv4Address_Int64; $i++) { 
			# Convert IP back from Int64
			$IPv4Address = (Convert-IPv4Address -Int64 $i).IPv4Address                
		
			# Create hashtable to pass parameters
			$ScriptParams = @{
				IPv4Address          = $IPv4Address
				Tries                = $Tries
				DisableDNSResolving  = $DisableDNSResolving
				EnableMACResolving   = $EnableMACResolving
				ExtendedInformations = $ExtendedInformations
				IncludeInactive      = $IncludeInactive
			}       
		
			# Catch when trying to divide through zero
			try {
				$Progress_Percent = (($i - $StartIPv4Address_Int64) / $IPsToScan) * 100 
			} catch { 
				$Progress_Percent = 100 
			}
		
			Write-Progress -Activity 'Setting up jobs...' -Id 1 -Status "Current IP-Address: $IPv4Address" -PercentComplete $Progress_Percent
								
			# Create new job
			$Job = [System.Management.Automation.PowerShell]::Create().AddScript($ScriptBlock).AddParameters($ScriptParams)
			$Job.RunspacePool = $RunspacePool
				
			$JobObj = [pscustomobject] @{
				RunNum = $i - $StartIPv4Address_Int64
				Pipe   = $Job
				Result = $Job.BeginInvoke()
			}
		
			# Add job to collection
			[void]$Jobs.Add($JobObj)
		}
		
		Write-Verbose -Message 'Waiting for jobs to complete & starting to process results...'
		
		# Total jobs to calculate percent complete, because jobs are removed after they are processed
		$Jobs_Total = $Jobs.Count
		
		# Process results, while waiting for other jobs
		Do {
			# Get all jobs, which are completed
			$Jobs_ToProcess = $Jobs | Where-Object -FilterScript { $_.Result.IsCompleted }
		
			# If no jobs finished yet, wait 500 ms and try again
			if ($null -eq $Jobs_ToProcess) {
				Write-Verbose -Message 'No jobs completed, wait 250ms...'
		
				Start-Sleep -Milliseconds 250
				continue
			}
				
			# Get jobs, which are not complete yet
			$Jobs_Remaining = ($Jobs | Where-Object -FilterScript { $_.Result.IsCompleted -eq $false }).Count
		
			# Catch when trying to divide through zero
			try {            
				$Progress_Percent = 100 - (($Jobs_Remaining / $Jobs_Total) * 100) 
			} catch {
				$Progress_Percent = 100
			}
		
			Write-Progress -Activity "Waiting for jobs to complete... ($($Threads - $($RunspacePool.GetAvailableRunspaces())) of $Threads threads running)" -Id 1 -PercentComplete $Progress_Percent -Status "$Jobs_Remaining remaining..."
			
			Write-Verbose -Message "Processing $(if($null -eq $Jobs_ToProcess.Count){'1'}else{$Jobs_ToProcess.Count}) job(s)..."
		
			# Processing completed jobs
			foreach ($Job in $Jobs_ToProcess) {       
				# Get the result...     
				$Job_Result = $Job.Pipe.EndInvoke($Job.Result)
				$Job.Pipe.Dispose()
		
				# Remove job from collection
				$Jobs.Remove($Job)
				
				# Check if result contains status
				if ($Job_Result.Status) {        
					if ($AssignVendorToMAC) {           
						$Vendor = [String]::Empty
		
						# Check if MAC is null or empty
						if (-not([String]::IsNullOrEmpty($Job_Result.MAC))) {
							# Split it, so we can search the vendor (XX-XX-XX-XX-XX-XX to XXXXXX)
							$MAC_VendorSearch = $Job_Result.MAC.Replace('-', '').Substring(0, 6)
										
							$Vendor = $OUIHashTable.Get_Item($MAC_VendorSearch)
						}
		
						[pscustomobject] @{
							IPv4Address  = $Job_Result.IPv4Address
							Status       = $Job_Result.Status
							Hostname     = $Job_Result.Hostname
							MAC          = $Job_Result.MAC
							Vendor       = $Vendor  
							BufferSize   = $Job_Result.BufferSize
							ResponseTime = $Job_Result.ResponseTime
							TTL          = $ResuJob_Resultlt.TTL
						} | Select-Object -Property $PropertiesToDisplay
					} else {
						$Job_Result | Select-Object -Property $PropertiesToDisplay
					}                            
				}
			} 
		
		} While ($Jobs.Count -gt 0)
		
		Write-Verbose -Message 'Closing RunspacePool and free resources...'
		
		# Close the RunspacePool and free resources
		$RunspacePool.Close()
		$RunspacePool.Dispose()
		
		Write-Verbose -Message "Script finished at $(Get-Date)"
	}
		
	End {
			
	}
}
#endregion

#region Invoke-IPv4NetworkScanDevice

function Invoke-IPv4NetworkScanDevice {
    [CmdletBinding(DefaultParameterSetName = 'CIDR')]
    Param(
        [Parameter(
            ParameterSetName = 'Range',
            Position = 0,
            Mandatory = $true,
            HelpMessage = 'Start IPv4-Address like 192.168.192.200')]
        [IPAddress]$StartIPv4Address,
    
        [Parameter(
            ParameterSetName = 'Range',
            Position = 1,
            Mandatory = $true,
            HelpMessage = 'End IPv4-Address like 192.168.1.254')]
        [IPAddress]$EndIPv4Address,
        
        [Parameter(
            ParameterSetName = 'CIDR',
            Position = 0,
            Mandatory = $true,
            HelpMessage = 'IPv4-Address which is in the subnet')]
        [Parameter(
            ParameterSetName = 'Mask',
            Position = 0,
            Mandatory = $true,
            HelpMessage = 'IPv4-Address which is in the subnet')]
        [IPAddress]$IPv4Address,
    
        [Parameter(
            ParameterSetName = 'CIDR',        
            Position = 1,
            Mandatory = $true,
            HelpMessage = 'CIDR like /24 without "/"')]
        [ValidateRange(0, 31)]
        [Int32]$CIDR,
       
        [Parameter(
            ParameterSetName = 'Mask',
            Position = 1,
            Mandatory = $true,
            Helpmessage = 'Subnetmask like 255.255.255.0')]
        [ValidateScript({
                if ($_ -match "^(254|252|248|240|224|192|128).0.0.0$|^255.(254|252|248|240|224|192|128|0).0.0$|^255.255.(254|252|248|240|224|192|128|0).0$|^255.255.255.(254|252|248|240|224|192|128|0)$") {
                    return $true
                }
                else {
                    throw "Enter a valid subnetmask (like 255.255.255.0)!"    
                }
            })]
        [String]$Mask,
    
        [Parameter(
            Position = 2,
            HelpMessage = 'Maxmium number of ICMP checks for each IPv4-Address (Default=2)')]
        [Int32]$Tries = 2,
    
        [Parameter(
            Position = 3,
            HelpMessage = 'Maximum number of threads at the same time (Default=256)')]
        [Int32]$Threads = 256,
        
        [Parameter(
            Position = 4,
            HelpMessage = 'Resolve DNS for each IP (Default=Enabled)')]
        [Switch]$DisableDNSResolving,
    
        [Parameter(
            Position = 5,
            HelpMessage = 'Resolve MAC-Address for each IP (Default=Disabled)')]
        [Switch]$EnableMACResolving,
    
        [Parameter(
            Position = 6,
            HelpMessage = 'Get extendend informations like BufferSize, ResponseTime and TTL (Default=Disabled)')]
        [Switch]$ExtendedInformations,
    
        [Parameter(
            Position = 7,
            HelpMessage = 'Include inactive devices in result')]
        [Switch]$IncludeInactive
    )
    
    Begin {
        Write-Verbose -Message "Script started at $(Get-Date)"
        
        $OUIListPath = "C:\Revention\Utilities\oui.txt"
    
        function Convert-Subnetmask {
            [CmdLetBinding(DefaultParameterSetName = 'CIDR')]
            param( 
                [Parameter( 
                    ParameterSetName = 'CIDR',       
                    Position = 0,
                    Mandatory = $true,
                    HelpMessage = 'CIDR like /24 without "/"')]
                [ValidateRange(0, 32)]
                [Int32]$CIDR,
    
                [Parameter(
                    ParameterSetName = 'Mask',
                    Position = 0,
                    Mandatory = $true,
                    HelpMessage = 'Subnetmask like 255.255.255.0')]
                [ValidateScript({
                        if ($_ -match "^(254|252|248|240|224|192|128).0.0.0$|^255.(254|252|248|240|224|192|128|0).0.0$|^255.255.(254|252|248|240|224|192|128|0).0$|^255.255.255.(255|254|252|248|240|224|192|128|0)$") {
                            return $true
                        }
                        else {
                            throw "Enter a valid subnetmask (like 255.255.255.0)!"    
                        }
                    })]
                [String]$Mask
            )
    
            Begin {
    
            }
    
            Process {
                switch ($PSCmdlet.ParameterSetName) {
                    "CIDR" {                          
                        # Make a string of bits (24 to 11111111111111111111111100000000)
                        $CIDR_Bits = ('1' * $CIDR).PadRight(32, "0")
                        
                        # Split into groups of 8 bits, convert to Ints, join up into a string
                        $Octets = $CIDR_Bits -split '(.{8})' -ne ''
                        $Mask = ($Octets | ForEach-Object -Process { [Convert]::ToInt32($_, 2) }) -join '.'
                    }
    
                    "Mask" {
                        # Convert the numbers into 8 bit blocks, join them all together, count the 1
                        $Octets = $Mask.ToString().Split(".") | ForEach-Object -Process { [Convert]::ToString($_, 2) }
                        $CIDR_Bits = ($Octets -join "").TrimEnd("0")
    
                        # Count the "1" (111111111111111111111111 --> /24)                     
                        $CIDR = $CIDR_Bits.Length             
                    }               
                }
    
                [pscustomobject] @{
                    Mask = $Mask
                    CIDR = $CIDR
                }
            }
    
            End {
                
            }
        }
    
        # Helper function to convert an IPv4-Address to Int64 and vise versa
        function Convert-IPv4Address {
            [CmdletBinding(DefaultParameterSetName = 'IPv4Address')]
            param(
                [Parameter(
                    ParameterSetName = 'IPv4Address',
                    Position = 0,
                    Mandatory = $true,
                    HelpMessage = 'IPv4-Address as string like "192.168.1.1"')]
                [IPaddress]$IPv4Address,
    
                [Parameter(
                    ParameterSetName = 'Int64',
                    Position = 0,
                    Mandatory = $true,
                    HelpMessage = 'IPv4-Address as Int64 like 2886755428')]
                [long]$Int64
            ) 
    
            Begin {
    
            }
    
            Process {
                switch ($PSCmdlet.ParameterSetName) {
                    # Convert IPv4-Address as string into Int64
                    "IPv4Address" {
                        $Octets = $IPv4Address.ToString().Split(".") 
                        $Int64 = [long]([long]$Octets[0] * 16777216 + [long]$Octets[1] * 65536 + [long]$Octets[2] * 256 + [long]$Octets[3]) 
                    }
            
                    # Convert IPv4-Address as Int64 into string 
                    "Int64" {            
                        $IPv4Address = (([System.Math]::Truncate($Int64 / 16777216)).ToString() + "." + ([System.Math]::Truncate(($Int64 % 16777216) / 65536)).ToString() + "." + ([System.Math]::Truncate(($Int64 % 65536) / 256)).ToString() + "." + ([System.Math]::Truncate($Int64 % 256)).ToString())
                    }      
                }
    
                [pscustomobject] @{   
                    IPv4Address = $IPv4Address
                    Int64       = $Int64
                }
            }
    
            End {
    
            }
        }
    
        # Helper function to create a new Subnet
        function Get-IPv4Subnet {
            [CmdletBinding(DefaultParameterSetName = 'CIDR')]
            param(
                [Parameter(
                    Position = 0,
                    Mandatory = $true,
                    HelpMessage = 'IPv4-Address which is in the subnet')]
                [IPAddress]$IPv4Address,
    
                [Parameter(
                    ParameterSetName = 'CIDR',
                    Position = 1,
                    Mandatory = $true,
                    HelpMessage = 'CIDR like /24 without "/"')]
                [ValidateRange(0, 31)]
                [Int32]$CIDR,
    
                [Parameter(
                    ParameterSetName = 'Mask',
                    Position = 1,
                    Mandatory = $true,
                    Helpmessage = 'Subnetmask like 255.255.255.0')]
                [ValidateScript({
                        if ($_ -match "^(254|252|248|240|224|192|128).0.0.0$|^255.(254|252|248|240|224|192|128|0).0.0$|^255.255.(254|252|248|240|224|192|128|0).0$|^255.255.255.(254|252|248|240|224|192|128|0)$") {
                            return $true
                        }
                        else {
                            throw "Enter a valid subnetmask (like 255.255.255.0)!"    
                        }
                    })]
                [String]$Mask
            )
    
            Begin {
            
            }
    
            Process {
                # Convert Mask or CIDR - because we need both in the code below
                switch ($PSCmdlet.ParameterSetName) {
                    "CIDR" {                          
                        $Mask = (Convert-Subnetmask -CIDR $CIDR).Mask            
                    }
                    "Mask" {
                        $CIDR = (Convert-Subnetmask -Mask $Mask).CIDR          
                    }                  
                }
                
                # Get CIDR Address by parsing it into an IP-Address
                $CIDRAddress = [System.Net.IPAddress]::Parse([System.Convert]::ToUInt64(("1" * $CIDR).PadRight(32, "0"), 2))
            
                # Binary AND ... this is how subnets work.
                $NetworkID_bAND = $IPv4Address.Address -band $CIDRAddress.Address
    
                # Return an array of bytes. Then join them.
                $NetworkID = [System.Net.IPAddress]::Parse([System.BitConverter]::GetBytes([UInt32]$NetworkID_bAND) -join ("."))
                
                # Get HostBits based on SubnetBits (CIDR) // Hostbits (32 - /24 = 8 -> 00000000000000000000000011111111)
                $HostBits = ('1' * (32 - $CIDR)).PadLeft(32, "0")
                
                # Convert Bits to Int64
                $AvailableIPs = [Convert]::ToInt64($HostBits, 2)
    
                # Convert Network Address to Int64
                $NetworkID_Int64 = (Convert-IPv4Address -IPv4Address $NetworkID.ToString()).Int64
    
                # Convert add available IPs and parse into IPAddress
                $Broadcast = [System.Net.IPAddress]::Parse((Convert-IPv4Address -Int64 ($NetworkID_Int64 + $AvailableIPs)).IPv4Address)
                
                # Change useroutput ==> (/27 = 0..31 IPs -> AvailableIPs 32)
                $AvailableIPs += 1
    
                # Hosts = AvailableIPs - Network Address + Broadcast Address
                $Hosts = ($AvailableIPs - 2)
                    
                # Build custom PSObject
                [pscustomobject] @{
                    NetworkID = $NetworkID
                    Broadcast = $Broadcast
                    IPs       = $AvailableIPs
                       Hosts     = $Hosts
                }
            }
    
            End {
    
            }
        }     
    }
    
    Process {
        # Calculate Subnet (Start and End IPv4-Address)
        if ($PSCmdlet.ParameterSetName -eq 'CIDR' -or $PSCmdlet.ParameterSetName -eq 'Mask') {
            # Convert Subnetmask
            if ($PSCmdlet.ParameterSetName -eq 'Mask') {
                $CIDR = (Convert-Subnetmask -Mask $Mask).CIDR     
            }
    
            # Create new subnet
            $Subnet = Get-IPv4Subnet -IPv4Address $IPv4Address -CIDR $CIDR
    
            # Assign Start and End IPv4-Address
            $StartIPv4Address = $Subnet.NetworkID
            $EndIPv4Address = $Subnet.Broadcast
        }
    
        # Convert Start and End IPv4-Address to Int64
        $StartIPv4Address_Int64 = (Convert-IPv4Address -IPv4Address $StartIPv4Address.ToString()).Int64
        $EndIPv4Address_Int64 = (Convert-IPv4Address -IPv4Address $EndIPv4Address.ToString()).Int64
    
        # Check if range is valid
        if ($StartIPv4Address_Int64 -gt $EndIPv4Address_Int64) {
            Write-Error -Message "Invalid IP-Range... Check your input!" -Category InvalidArgument -ErrorAction Stop
        }
    
        # Calculate IPs to scan (range)
        $IPsToScan = ($EndIPv4Address_Int64 - $StartIPv4Address_Int64)
        
        Write-Verbose -Message "Scanning range from $StartIPv4Address to $EndIPv4Address ($($IPsToScan + 1) IPs)"
        Write-Verbose -Message "Running with max $Threads threads"
        Write-Verbose -Message "ICMP checks per IP: $Tries"
    
        # Properties which are displayed in the output
        $PropertiesToDisplay = @()
        $PropertiesToDisplay += "IPv4Address", "Status"
    
        if ($DisableDNSResolving -eq $false) {
            $PropertiesToDisplay += "Hostname"
        }
    
        if ($EnableMACResolving) {
            $PropertiesToDisplay += "MAC"
        }
    
        # Check if it is possible to assign vendor to MAC --> import CSV-File 
        if ($EnableMACResolving) {
            if (Test-Path -Path $OUIListPath -PathType Leaf) {
                $OUIHashTable = @{ }
    
                Write-Verbose -Message "Read oui.txt and fill hash table..."
    
                foreach ($Line in Get-Content -Path $OUIListPath) {
                    if (-not([String]::IsNullOrEmpty($Line))) {
                        try {
                            $HashTableData = $Line.Split('|')
                            $OUIHashTable.Add($HashTableData[0], $HashTableData[1])
                        }
                        catch [System.ArgumentException] { } # Catch if mac is already added to hash table
                    }
                }
    
                $AssignVendorToMAC = $true
    
                $PropertiesToDisplay += "Vendor"
            }
            else {
                $AssignVendorToMAC = $false
    
                Write-Warning -Message "No OUI-File to assign vendor with MAC-Address found! Execute the script ""Create-OUIListFromWeb.ps1"" to download the latest version. This warning does not affect the scanning procedure."
            }
        }  
        
        if ($ExtendedInformations) {
            $PropertiesToDisplay += "BufferSize", "ResponseTime", "TTL"
        }
    
        # Scriptblock --> will run in runspaces (threads)...
        [System.Management.Automation.ScriptBlock]$ScriptBlock = {
            Param(
                $IPv4Address,
                $Tries,
                $DisableDNSResolving,
                $EnableMACResolving,
                $ExtendedInformations,
                $IncludeInactive
            )
     
            # +++ Send ICMP requests +++
            $Status = [String]::Empty
    
            for ($i = 0; $i -lt $Tries; i++) {
                try {
                    $PingObj = New-Object System.Net.NetworkInformation.Ping
                    
                    $Timeout = 1000
                    $Buffer = New-Object Byte[] 32
                    
                    $PingResult = $PingObj.Send($IPv4Address, $Timeout, $Buffer)
    
                    if ($PingResult.Status -eq "Success") {
                        $Status = "Up"
                        break # Exit loop, if host is reachable
                    }
                    else {
                        $Status = "Down"
                    }
                }
                catch {
                    $Status = "Down"
                    break # Exit loop, if there is an error
                }
            }
                 
            # +++ Resolve DNS +++
            $Hostname = [String]::Empty     
    
            if ((-not($DisableDNSResolving)) -and ($Status -eq "Up" -or $IncludeInactive)) {   	
                try { 
                    $Hostname = ([System.Net.Dns]::GetHostEntry($IPv4Address).HostName)
                } 
                catch { } # No DNS      
            }
         
            # +++ Get MAC-Address +++
            $MAC = [String]::Empty 
    
            if (($EnableMACResolving) -and (($Status -eq "Up") -or ($IncludeInactive))) {
                $Arp_Result = (arp -a).ToUpper().Trim()
    
                foreach ($Line in $Arp_Result) {                
                    if ($Line.Split(" ")[0] -eq $IPv4Address) {                    
                        $MAC = [Regex]::Matches($Line, "([0-9A-F][0-9A-F]-){5}([0-9A-F][0-9A-F])").Value
                    }
                }
            }
    
            # +++ Get extended informations +++
            $BufferSize = [String]::Empty 
            $ResponseTime = [String]::Empty 
            $TTL = $null
    
            if ($ExtendedInformations -and ($Status -eq "Up")) {
                try {
                    $BufferSize = $PingResult.Buffer.Length
                    $ResponseTime = $PingResult.RoundtripTime
                    $TTL = $PingResult.Options.Ttl
                }
                catch { } # Failed to get extended informations
            }	
        
            # +++ Result +++        
            if (($Status -eq "Up") -or ($IncludeInactive)) {
                [pscustomobject] @{
                    IPv4Address  = $IPv4Address
                    Status       = $Status
                    Hostname     = $Hostname
                    MAC          = $MAC   
                    BufferSize   = $BufferSize
                    ResponseTime = $ResponseTime
                    TTL          = $TTL
                }
            }
            else {
                $null
            }
        } 
    
        Write-Verbose -Message "Setting up RunspacePool..."
    
        # Create RunspacePool and Jobs
        $RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Threads, $Host)
        $RunspacePool.Open()
        [System.Collections.ArrayList]$Jobs = @()
    
        Write-Verbose -Message "Setting up jobs..."
    
        # Set up jobs for each IP...
        for ($i = $StartIPv4Address_Int64; $i -le $EndIPv4Address_Int64; $i++) { 
            # Convert IP back from Int64
            $IPv4Address = (Convert-IPv4Address -Int64 $i).IPv4Address                
    
            # Create hashtable to pass parameters
            $ScriptParams = @{
                IPv4Address          = $IPv4Address
                Tries                = $Tries
                DisableDNSResolving  = $DisableDNSResolving
                EnableMACResolving   = $EnableMACResolving
                ExtendedInformations = $ExtendedInformations
                IncludeInactive      = $IncludeInactive
            }       
    
            # Catch when trying to divide through zero
            try {
                $Progress_Percent = (($i - $StartIPv4Address_Int64) / $IPsToScan) * 100 
            } 
            catch { 
                $Progress_Percent = 100 
            }
    
            Write-Progress -Activity "Setting up jobs..." -Id 1 -Status "Current IP-Address: $IPv4Address" -PercentComplete $Progress_Percent
                             
            # Create new job
            $Job = [System.Management.Automation.PowerShell]::Create().AddScript($ScriptBlock).AddParameters($ScriptParams)
            $Job.RunspacePool = $RunspacePool
            
            $JobObj = [pscustomobject] @{
                RunNum = $i - $StartIPv4Address_Int64
                Pipe   = $Job
                Result = $Job.BeginInvoke()
            }
    
            # Add job to collection
            [void]$Jobs.Add($JobObj)
        }
    
        Write-Verbose -Message "Waiting for jobs to complete & starting to process results..."
    
        # Total jobs to calculate percent complete, because jobs are removed after they are processed
        $Jobs_Total = $Jobs.Count
    
        # Process results, while waiting for other jobs
        Do {
            # Get all jobs, which are completed
            $Jobs_ToProcess = $Jobs | Where-Object -FilterScript { $_.Result.IsCompleted }
      
            # If no jobs finished yet, wait 500 ms and try again
            if ($null -eq $Jobs_ToProcess) {
                Write-Verbose -Message "No jobs completed, wait 250ms..."
    
                Start-Sleep -Milliseconds 250
                continue
            }
            
            # Get jobs, which are not complete yet
            $Jobs_Remaining = ($Jobs | Where-Object -FilterScript { $_.Result.IsCompleted -eq $false }).Count
    
            # Catch when trying to divide through zero
            try {            
                $Progress_Percent = 100 - (($Jobs_Remaining / $Jobs_Total) * 100) 
            }
            catch {
                $Progress_Percent = 100
            }
    
            Write-Progress -Activity "Waiting for jobs to complete... ($($Threads - $($RunspacePool.GetAvailableRunspaces())) of $Threads threads running)" -Id 1 -PercentComplete $Progress_Percent -Status "$Jobs_Remaining remaining..."
          
            Write-Verbose -Message "Processing $(if($null -eq $Jobs_ToProcess.Count){"1"}else{$Jobs_ToProcess.Count}) job(s)..."
    
            # Processing completed jobs
            foreach ($Job in $Jobs_ToProcess) {       
                # Get the result...     
                $Job_Result = $Job.Pipe.EndInvoke($Job.Result)
                $Job.Pipe.Dispose()
    
                # Remove job from collection
                $Jobs.Remove($Job)
               
                # Check if result contains status
                if ($Job_Result.Status) {        
                    if ($AssignVendorToMAC) {           
                        $Vendor = [String]::Empty
    
                        # Check if MAC is null or empty
                        if (-not([String]::IsNullOrEmpty($Job_Result.MAC))) {
                            # Split it, so we can search the vendor (XX-XX-XX-XX-XX-XX to XXXXXX)
                            $MAC_VendorSearch = $Job_Result.MAC.Replace("-", "").Substring(0, 6)
                                    
                            $Vendor = $OUIHashTable.Get_Item($MAC_VendorSearch)
                        }
    
                        [pscustomobject] @{
                            IPv4Address  = $Job_Result.IPv4Address
                            Status       = $Job_Result.Status
                            Hostname     = $Job_Result.Hostname
                            MAC          = $Job_Result.MAC
                            Vendor       = $Vendor  
                            BufferSize   = $Job_Result.BufferSize
                            ResponseTime = $Job_Result.ResponseTime
                            TTL          = $ResuJob_Resultlt.TTL
                        } | Select-Object -Property $PropertiesToDisplay
                    }
                    else {
                        $Job_Result | Select-Object -Property $PropertiesToDisplay
                    }                            
                }
            } 
    
        } While ($Jobs.Count -gt 0)
    
        Write-Verbose -Message "Closing RunspacePool and free resources..."
    
        # Close the RunspacePool and free resources
        $RunspacePool.Close()
        $RunspacePool.Dispose()
    
        Write-Verbose -Message "Script finished at $(Get-Date)"
    }
    
    End {
        
    }
    }
    #endregion

#region Function Update-OUIList
function Update-OUIList {
    # Define the output path
    $outputPath = 'C:\Revention\Utilities\oui.txt'

    # Ensure the directory exists
    $directory = [System.IO.Path]::GetDirectoryName($outputPath)
    if (-Not (Test-Path $directory)) {
        New-Item -ItemType Directory -Path $directory
    }

    # Fetch the latest OUI list
	$LatestOUIs = (Invoke-WebRequest -Uri 'https://standards-oui.ieee.org/oui/oui.txt' -UseBasicParsing).Content

    # Create StreamWriter for output file
    $streamWriter = New-Object System.IO.StreamWriter($outputPath)

    try {
        # Parse and format the content
        foreach ($Line in $LatestOUIs -split '[\r\n]') {
            if ($Line -match '^[A-F0-9]{6}') {
                $formattedLine = ($Line -replace '\s+', ' ').Replace(' (base 16) ', '|').Trim()
                $streamWriter.WriteLine($formattedLine)
            }
        }
    }
    finally {
        # Close StreamWriter
        $streamWriter.Close()
    }
}
#endregion	

#region Get-FileVersion
function Get-FileVersion {
    param (
        [string]$FilePath
    )

    try {
        $fileItem = Get-Item -LiteralPath $FilePath -ErrorAction Stop
        return $fileItem.LastWriteTime.ToString('yMMdd').Substring(1)
    }
    catch [System.UnauthorizedAccessException] {
        # Use specific credentials to map the network drive
        $netPath = [System.IO.Path]::GetDirectoryName($FilePath)
        net use $netPath /user:Revention Revpass12! 2>&1 | Out-Null
        try {
            $fileItem = Get-Item -LiteralPath $FilePath -ErrorAction Stop
            return $fileItem.LastWriteTime.ToString('yMMdd').Substring(1)
        }
        catch {
            return "Failed even with specific credentials: $_"
        }
        # Remove the network drive mapping
        net use $netPath /delete 2>&1 | Out-Null
    }
    catch [System.IO.FileNotFoundException], [System.Management.Automation.ItemNotFoundException] {
        return 'N/A'
    }
    catch {
        return "An unexpected error occurred: $_"
    }
}
#endregion

#region Get-FileVersions
function Get-FileVersionsStatus {
	param (
		$ComputerName,
		$FileList
	)
    
	foreach ($file in $FileList) {
		$filePath = "Revention\$($file.FileName)"
		$localVersion = Get-FileVersion -FilePath "\\Revent1\$filePath"
		$remoteVersion = Get-RemoteFileVersion -ComputerName $ComputerName -FilePath $filePath
		$label = $file.Label
        
		if ($remoteVersion -eq $localVersion) {
			Update-StatusLabel -Label $label -StatusText $remoteVersion -Color 'green'
		} else {
			Update-StatusLabel -Label $label -StatusText $remoteVersion -Color 'red'
		}
	}
}

#endregion

#region Update-StatusLabel
function Update-StatusLabel {
	param (
		$Label,
		$StatusText,
		$Color
	)
    
	$Label.Text = $StatusText
	$Label.ForeColor = $Color
}

#endregion

#region Test-paths
function Test-Paths {
    param (
        [string[]]$Paths
    )
    
    $TestdPaths = New-Object 'System.Collections.Generic.List[System.String]'
    foreach ($path in $Paths) {
        if (Test-Path $path) {
            $TestdPaths.Add($path)
        }
    }
    
    return $TestdPaths.ToArray()
}
#endregion

#region Update-BackupPaths
function Update-BackupPaths {
	# Test each path
	$paths = Test-Paths -Paths @(
		'C:\Revention\Backup',
		'E:\',
		'D:\',
		'\\REVENT2\Revention\Backup',
		'\\REVENT3\Revention\Backup',
		'\\REVENT4\Revention\Backup',
		'R:\Backup',
		'C:\Revention\New'
	)
    
	# SQL Server connection parameters
	$SqlServerInstance = 'Revent1\REVENTION'
	$DatabaseName = 'REVENTION'

	$credential = Get-Credential -UserName 'Revention' -Message 'Enter the password for the SQL Server connection.'
    
	# Connect to SQL Server
	$connection = Connect-ToSQLServer -SqlServerInstance $SqlServerInstance -DatabaseName $DatabaseName -Username $credential.UserName -SecurePassword $credential.Password
    
	try {
		# Update and retrieve the paths in one go
		$query = @"
        UPDATE BackupSched
        SET Path1 = '$($paths[0])', Path2 = '$($paths[1])', Path3 = '$($paths[2])'
        WHERE BackupSchedKey = 1;

        SELECT Path1, Path2, Path3 FROM BackupSched WHERE BackupSchedKey = 1;
"@
		$command = $connection.CreateCommand()
		$command.CommandText = $query
		$reader = $command.ExecuteReader()

		$table = New-Object System.Data.DataTable
		$table.Load($reader)
		$reader.Close()

		$output = $table | Format-Table | Out-String
		Add-RichTextBox "Paths are validated and updated in the database: $output"
	} catch {
		Add-RichTextBox 'An error occurred.'
	} finally {
		$connection.Close()
	}
}
#endregion

#region Get-RemoteFileVersion
function Get-RemoteFileVersion {
	param (
		[string]$ComputerName,
		[string]$FilePath
	)
		
	if ($ComputerName -ne $env:COMPUTERNAME) {
		$FilePath = "\\$ComputerName\$FilePath"
	} else {
		$FilePath = "C:\$FilePath"
	}
		
	if (Test-Path $FilePath -ErrorAction SilentlyContinue) {
		return (Get-FileVersion -FilePath $FilePath)
	} else {
		return 'FAIL'
	}
}
#endregion

#Region New-PrintersOnRemoteComputer
function New-PrintersOnRemoteComputer {
	param (
		[string]$ComputerName,
		[int]$NPrinters
	)
	
	# Loop through number of printers
	for ($i = 1; $i -le $NPrinters; $i++) {
		$printerName = "Printer$i"
		$IP = 210 + $i
		$printerExists = Get-WmiObject -Query "SELECT * FROM Win32_Printer WHERE Name = '$printerName'"
		
		# Check if printer already exists
		if ($null -eq $printerExists) {
			Add-RichTextBox "Creating $printerName"
			cscript C:\Windows\System32\Printing_Admin_Scripts\en-US\prnport.vbs -a -r "IP_192.168.192.$IP" -h "192.168.192.$IP" -o raw
			& rundll32 printui.dll, PrintUIEntry /if /b "$printerName" /f "$env:windir\inf\prnge001.inf" /r "IP_192.168.192.$IP" /m 'Generic / Text Only'
		} else {
			Add-RichTextBox "$printerName already exists. Skipping..."
		}
	}
}
#endregion

#Region New-StationPrinterComputer

# Function to create a station printer
function New-StationPrinterComputer {
	param (
		[string] $ComputerName,
		[int] $StationNumber
	)

	$printerName = "Station$StationNumber"
	$driverName = 'Generic / Text Only'
	$portName = 'COM2:'

	# Ensure that the port exists
	if (-Not (Get-PrinterPort -Name $portName)) {
		Add-PrinterPort -Name $portName -PrinterHostAddress $portName
	}

	# Create the printer
	Add-Printer -Name $printerName -DriverName $driverName -PortName $portName
}
	
#region Show-MsgBox
	 
function Show-MsgBox { 
	 
	[CmdletBinding()] 
	param( 
		[Parameter(Position = 0, Mandatory = $true)] [string]$Prompt, 
		[Parameter(Position = 1, Mandatory = $false)] [string]$Title = '', 
		[Parameter(Position = 2, Mandatory = $false)] [ValidateSet('Information', 'Question', 'Critical', 'Exclamation')] [string]$Icon = 'Information', 
		[Parameter(Position = 3, Mandatory = $false)] [ValidateSet('OKOnly', 'OKCancel', 'AbortRetryIgnore', 'YesNoCancel', 'YesNo', 'RetryCancel')] [string]$BoxType = 'OkOnly', 
		[Parameter(Position = 4, Mandatory = $false)] [ValidateSet(1,2,3)] [int]$DefaultButton = 1 
	) 
	[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null 
	switch ($Icon) { 
		'Question' { $vb_icon = [microsoft.visualbasic.msgboxstyle]::Question } 
		'Critical' { $vb_icon = [microsoft.visualbasic.msgboxstyle]::Critical } 
		'Exclamation' { $vb_icon = [microsoft.visualbasic.msgboxstyle]::Exclamation } 
		'Information' { $vb_icon = [microsoft.visualbasic.msgboxstyle]::Information }
 } 
	switch ($BoxType) { 
		'OKOnly' { $vb_box = [microsoft.visualbasic.msgboxstyle]::OKOnly } 
		'OKCancel' { $vb_box = [microsoft.visualbasic.msgboxstyle]::OkCancel } 
		'AbortRetryIgnore' { $vb_box = [microsoft.visualbasic.msgboxstyle]::AbortRetryIgnore } 
		'YesNoCancel' { $vb_box = [microsoft.visualbasic.msgboxstyle]::YesNoCancel } 
		'YesNo' { $vb_box = [microsoft.visualbasic.msgboxstyle]::YesNo } 
		'RetryCancel' { $vb_box = [microsoft.visualbasic.msgboxstyle]::RetryCancel }
 } 
	switch ($Defaultbutton) { 
		1 { $vb_defaultbutton = [microsoft.visualbasic.msgboxstyle]::DefaultButton1 } 
		2 { $vb_defaultbutton = [microsoft.visualbasic.msgboxstyle]::DefaultButton2 } 
		3 { $vb_defaultbutton = [microsoft.visualbasic.msgboxstyle]::DefaultButton3 }
 } 
	$popuptype = $vb_icon -bor $vb_box -bor $vb_defaultbutton 
	$ans = [Microsoft.VisualBasic.Interaction]::MsgBox($prompt,$popuptype,$title) 
	return $ans 
} #end
#endregion

#region Connect-ToSQLServer
function Connect-ToSQLServer {
	param (
		[string]$SqlServerInstance,
		[string]$DatabaseName,
		[string]$Username,
		[securestring]$SecurePassword
	)
		
	# Convert the SecureString to a regular string
	$Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
		[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
	)
		
	# Create the connection string
	$connectionString = "Server=$SqlServerInstance;Database=$DatabaseName;User Id=$Username;Password=$Password;"
	$connection = New-Object System.Data.SqlClient.SqlConnection $connectionString
	$connection.Open()
		
	# Return the connection object
	return $connection
}
#endregion
	
#region Show-InputBox
Function Show-InputBox {
	Param([string]$message = $(Throw 'You must enter a prompt message'),
		[string]$title = 'Input',
		[string]$default
	)     
	[reflection.assembly]::loadwithpartialname('microsoft.visualbasic') | Out-Null
	[microsoft.visualbasic.interaction]::InputBox($message,$title,$default) 
}
#endregion
	
#Database Functions ###################################################

function Connect-ToSQLServer {
	param (
		[string]$SqlServerInstance,
		[string]$DatabaseName,
		[string]$Username,
		[securestring]$SecurePassword
	)
	$Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
		[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
	)
	$connectionString = "Server=$SqlServerInstance;Database=$DatabaseName;User Id=$Username;Password=$Password;"
	$connection = New-Object System.Data.SqlClient.SqlConnection $connectionString
	$connection.Open()
	return $connection
}

function Get-CommonSqlConnection {
    $SqlServerInstance = 'Revent1\REVENTION'
    $DatabaseName = 'REVENTION'
    
    $credential = Get-Credential -UserName 'Revention' -Message 'Enter the password for the SQL Server connection.'

    return Connect-ToSQLServer -SqlServerInstance $SqlServerInstance -DatabaseName $DatabaseName -Username $credential.UserName -SecurePassword $credential.Password
}

function Invoke-SqlQuery {
    param (
        $connection,
        [string]$query
    )
    $command = $connection.CreateCommand()
    $command.CommandText = $query
    $reader = $command.ExecuteReader()
    $table = New-Object System.Data.DataTable
    $table.Load($reader)
    $reader.Close()

    # Check if this is the OrdStageEvent query
    if ($query -match 'OrdStageEvent') {
        return $table | Select-Object Stage, Event, EnterExit, Ordtype, Direction, PrinterName, SyncStatus | 
                Format-Table -AutoSize | Out-String -Width $richtextbox_output.Width
    }
    # Check if this is the CCBatches query
    elseif ($query -match 'CCBatches') {
        return $table | Select-Object CCBatchKey, BizDate, CloseTime, 
                @{Name='IsOpen'; Expression={if ($_.IsOpen) {'Closed'} else {'Open'}}} | 
                Format-Table -AutoSize | Out-String -Width $richtextbox_output.Width
    }
    else {
        return $table | Format-Table -AutoSize | Out-String -Width $richtextbox_output.Width
    }
}

function Invoke-SQLButtonClick {
	param (
		[string]$logText,
		[string[]]$queries,
		[string[]]$sectionHeaders = @(),
		[switch]$enableButton,
		[string]$buttonName
	)

	Add-Logs -text $logText

	# Initialize StringBuilder for efficient string concatenation
	$outputBuilder = New-Object System.Text.StringBuilder
	$separatorBuilder = New-Object System.Text.StringBuilder

	# Get common SQL connection
	$connection = Get-CommonSqlConnection

	try {
		$sectionIndex = 0

		foreach ($query in $queries) {
			# Append section headers if available
			if ($sectionHeaders -and $sectionHeaders[$sectionIndex]) {
				[void]$outputBuilder.AppendLine("`n" + $sectionHeaders[$sectionIndex] + "`n")
			}

			# Execute SQL query and append the result
			$queryResult = Invoke-SqlQuery -connection $connection -query $query
			[void]$outputBuilder.AppendLine($queryResult)

			$sectionIndex++
		}
	} finally {
		# Close the SQL connection
		$connection.Close()
	}

	# Convert StringBuilder to string
	$output = $outputBuilder.ToString()
	$separator = $separatorBuilder.Append("`n# # # # # # # # # #`n").ToString()

	# Use the Text property of the RichTextBox to set the new text
	$richtextbox_output.Text = $richtextbox_output.Text + $separator + $output

	# Enable the button if specified
	if ($enableButton) {
		Set-Variable -Name $buttonName -Value $true -Scope Script
	}
}

#Database Functions ###################################################



#endregion FUNCTIONS

#region Get-MainForm_pff
function Get-MainForm_pff {

	#----------------------------------------------
	#region Generated Form Objects
	#----------------------------------------------
	[System.Windows.Forms.Application]::EnableVisualStyles()
	$form_MainForm = New-Object 'System.Windows.Forms.Form'
	$richtextbox_output = New-Object 'System.Windows.Forms.RichTextBox'
	$panel_RTBButtons = New-Object 'System.Windows.Forms.Panel'
	$button_formExit = New-Object 'System.Windows.Forms.Button'
	$button_outputClear = New-Object 'System.Windows.Forms.Button'
	$button_ExportRTF = New-Object 'System.Windows.Forms.Button'
	$button_outputCopy = New-Object 'System.Windows.Forms.Button'

	$tabcontrol_computer = New-Object 'System.Windows.Forms.TabControl'

	#region MAIN HEADER	 ################################################
	$groupbox_ComputerName = New-Object 'System.Windows.Forms.GroupBox'
	
	$textbox_computername = New-Object 'System.Windows.Forms.TextBox'
	$button_Check = New-Object 'System.Windows.Forms.Button'

	$label_PingStatus = New-Object 'System.Windows.Forms.Label'
	$label_Ping = New-Object 'System.Windows.Forms.Label'

	$label_POSStatus = New-Object 'System.Windows.Forms.Label'
	$label_POS = New-Object 'System.Windows.Forms.Label'

	$label_RevControlStatus = New-Object 'System.Windows.Forms.Label'
	$label_RevControl = New-Object 'System.Windows.Forms.Label'

	$label_RevcloudStatus = New-Object 'System.Windows.Forms.Label'
	$label_Revcloud = New-Object 'System.Windows.Forms.Label'

	$label_RevMonStatus = New-Object 'System.Windows.Forms.Label'
	$label_RevMon = New-Object 'System.Windows.Forms.Label'

	$label_RevScreenMgrStatus = New-Object 'System.Windows.Forms.Label'
	$label_RevScreenMgr = New-Object 'System.Windows.Forms.Label'


	$label_HRUpdateStatus = New-Object 'System.Windows.Forms.Label'
	$label_HRUpdate = New-Object 'System.Windows.Forms.Label'

	

	#endregion MAIN HEADER	 ################################################

	#region General TAB
	#General Tab ##########################################
	$tabpage_general = New-Object 'System.Windows.Forms.TabPage'

	$button_IPScanner = New-Object 'System.Windows.Forms.Button'
	$button_VNC = New-Object 'System.Windows.Forms.Button'
	$buttonC = New-Object 'System.Windows.Forms.Button'
	$button_networkconfig = New-Object 'System.Windows.Forms.Button'
	$button_Restart = New-Object 'System.Windows.Forms.Button'
	$button_Shutdown = New-Object 'System.Windows.Forms.Button'


	#endregion General TAB #############################################
	
	#region Database TAB ###################################################
	$tabpage_Database = New-Object 'System.Windows.Forms.TabPage'

	#DataBase> 
	$groupbox_POSSettings = New-Object 'System.Windows.Forms.GroupBox'
	$button_BusinessInfo = New-Object 'System.Windows.Forms.Button'
	$button_DbPrinters = New-Object 'System.Windows.Forms.Button'
	$button_DBStages = New-Object 'System.Windows.Forms.Button'

        
	$groupbox_POSAudit = New-Object 'System.Windows.Forms.GroupBox'
	$button_OrderHistory = New-Object 'System.Windows.Forms.Button'
	$button_CCBatch = New-Object 'System.Windows.Forms.Button'
	$button_SyncRecords = New-Object 'System.Windows.Forms.Button'
	$button_TotalSyncRecords = New-Object 'System.Windows.Forms.Button'

	#endregion Database TAB	 ################################################

	#region Services TAB ###################################################
	$tabpage_Services = New-Object 'System.Windows.Forms.TabPage'

	$button_mmcServices = New-Object 'System.Windows.Forms.Button'
	$button_HRServices = New-Object 'System.Windows.Forms.Button'
	$button_servicesAutoNotStarted = New-Object 'System.Windows.Forms.Button'


	$groupbox_RevCtrl = New-Object 'System.Windows.Forms.GroupBox'
	$button_RevControlSvcRestart = New-Object 'System.Windows.Forms.Button'
	$button_RevControlSvcStart = New-Object 'System.Windows.Forms.Button'
	$button_RevControlSvcStop = New-Object 'System.Windows.Forms.Button'
	$groupbox_RevCloud = New-Object 'System.Windows.Forms.GroupBox'
	$button_RevCloudSvcRestart = New-Object 'System.Windows.Forms.Button'
	$button_RevCloudSvcStart = New-Object 'System.Windows.Forms.Button'
	$button_RevCloudSvcStop = New-Object 'System.Windows.Forms.Button'   
	$groupbox_RevPrinterServer = New-Object 'System.Windows.Forms.GroupBox'
	$button_RevPrinterServerSvcRestart = New-Object 'System.Windows.Forms.Button'
	$button_RevPrinterServerSvcStart = New-Object 'System.Windows.Forms.Button'
	$button_RevPrinterServerSvcStop = New-Object 'System.Windows.Forms.Button'
	$groupbox_PrinterSpooler = New-Object 'System.Windows.Forms.GroupBox'
	$button_PrinterSpoolerSvcRestart = New-Object 'System.Windows.Forms.Button'
	$button_PrinterSpoolerSvcStart = New-Object 'System.Windows.Forms.Button'
	$button_PrinterSpoolerSvcStop = New-Object 'System.Windows.Forms.Button'
    



	#Services>


	#endregion Services TAB	 ################################################

	
	#region MAIN MENU ################################################
	#AdminArsenal MENU
	$ToolStripMenuItem_AdminArsenal = New-Object 'System.Windows.Forms.ToolStripMenuItem'

	$ToolStripMenuItem_PrintersControl = New-Object 'System.Windows.Forms.ToolStripMenuItem'
	$toolstripseparator4 = New-Object 'System.Windows.Forms.ToolStripSeparator'

	$ToolStripMenuItem_CommandPrompt = New-Object 'System.Windows.Forms.ToolStripMenuItem'
	$ToolStripMenuItem_Powershell = New-Object 'System.Windows.Forms.ToolStripMenuItem'
	$toolstripseparator5 = New-Object 'System.Windows.Forms.ToolStripSeparator'

	$ToolStripMenuItem_SSMS = New-Object 'System.Windows.Forms.ToolStripMenuItem'
	$ToolStripMenuItem_Notepad = New-Object 'System.Windows.Forms.ToolStripMenuItem'
	$ToolStripMenuItem_shutdownGui = New-Object 'System.Windows.Forms.ToolStripMenuItem'

	#LocalHost MENU
	$ToolStripMenuItem_localhost = New-Object 'System.Windows.Forms.ToolStripMenuItem'

	$ToolStripMenuItem_netstatsListening = New-Object 'System.Windows.Forms.ToolStripMenuItem'
	$toolstripseparator1 = New-Object 'System.Windows.Forms.ToolStripSeparator'

	$ToolStripMenuItem_compmgmt = New-Object 'System.Windows.Forms.ToolStripMenuItem'
	$ToolStripMenuItem_services = New-Object 'System.Windows.Forms.ToolStripMenuItem'
	$toolstripseparator3 = New-Object 'System.Windows.Forms.ToolStripSeparator'

	$ToolStripMenuItem_systemproperties = New-Object 'System.Windows.Forms.ToolStripMenuItem'
	$ToolStripMenuItem_devicemanager = New-Object 'System.Windows.Forms.ToolStripMenuItem'
	$ToolStripMenuItem_taskManager = New-Object 'System.Windows.Forms.ToolStripMenuItem'

	#DROPDOWN MENU ------ Other Windows Apps
	$ToolStripMenuItem_otherLocalTools = New-Object 'System.Windows.Forms.ToolStripMenuItem'

	$ToolStripMenuItem_addRemovePrograms = New-Object 'System.Windows.Forms.ToolStripMenuItem'
	$ToolStripMenuItem_diskManagement = New-Object 'System.Windows.Forms.ToolStripMenuItem'
	$ToolStripMenuItem_networkConnections = New-Object 'System.Windows.Forms.ToolStripMenuItem'
	$ToolStripMenuItem_scheduledTasks = New-Object 'System.Windows.Forms.ToolStripMenuItem'
	
	#Scripts MENU
	$ToolStripMenuItem_scripts = New-Object 'System.Windows.Forms.ToolStripMenuItem'

	$ToolStripMenuItem_SET_Backup_Path = New-Object 'System.Windows.Forms.ToolStripMenuItem'
	$ToolStripMenuItem_SET_Allow_Batch = New-Object 'System.Windows.Forms.ToolStripMenuItem'
	$ToolStripMenuItem_SET_HungerRush_ShortCuts = New-Object 'System.Windows.Forms.ToolStripMenuItem'
	$ToolStripMenuItem_SET_Allow_Close_Day = New-Object 'System.Windows.Forms.ToolStripMenuItem'

	#DROPDOWN MENU ------ Printers
	$ToolStripMenuItem_Printers = New-Object 'System.Windows.Forms.ToolStripMenuItem'

	$ToolStripMenuItem_CREATE_Kitchen_Printers = New-Object 'System.Windows.Forms.ToolStripMenuItem'
	$ToolStripMenuItem_REMOVE_ALL_Printers = New-Object 'System.Windows.Forms.ToolStripMenuItem'
	$ToolStripMenuItem_CREATE_Station_Printer = New-Object 'System.Windows.Forms.ToolStripMenuItem'
	$ToolStripMenuItem_Test_All_Local_Printers = New-Object 'System.Windows.Forms.ToolStripMenuItem'

	#endregion MAIN MENU ################################################

	$richtextbox_Logs = New-Object 'System.Windows.Forms.RichTextBox'
	$statusbar1 = New-Object 'System.Windows.Forms.StatusBar'
	$menustrip_principal = New-Object 'System.Windows.Forms.MenuStrip'
	$errorprovider1 = New-Object 'System.Windows.Forms.ErrorProvider'
	$tooltipinfo = New-Object 'System.Windows.Forms.ToolTip'
	$imagelistAnimation = New-Object 'System.Windows.Forms.ImageList'
	$timerCheckJob = New-Object 'System.Windows.Forms.Timer'
	#endregion Generated Form Objects
	
	
	######### CONFIGURATION #########
	#region Info
	# HungerRush InstallXpert information
	$ApplicationName = 'HungerRush InstallXpert'
	$ApplicationVersion = '0.1'
	$ApplicationLastUpdate	= '09/27/2023'
	
	# Author Information
	$AuthorName = 'Kyle Ramsy'
	$AuthorEmail = 'Kyle.Ramsy@hungerrush.com'
	
	# Text to show in the Status Bar when the form load
	$StatusBarStartUp	= "$AuthorName - $AuthorEmail"
	
	# Title of the MainForm
	$domain = $env:userdomain.ToUpper()
	$MainFormTitle = "$ApplicationName $ApplicationVersion - Last Update: $ApplicationLastUpdate - $domain\$env:username"
	
	# Default Error Action
	$ErrorActionPreference = 'SilentlyContinue'
	
	# RichTextBox OUTPUT form
	
	# RichTextBox LOGS form
	#  Message to show when the form load
	$RichTexBoxLogsDefaultMessage = "Welcome on $ApplicationName $LAKVersion"
	#endregion
	
	###############
	$OnLoadFormEvent = {
		# Set the status bar name
		$statusbar1.Text = $StatusBarStartUp
		
		
		$form_MainForm.Text = $MainFormTitle
		$textbox_computername.Text = $env:COMPUTERNAME
		Add-Logs -text $RichTexBoxLogsDefaultMessage
	
	}
		
	# TIMERS
	
	$timerCheckJob_Tick2 = {
		#Check if the process stopped
		if ($null -ne $timerCheckJob.Tag) {		
			if ($timerCheckJob.Tag.State -ne 'Running') {
				#Stop the Timer
				$buttonStart.ImageIndex = -1
				$buttonStart.Enabled = $true	
				$buttonStart.Visible = $true
				$timerCheckJob.Tag = $null
				$timerCheckJob.Stop()
			} else {
				if ($buttonStart.ImageIndex -lt $buttonStart.ImageList.Images.Count - 1) {
					$buttonStart.ImageIndex += 1
				} else {
					$buttonStart.ImageIndex = 0		
				}
			}
		}
	}

	#region MAIN HEADER Event Handlers	 ################################################	
	$button_Check_Click = {
		$button_Check.Enabled = $false
	
		Get-ComputerTxtBox
		Add-logs -text "$ComputerName - Check Connectivity and Basic Properties"
	
		$fileInfoList = @(
			@{ FileName = 'RevControlSvc.exe'; Label = $label_RevControlStatus },
			@{ FileName = 'RevCloudSvc\RevCloudSvc.exe'; Label = $label_RevCloudStatus },
			@{ FileName = 'HungerRushUpdater.exe'; Label = $label_HRUpdateStatus },
			@{ FileName = 'RevScreenMgr.exe'; Label = $label_RevScreenMgrStatus },
			@{ FileName = 'RevMon\RevMonitorSvc.exe'; Label = $label_RevMonStatus },
			@{ FileName = 'ReventionPOS.exe'; Label = $label_POSStatus }
		)
	
		if (Test-Connection $ComputerName -Count 1 -Quiet) {
			Update-StatusLabel -Label $label_PingStatus -StatusText 'OK' -Color 'green'
			Get-FileVersionsStatus -ComputerName $ComputerName -FileList $fileInfoList
		} else {
			# Try using PsExec from the local machine's System32 folder as a fallback method
			try {
				$result = & 'C:\Windows\System32\PsExec.exe' \\$ComputerName -s cmd /c echo "Connected"
				if ($result -match "Connected") {
					Update-StatusLabel -Label $label_PingStatus -StatusText 'OK (PsExec)' -Color 'green'
					Get-FileVersionsStatus -ComputerName $ComputerName -FileList $fileInfoList
				} else {
					throw
				}
			} catch {
				Update-StatusLabel -Label $label_PingStatus -StatusText 'FAIL' -Color 'red'
			
				foreach ($file in $fileInfoList) {
					Update-StatusLabel -Label $file.Label -StatusText 'FAIL' -Color 'red'
				}
			}
		}
	
		$button_Check.Enabled = $true
	}
		#region MAIN HEADER	 ################################################

	#region MAIN MENU Event Handlers  ################################################
	#AdminArsenal MENU
	$ToolStripMenuItem_PrintersControl_Click = { control.exe /name Microsoft.DevicesAndPrinters }
	
	$ToolStripMenuItem_CommandPrompt_Click = { Start-Process cmd.exe }

	$ToolStripMenuItem_Powershell_Click = { Start-Process powershell.exe -Verb runas }
	
	$ToolStripMenuItem_shutdownGui_Click = { Start-Process shutdown.exe -ArgumentList /i }
	$ToolStripMenuItem_SSMS_Click = { Start-Process 'ssms.exe' -ArgumentList '-NoSplash' }
	$ToolStripMenuItem_Notepad_Click = { Start-Process notepad.exe }

	#LocalHost MENU
	$ToolStripMenuItem_netstatsListening_Click = {
		$this.Enabled = $False
		Add-logs -text "$env:ComputerName - Netstat"
		$resultNetstat = Get-NetStat | Format-Table -AutoSize | Out-String
		Add-RichTextBox $resultNetstat
	}

	$ToolStripMenuItem_compmgmt_Click = { compmgmt.msc }
	
	$ToolStripMenuItem_services_Click = { services.msc }

	$ToolStripMenuItem_systemproperties_Click = { Start-Process 'sysdm.cpl' }

	$ToolStripMenuItem_devicemanager_Click = { Start-Process 'devmgmt.msc' }

	$ToolStripMenuItem_taskManager_Click = { Taskmgr }


	#DROPDOWN MENU ------ Other Windows Apps
	$ToolStripMenuItem_addRemovePrograms_Click = { Start-Process appwiz.cpl;Add-logs -text 'Localhost - Add/Remove Programs (appwiz.cpl)' }
	
	$ToolStripMenuItem_diskManagement_Click = { Start-Process 'diskmgmt.msc' }
	
	$ToolStripMenuItem_networkConnections_Click = { Start-Process 'ncpa.cpl' }

	$ToolStripMenuItem_scheduledTasks_Click = { Start-Process (control schedtasks) }


	#region Scripts MENU Event Handlers  ############################################
	$ToolStripMenuItem_SET_Backup_Path_Click = {    
		Add-logs -text 'Database - Set New Backup Paths'
		# Get computer name
		$computerName = (Get-ComputerInfo).CsName
		if ($computerName -eq 'Revent1') {
			Update-BackupPaths
		} else {
			Add-RichTextBox "Script only runs on 'Revent1'"
		}
	}
	
	$ToolStripMenuItem_CREATE_Kitchen_Printers_Click = {
		# Get the computer name from the text box
		$ComputerName = Get-ComputerTxtBox
		
		# Ask the user for the number of printers to create
		$NPrinters = Show-Inputbox -message 'How many kitchen printers do you need to be set up in Windows? (Note this will not assign IP to actual printers.)' -title 'Create Kitchen Printers' -default ''
		
		# Check if the input is a valid number
		if ($NPrinters -match '^\d+$') {
			# Convert the input to an integer
			$NPrinters = [int]$NPrinters
			
			# Check if the number of printers is greater than zero
			if ($NPrinters -gt 0) {
				# Create the printers on the remote computer
				New-PrintersOnRemoteComputer -ComputerName $ComputerName -NPrinters $NPrinters
				
				# Display all printers in a table format
				$result = Get-WmiObject -Query 'SELECT * FROM Win32_Printer' -ComputerName $ComputerName | Format-Table Name, DriverName, PortName -AutoSize | Out-String
				if ($null -ne $result ) {
					# Add the result to a RichTextBox or display it using Add-RichTextBox		}
					# Assuming the function Add-RichTextBox exists
					Add-RichTextBox $result
				}
				
				# Log the action if necessary
				Add-logs -text "Printers: Created $NPrinters kitchen printers."
			} else {
				Add-RichTextBox 'Invalid input. Please enter a positive number.'
			}
		} else {
			Add-RichTextBox 'Invalid input. Please enter a valid number.'
		}
	}

	$ToolStripMenuItem_REMOVE_ALL_Printers_Click = {
		# Get the computer name from the text box
		$ComputerName = Get-ComputerTxtBox

		# Get list of all installed printers
		$printers = Get-WmiObject -Query 'Select * From Win32_Printer'

		# Check if there are printers to remove
		if ($printers.Count -gt 0) {
			# Loop through each printer and remove it
			foreach ($printer in $printers) {
				Write-Output "Removing printer: $($printer.Name)"
				Remove-Printer -Name $printer.Name
		
				# Add message to RichTextBox
				Add-RichTextBox ('Deleted ' + $printer.Name + "`r`n" + ('#' * 19))
			}		
			# Display all printers in a table format after removal
			$result = Get-WmiObject -Query 'SELECT * FROM Win32_Printer' -ComputerName $ComputerName | Format-Table Name, DriverName, PortName -AutoSize | Out-String
			if ($null -ne $result) {
				# Add the result to a RichTextBox (replace with the actual function if needed)
				Add-RichTextBox $result
			}

			# Log the action
			Add-logs -text "Printers: Removed ALL printers from $ComputerName."
		} else {
			Add-RichTextBox 'No printers found to remove.'
		}
	}

	$ToolStripMenuItem_CREATE_Station_Printer_Click = {
		# Get the computer name from the text box
		$ComputerName = Get-ComputerTxtBox
	
		# Ask the user for the station number
		$StationNumber = Show-Inputbox -message 'Enter the station number for the printer you want to set up in Windows.' -title 'Create Station Printer' -default ''
	
		# Check if the input is a valid number
		if ($StationNumber -match '^\d+$') {
			# Convert the input to an integer
			$StationNumber = [int]$StationNumber
	
			# Call the function to create the printer on the remote computer
			New-StationPrinterComputer -ComputerName $ComputerName -StationNumber $StationNumber
			Add-logs -text "Printers: Station Printer Created."
		} else {
			Add-RichTextBox 'Invalid input. Please enter a valid station number.'
		}	}

$ToolStripMenuItem_SET_Allow_Batch_Click = {
	# Log text
	$logText = "Database: SET Allow Batch on Station 1 Only"
		
	# SQL queries
	$queries = @(
	"UPDATE ComputerCCOpts SET AllowBatch = 'False' WHERE ComputerName <> 'Station1';",
	@"
	SELECT Computer.ComputerName, Computer.IPAddr, Computer.osComputerName, Computer.AllowCloseDay, ComputerCCOpts.AllowBatch
	FROM Computer
	INNER JOIN ComputerCCOpts ON Computer.ComputerName = ComputerCCOpts.ComputerName
"@)
		
	# Add logs
	Add-Logs -text $logText
	
	# Initialize StringBuilder for output and separator
	$outputBuilder = New-Object System.Text.StringBuilder
	$separatorBuilder = New-Object System.Text.StringBuilder
		
	# Get common SQL connection
	$connection = Get-CommonSqlConnection
		
	try {
	# Loop through each query
	foreach ($query in $queries) {
	# Execute SQL query and get the result
	$queryResult = Invoke-SqlQuery -connection $connection -query $query
	[void]$outputBuilder.AppendLine($queryResult)
	}
	} finally {
	# Close the SQL connection
	$connection.Close()
	}
		
	# Convert StringBuilder to string for output and separator
	$output = $outputBuilder.ToString()
	$separator = $separatorBuilder.Append("`n# # # # # # # # # #`n").ToString()
		
	# Append the new text to the RichTextBox
	$richtextbox_output.Text = $richtextbox_output.Text + $separator + $output
	}

$ToolStripMenuItem_SET_HungerRush_ShortCuts_Click = {    
		Add-logs -text 'Dasktop ShortCuts - Created HR shortcuts for all profiles'
    # Bypass Execution Policy
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

    # Add legacy shortcuts
    Write-Host
    Write-host "Adding Legacy Shortcuts"-ForegroundColor Cyan

    $TargetPath = "C:\Revention\ReventionPOS.exe"

    $ShortcutPaths = @(
        "$env:USERPROFILE\Desktop\Revention POS.lnk",
        "C:\Users\Revention\Desktop\Revention POS.lnk",
        "C:\Users\Revention\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Revention POS.lnk"
        "C:\Users\Manager\Desktop\Revention POS.lnk",
        "C:\Users\Owner\Desktop\Revention POS.lnk"

    )

    foreach ($ShortcutPath in $ShortcutPaths) {
        try {
            $WshShell = New-Object -ComObject WScript.Shell -ErrorAction Stop
            $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
            $Shortcut.TargetPath = $TargetPath
            $Shortcut.Save()
            Add-RichTextBox "Shortcut created: $ShortcutPath"
        }
        catch {
            Add-RichTextBox "Failed to create shortcut: $ShortcutPath" -ForegroundColor Yellow
        }
}	
}

$ToolStripMenuItem_Test_All_Local_Printers_Click = {    
	Add-logs -text 'Printers - Test ALL Local Printers '
# Add legacy shortcuts
$printers = Get-WmiObject -Query "Select * From Win32_Printer"

foreach ($printer in $printers) {
$printerName = $printer.Name
Write-Host "Printing test page for printer: $printerName"

try {
	$printer.InvokeMethod("PrintTestPage", $null)
	Add-RichTextbox "Test page sent to printer: $printerName"
} catch {
	Add-RichTextbox "Error printing test page for printer: $printerName"
	Add-RichTextbox $_.Exception.Message
}
}}

$ToolStripMenuItem_SET_Allow_Close_Day_Click = {    
    Add-Logs "Database: SET Allow Close Day on Station 1 Only"

        # Get common SQL connection
    $connection = Get-CommonSqlConnection

    # Open the SQL connection
    $connection.Open()

    try {

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
        # Execute SQL query and get the result
        $queryResult = Invoke-SqlQuery -connection $connection -query $query

        # Initialize StringBuilder for output
        $outputBuilder = New-Object System.Text.StringBuilder
        [void]$outputBuilder.AppendLine($queryResult)

    } finally {
        # Close the SQL connection
        $connection.Close()
    }

    $output = $outputBuilder.ToString()
    $separator = "`n# # # # # # # # # #`n"

    $richtextbox_output.Text = $richtextbox_output.Text + $separator + $output
}


	#endregion ############################################			

	#endregion MAIN MENU ################################################

	#region General TAB Event Handlers ################################################

	#General Tab ####################################################
    $button_IPScanner_Click = {
		Get-ComputerTxtBox
		Add-Logs -text 'IP Scanner'
		$button_IPScanner.Enabled = $False


	    # Ask for Start IP
		$startIP = Show-InputBox -message 'Please enter the Start IP.' -title 'Start IP' -default '192.168.192.1'
		if ($null -eq $startIP) {
			$button_IPScanner.Enabled = $true
			return
		}
	
		# Ask for End IP
		$endIP = Show-InputBox -message 'Please enter the End IP.' -title 'End IP' -default '192.168.192.254'
		if ($null -eq $endIP) {
			$button_IPScanner.Enabled = $true
			return
		}
	
		Add-Logs -text "Start IP: $startIP"
		Add-Logs -text "End IP: $endIP"
		Add-RichTextBox 'Scanning Network...............'
        Update-OUIList

		# Perform IP Scan
		$result = Invoke-IPv4NetworkScan -StartIPv4Address $startIP -EndIPv4Address $endIP -EnableMACResolving | Format-Table -AutoSize | Out-String
	
		Add-RichTextBox "$result`n"
######################
# Ask user for the total number of stations using Input Box
$endRange = Show-InputBox "Enter the total number of stations" "Number of Stations"
$startRange = 1  # Start of the range is always 1

$stationInfoArray = @()

for ($i = $startRange; $i -le $endRange; $i++) {
    $stationName = "Revent$i"
    
    # Display the station name as it's being scanned
    Write-Host "Scanning $stationName..."

    # Resolve IP Address from Station Name
    $ipAddress = ([System.Net.Dns]::GetHostAddresses($stationName) | Where-Object { $_.AddressFamily -eq 'InterNetwork' })[0].IPAddressToString

    $info = [ordered]@{
        "StationName" = $stationName
        "IPAddress" = $ipAddress
    }

    $paths = @(
        "\\$stationName\Revention\ReventionPOS.exe",
        "\\$stationName\Revention\RevControlSvc.exe",
        "\\$stationName\Revention\RevCloudSvc\RevCloudSvc.exe",
        "\\$stationName\Revention\RevUpdate\RUSvc.exe",
        "\\$stationName\Revention\RevMon\RevMonitorSvc.exe",
        "\\$stationName\Revention\RevScreenMgr.exe",
        "\\$stationName\Revention\HrPack.exe",
        "\\$stationName\Revention\HrPackSlim.exe"
    )
    
    foreach ($path in $paths) {
        $keyName = ($path -split '\\')[-1] -replace "\.exe$"
        $file = Get-Item $path -ErrorAction SilentlyContinue
        $info[$keyName] = if ($file) { $file.LastWriteTime.ToString("yMMdd") } else { "N/A" }
    }

    $stationInfoObject = New-Object PSObject -Property $info
    $stationInfoArray += $stationInfoObject
}

$displayResults = $stationInfoArray | Format-Table -Property @{Expression="IPAddress"; Width=16}, @{Expression="StationName"; Width=15}, @{Expression="ReventionPOS"; Width=10}, @{Expression="RevControlSvc"; Width=12}, @{Expression="RevCloudSvc"; Width=11}, @{Expression="RevUpdate"; Width=9}, @{Expression="RevMon"; Width=7}, @{Expression="RevScreenMgr"; Width=13}, @{Expression="HrPack"; Width=7}, @{Expression="HrPackSlim"; Width=10} | Out-String -Width 2000

# Display the results in the RichTextBox (assuming Add-RichTextBox is defined)
Add-RichTextBox "$displayResults`n"

}
	
	$button_networkPing_Click = {
		Get-ComputerTxtBox
		Add-logs -text "$ComputerName - Network - Ping"
		$cmd = 'cmd'
		$param_user = $textbox_pingparam.text
		$param = "/k ping $param_user $computername"
		Start-Process $cmd $param
	}

	$button_VNC_Click = {
		Get-ComputerTxtBox
		Add-Logs -text "$ComputerName - VNC Computer"
		$Confirmation = Show-MsgBox -Prompt "You want to connect to $ComputerName using VNC. Are you sure?" -Title "$ComputerName - VNC Computer" -Icon Exclamation -BoxType YesNo
		if ($Confirmation -eq 'YES') {
			$securePassword = ConvertTo-SecureString 'support' -AsPlainText -Force
			$credential = New-Object System.Management.Automation.PSCredential('revadmin', $securePassword)

			& 'C:\Program Files\uvnc bvba\UltraVNC\vncviewer.exe' -connect $ComputerName -password $credential.GetNetworkCredential().Password
		}
	}

	$button_networkIPConfig_Click = {
		Get-ComputerTxtBox
		Add-logs -text "$ComputerName - Network - Configuration"
		$result = Get-IP -ComputerName $ComputerName | Format-Table Name,IP4,IP4Subnet,DefaultGWY,MacAddress,DNSServer,WinsPrimary,WinsSecondary -AutoSize | Out-String -Width $richtextbox_output.Width
		Add-RichTextBox "$result`n"
	}

	$buttonC_Click = {
		Get-ComputerTxtBox
		Add-Logs -text "$ComputerName - Open Revention Folder"
		$PathToCDrive = "\\$ComputerName\c$\Revention"
		Explorer.exe $PathToCDrive
	}

	$button_Restart_Click = {
		Get-ComputerTxtBox
		Add-Logs -text "$ComputerName - Restart Computer"
		#$result = Restart-Computer -ComputerName $ComputerName -Force -Confirm
		$Confirmation = Show-MsgBox -Prompt "You want to restart $ComputerName, Are you sure ?" -Title "$ComputerName - Restart Computer" -Icon Exclamation -BoxType YesNo
		#$result = (Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName).Reboot()
		if ($Confirmation -eq 'YES') { 
			#(Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName).Reboot()
			Restart-Computer -ComputerName $ComputerName -Force
			Show-MsgBox -Prompt "$ComputerName - Restart Initialized" -Title "$ComputerName - Restart Computer" -Icon Information -BoxType OKOnly
		} else { Show-MsgBox -BoxType 'OKOnly' -Title "$ComputerName - Restart" -Prompt "$ComputerName - Restart Cancelled" -Icon 'Information' }
	}
	
	$button_Shutdown_Click = {
		Get-ComputerTxtBox
		Add-Logs -text "$ComputerName - Shutdown Computer"
		#$result = Stop-Computer -ComputerName $ComputerName -Force -Confirm
		$Confirmation = Show-MsgBox -Prompt "You want to shutdown $ComputerName, Are you sure ?" -Title "$ComputerName - Shutdown Computer" -Icon Exclamation -BoxType YesNo
		if ($Confirmation -eq 'YES') { 
			#(Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName).shutdown()
			Stop-Computer -ComputerName $ComputerName -Force
			Show-MsgBox -Prompt "$ComputerName - Shutdown Initialized" -Title "$ComputerName - Shutdown Computer" -Icon Information -BoxType OKOnly
		} else { Show-MsgBox -BoxType 'OKOnly' -Title "$ComputerName - Shutdown" -Prompt "$ComputerName - Shutdown Cancelled" -Icon 'Information' }
	}
	
	#endregion General TAB #############################################


	#region Database TAB Event Handlers###################################################
    $button_BusinessInfo_Click = {

        $button_BusinessInfo.Enabled = $False   

        # Define common parameters
        $logText = 'Database - Business Info'
        $enableButton = $true
        $buttonName = 'button_BusinessInfo'
    
        # Define the SQL queries
        $queries = @(
            'SELECT AboveStoreID, BusinessName, StoreNum, EmailServer, EmailUser FROM Business',
            'SELECT Computer.ComputerName, Computer.IPAddr, Computer.AllowCloseDay, ComputerCCOpts.AllowBatch, StationType
             FROM Computer
             INNER JOIN ComputerCCOpts ON Computer.ComputerName = ComputerCCOpts.ComputerName',
            'SELECT Path1, Path2, Path3 FROM BackupSched',
            'SELECT TOP 4 BUTime, [Path], ROW_NUMBER() over (order by BUTime desc) as path_rank
             FROM Backuplog
             ORDER BY BUTime desc',
            'SELECT CCBatchKey, BizDate, CloseTime, IsOpen FROM CCBatch'
        )
    
        # Execute the queries and process the results
        Invoke-SQLButtonClick -logText $logText -queries $queries -enableButton:$enableButton -buttonName $buttonName
    
        # Optionally re-enable the button if needed
        $button_BusinessInfo.Enabled = $true
    }
    
    $button_DbPrinters_Click = {

        $button_DbPrinters.Enabled = $false

        # Define common parameters
        $logText = 'Database - Printers'
        $enableButton = $true
        $buttonName = 'button_DbPrinters'
    
        # Define the SQL queries
        $queries = @(
            'SELECT * FROM dbo.printer ORDER BY ComputerName ASC, PrinterName ASC;',
            'SELECT * FROM dbo.PrinterKtn ORDER BY PrinterName ASC;',
            'SELECT COUNT(PrintJobKey) as Print_Jobs_Pending From dbo.PrintJobs;',
            'SELECT ComputerName, PrtDel, PrtExp, Prtlbl, PrtMap, PrtOth, PrtRpt FROM dbo.Computer'
        )
        $sectionHeaders = @('Station Printers:', 'Kitchen Printers:')
    
        # Execute the queries and process the results
        Invoke-SQLButtonClick -logText $logText -queries $queries -sectionHeaders $sectionHeaders -enableButton:$enableButton -buttonName $buttonName

        $button_DbPrinters.Enabled = $True
    }
    
    $button_DBStages_Click = {

        $button_DBStages.Enabled = $false

        # Define common parameters
        $logText = 'Database - Stages'
        $enableButton = $true
        $buttonName = 'button_DBStages'
    
        # Define the SQL queries
        $queries = @(
            "SELECT Stage, Event, 
            CASE 
                WHEN EnterExit IS NULL THEN 'Unknown' 
                WHEN EnterExit = 0 THEN 'On Entry' 
                WHEN EnterExit = 1 THEN 'On Exit' 
                ELSE 'Unknown' 
            END as EnterExit, 
            Ordtype, 
            CASE 
                WHEN Direction IS NULL THEN 'Unknown' 
                WHEN Direction = 0 THEN 'Both' 
                WHEN Direction = 1 THEN 'Forward' 
                ELSE 'Unknown' 
            END as Direction, 
            PrinterName, SyncStatus FROM OrdStageEvent ORDER BY Ordtype, EventCode"
        )
    
        # Execute the queries and process the results
        Invoke-SQLButtonClick -logText $logText -queries $queries -enableButton:$enableButton -buttonName $buttonName
    
        # Optionally re-enable the button if needed
        $button_DBStages.Enabled = $true
    }
                        
    $button_OrderHistory_Click = {
        
        $OrdNum = Show-InputBox -message 'Please enter the order number.' -title 'Order Number' -default '956'
        $BizDate = Show-InputBox -message 'Please enter the business date (format: MM/dd/yyyy).' -title 'Business Date' -default (Get-Date -Format 'MM/dd/yyyy')
        
        $button_OrderHistory.Enabled = $false


        # Define common parameters
        $logText = "Order History: ORDER#: $OrdNum, Biz DATE: $BizDate"
        $enableButton = $true
        $buttonName = 'button_OrderHistory'
    
        # Log the order number and business date
        Add-Logs -text $logText
            
        # Define the SQL queries
        $queries = @(
            "SELECT O.*,OT.OrderTypeCategory FROM Ord O LEFT JOIN ORDTYPE OT ON OT.OrdType=O.OrdType WHERE BizDate = '$BizDate' AND OrdNumber = $OrdNum",
            "SELECT * FROM OrdItem WHERE BizDate = '$BizDate' AND OrdNumber = $OrdNum ORDER BY OrdItemNumber",
            "SELECT [OrdStageTimeKey], [BizDate], [OrdNum], [OrdType], [Stage], [StartTime], [EndTime], [EntSync], [SyncStatus], [EntID] FROM [dbo].[OrdStageTime] WHERE [OrdNum] = $OrdNum AND [BizDate] = '$BizDate'"
        )
        
        # Execute the queries and process the results
        Invoke-SQLButtonClick -logText $logText -queries $queries -enableButton:$enableButton -buttonName $buttonName
    
        # Optionally re-enable the button if needed
        $button_OrderHistory.Enabled = $true
    }
    
    $button_CCBatch_Click = {
        $NumDays = Show-InputBox -message 'Please enter the number of days.' -title 'Number of Days' -default '7'
        
        # Disable the button while operation is running
        $button_CCBatch.Enabled = $false
    
        # Define common parameters
        $logText = "CCBatch - Last $NumDays Days"
        $enableButton = $true
        $buttonName = 'button_CCBatch'
    
        # Log the action
        Add-Logs -text $logText
        
        # Define the SQL queries
        $queries = @(
            'Select AboveStoreID, BusinessName, StoreNum FROM Business',
            "SELECT top $NumDays CCBatchKey, BizDate, CloseTime, 
            CASE IsOpen WHEN 'true' THEN 'Open' WHEN 'false' THEN 'Closed' ELSE 'Unknown' END as IsOpen FROM CCBatches ORDER BY BizDate DESC"
        )
    
        $sectionHeaders = @('Business Info:', 'CC Batch')
    
        # Execute the queries and process the results
        Invoke-SQLButtonClick -logText $logText -queries $queries -sectionHeaders $sectionHeaders -enableButton:$enableButton -buttonName $buttonName
    
        # Re-enable the button after operation is complete
        $button_CCBatch.Enabled = $true
    }
    
	$button_SyncRecords_Click = {
		# Initialize SQL connection parameters
		$SqlServerInstance = 'Revent1\REVENTION'
		$DatabaseName = 'REVENTION'

		$credential = Get-Credential -UserName 'Revention' -Message 'Enter the password for the SQL Server connection.'
	
		# Connect to SQL Server
		$connection = Connect-ToSQLServer -SqlServerInstance $SqlServerInstance -DatabaseName $DatabaseName -Username $credential.UserName -SecurePassword $credential.Password
	
		# Initialize command object
		$command = $connection.CreateCommand()
	
		# Specify tables to include
		$tablesToInclude = @(
			'APIUsers', 'Business', 'BusinessHours', 'BusinessServiceHours', 'Computer', 'ComputerCCOpts', 'ComputerCustDisp', 'ComputerExcldPmtTypes', 'ComputerOrdTypeXRef', 'DeliveryDriver', 'DeliveryOpts', 'DeliveryOptsTP', 'DeliveryOrder', 'DeliveryOrderTP', 'Employee', 'EmployeeFP', 'EmployeeLaborType', 'EventLog', 'GiftCardRange', 'KtchDisp', 'KtchDispOTXRef', 'KtchDispProdItmXRef', 'KtchDispPrtXRef', 'KtchDispQueue', 'LaborType', 'Menu86', 'MenuCategory', 'MenuCountdown', 'MenuCpnExcldOrdType', 'MenuCpnItm', 'MenuCpnMenuGroup', 'MenuCpns', 'MenuCpnValCode', 'MenuGrpDescXRef', 'MenuGrpItmXRef', 'MenuGrpMdCatXRef', 'MenuGrpMdSzXRef', 'MenuGrpMdXRef', 'MenuGrpPrfXRef', 'MenuGrpPSMdXRef', 'MenuGrps', 'MenuGrpStdMdSzXRef', 'MenuGrpStdMdXRef', 'MenuGrpStySzXRef', 'MenuGrpStyXRef', 'MenuGrpSzXRef', 'MenuGrpXRef', 'MenuItmDescXRef', 'MenuItmExcldMdXRef', 'MenuItmMdSzXRef', 'MenuItmMdXRef', 'MenuItmPrfXRef', 'MenuItmPSMdXRef', 'MenuItmReqMdXRef', 'MenuItms', 'MenuItmStySzXRef', 'MenuItmStyXRef', 'MenuItmSzTPXRef', 'MenuItmSzXRef', 'MenuItmTierSzXRef', 'MenuItmTierXRef', 'MenuItmTPXRef', 'MenuKtchPrtCat', 'MenuMdCat', 'MenuMds', 'MenuOrdNote', 'MenuPLU', 'MenuPrfMbrs', 'MenuPrfMbrXRef', 'MenuPrfs', 'MenuProdItm', 'MenuReportGrp', 'Menus', 'MenuStys', 'MenuSubmenuGrpXRef', 'MenuSubmenus', 'MenuSubmenuTime', 'MenuSubmenuTimeLT', 'MenuSubmenuXRef', 'MenuSuggXRef', 'MenuSzs', 'MenuTaxOrdType', 'MenuTaxType', 'MenuTaxZone', 'MenuTimePrice', 'MenuUPCItms', 'OrdBtnLayout', 'OrdStage', 'OrdStageEvent', 'OrdType', 'OrdTypeExcldItems', 'OrdTypeExcldPmtTypes', 'OrdTypeStage', 'PaymentType', 'PaymentTypeCat', 'Printer', 'PrinterCustOrdTypeXref', 'PrinterGroup', 'PrinterGroupXRef', 'PrinterKtn', 'PrinterKtnPrtCatXref', 'PrinterLblPrtCatXRef', 'PrinterOrdTypeXRef', 'PrinterRouting', 'PrinterTktFieldType', 'PrinterTktFmt', 'ReportCat', 'ReportOpts', 'RevCenter', 'SecChgAudit', 'SecGrp', 'SecGrpRights', 'SecIndGrp', 'SecIndRights', 'SecRightsDefault', 'SurchargePaymentType', 'Surcharges', 'SyncRecords', 'SysConfig', 'SysConfigPMS', 'SysGCOpts', 'SysOrdOpts', 'UISvcConfig', 'XO_SvcCon', 'XO_SvcLog', 'XO_SvcTypes', 'ZoneGeocodes', 'Zones'
		)
		$tablesString = $tablesToInclude -join "','"
	
		# SQL Query
		$sql = @"
		SELECT TOP 25 EntID, TableName, EntSync
		FROM dbo.SyncRecords
		WHERE syncstatus = 1
		AND TableName IN ('$tablesString')
		ORDER BY EntSync DESC
"@
		$command.CommandText = $sql
		$reader = $command.ExecuteReader()
	
		# Initialize output and custom object array
		$syncOutput = ''
		$allTables = @()
	
		while ($reader.Read()) {
			$EntID = $reader["EntID"]
			$TableName = $reader["TableName"]
			$EntSync = $reader["EntSync"]
	
			# Query specific table based on EntID
			$queryConnection = Connect-ToSQLServer -SqlServerInstance $SqlServerInstance -DatabaseName $DatabaseName -Username $Username -SecurePassword $SecurePassword
			$queryCommand = $queryConnection.CreateCommand()
			$querySql = "SELECT * FROM [$TableName] WHERE EntID = @EntID ORDER BY EntSync ASC"
			$queryCommand.CommandText = $querySql
			$queryCommand.Parameters.Add((New-Object Data.SqlClient.SqlParameter("@EntID",[Data.SqlDbType]::Int))).Value = $EntID
			$queryReader = $queryCommand.ExecuteReader()
			$table = new-object "System.Data.DataTable"
			$table.Load($queryReader)
	
			# Create custom object and append to array
			$allTables += [PSCustomObject]@{
				'TableData' = $table | Format-Table -AutoSize | Out-String -Width $richtextbox_output.Width
				'EntSync' = $EntSync
				'TableName' = $TableName
			}
	
			# Close query reader and connection
			$queryReader.Close()
			$queryConnection.Close()
		}
	
		# Close the main reader and connection
		$reader.Close()
		$connection.Close()
	
		# Sort all tables by EntSync and TableName, then append to $syncOutput.
		$allTables | Sort-Object { $_.EntSync -as [datetime] }, { $_.TableName } | ForEach-Object {
			$syncOutput += "Table Name: $($_.TableName), EntSync: $($_.EntSync)`r`n"
			$syncOutput += $_.TableData
		}
	
		# Update the rich text box
		$richtextbox_output.Text += "`n# # # # # # # # # #`n"
		$richtextbox_output.Text += $syncOutput
	
		# Enable the "OrderHistory" button
		$button_SyncRecords.Enabled = $true
}        
    $button_TotalSyncRecords_Click = {
        # Define common parameters
        $logText = 'Database - Total Sync Records'
        $enableButton = $true
        $buttonName = 'button_TotalSyncRecords'

        # Define the SQL queries
        $queries = @(
            'SELECT 
            SUM(CASE WHEN SyncStatus = 1 THEN 1 ELSE 0 END) AS Synced_Records,
            SUM(CASE WHEN SyncStatus = 2 THEN 1 ELSE 0 END) AS Pending_Records,
            SUM(CASE WHEN SyncStatus = 0 THEN 1 ELSE 0 END) AS Unsynced_Records
            FROM SyncRecords;'
        )

        # Execute the queries and process the results
        Invoke-SQLButtonClick -logText $logText -queries $queries -enableButton:$enableButton -buttonName $buttonName
    }


	#endregion Database TAB ###################################################

	#region Services TAB Event Handlers###################################################

	$button_mmcServices_Click = {
		Get-ComputerTxtBox
		Add-logs -text "$ComputerName - Services MMC (services.msc /computer:$ComputerName)"
		$command = 'services.msc'
		$arguments = "/computer:$computername"
		Start-Process $command $arguments 
	}

	$button_HRServices_Click = {
		Get-ComputerTxtBox
		Add-logs -text "$ComputerName - Services - Selected Services + Owners"

		if ($ComputerName -eq 'localhost') {
			$ComputerName = '.'
		}

		$Services = @(
			'RevControlSvc',
			'RevCloudSvc',
			'RevPrtSrv',
			'RevBackup',
			'RevCallerId',
			'RevGiftCardService',
			'RevMonitorSvc',
			'RUSvc',
			'RUSvcWatcher',
			'HungerRushUpdater',
			'TriposService',
			'HungerRushSyncSvc',
			'Spooler'
		)

		$Services_StartModeAuto = Get-WmiObject Win32_Service -ComputerName $ComputerName |
			Where-Object { $Services -contains $_.Name } |
			Select-Object Name, ProcessID, StartMode, State, @{Name = 'Owner'; Expression = { $_.StartName } } |
			Format-Table -AutoSize |
			Out-String

		Add-RichTextBox $Services_StartModeAuto
	}

	$button_servicesAutoNotStarted_Click = {
		Get-ComputerTxtBox
		Add-Logs -text "$ComputerName - Services - Services with StartMode: Automatic and Status: NOT Running"

		if ($ComputerName -eq 'localhost') {
			$ComputerName = '.'
		}

		$Services = @(
			'RevControlSvc',
			'RevCloudSvc',
			'RevPrtSrv',
			'RevBackup',
			'RevCallerId',
			'RevGiftCardService',
			'RevMonitorSvc',
			'RUSvc',
			'RUSvcWatcher',
			'HungerRushUpdater',
			'TriposService',
			'HungerRushSyncSvc',
			'Spooler'
		)

		$Services_StartModeAuto = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "StartMode='Auto' AND State!='Running'" |
			Where-Object { $Services -contains $_.Name } |
			Select-Object DisplayName, Name, StartMode, State |
			Format-Table -AutoSize |
			Out-String

		Add-RichTextBox $Services_StartModeAuto
	}

	$button_RevControlSvcStart_Click = {
		# Get the computer name from the text box
		Get-ComputerTxtBox

		# Log the action
		Add-logs -text "$ComputerName - Start Service"

		# Hardcoding the service name to 'revcontrolsvc'
		$Service_query = 'revcontrolsvc'
		Add-logs -text "$ComputerName - Service to Start: $Service_query"

		if ($ComputerName -like 'localhost') {
			# Start the service on localhost
			Add-logs -text "$ComputerName - Starting Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -Filter "Name='$Service_query'"
			$Service_query_return.startservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be started"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Start Service $Service_query - Done."
		} else {
			# Start the service on remote computer
			Add-logs -text "$ComputerName - Starting Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'"
			$Service_query_return.startservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be started"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Start Service $Service_query - Done."
		}
	}

	$button_RevControlSvcStop_Click = {
		# Get the computer name from the text box
		Get-ComputerTxtBox

		# Log the action
		Add-logs -text "$ComputerName - Stop Service"

		# Hardcoding the service name to 'revcontrolsvc'
		$Service_query = 'revcontrolsvc'
		Add-logs -text "$ComputerName - Service to Stop: $Service_query"

		if ($ComputerName -like 'localhost') {
			# Stop the service on localhost
			Add-logs -text "$ComputerName - Stopping Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -Filter "Name='$Service_query'"
			$Service_query_return.stopservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be stopped"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Stop Service $Service_query - Done."
		} else {
			# Stop the service on remote computer
			Add-logs -text "$ComputerName - Stopping Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'"
			$Service_query_return.stopservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be stopped"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Stop Service $Service_query - Done."
		}
	}

	$button_RevControlSvcRestart_Click = {
		# Get the computer name from the text box
		Get-ComputerTxtBox

		# Log the action
		Add-logs -text "$ComputerName - Restart Service"

		# Hardcoding the service name to 'revcontrolsvc'
		$Service_query = 'revcontrolsvc'
		Add-logs -text "$ComputerName - Service to Restart: $Service_query"

		if ($ComputerName -like 'localhost') {
			# Restart the service on localhost
			Add-logs -text "$ComputerName - Restarting Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -Filter "Name='$Service_query'"
			$Service_query_return.stopservice()
			Start-Sleep -Milliseconds 1000
			$Service_query_return.startservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be restarted"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Restart Service $Service_query - Done."
		} else {
			# Restart the service on remote computer
			Add-logs -text "$ComputerName - Restarting Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'"
			$Service_query_return.stopservice()
			Start-Sleep -Milliseconds 1000
			$Service_query_return.startservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be restarted"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Restart Service $Service_query - Done."
		}
	}

	$button_RevCloudSvcStop_Click = {
		# Get the computer name from the text box
		Get-ComputerTxtBox

		# Log the action
		Add-logs -text "$ComputerName - Stop Service"

		# Hardcoding the service name to 'RevCloudSvc'
		$Service_query = 'RevCloudSvc'
		Add-logs -text "$ComputerName - Service to Stop: $Service_query"

		if ($ComputerName -like 'localhost') {
			# Stop the service on localhost
			Add-logs -text "$ComputerName - Stopping Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -Filter "Name='$Service_query'"
			$Service_query_return.stopservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be stopped"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Stop Service $Service_query - Done."
		} else {
			# Stop the service on remote computer
			Add-logs -text "$ComputerName - Stopping Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'"
			$Service_query_return.stopservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be stopped"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Stop Service $Service_query - Done."
		}
	}

	$button_RevCloudSvcStart_Click = {
		# Get the computer name from the text box
		Get-ComputerTxtBox

		# Log the action
		Add-logs -text "$ComputerName - Start Service"

		# Hardcoding the service name to 'RevCloudSvc'
		$Service_query = 'RevCloudSvc'
		Add-logs -text "$ComputerName - Service to Start: $Service_query"

		if ($ComputerName -like 'localhost') {
			# Start the service on localhost
			Add-logs -text "$ComputerName - Starting Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -Filter "Name='$Service_query'"
			$Service_query_return.startservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be started"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Start Service $Service_query - Done."
		} else {
			# Start the service on remote computer
			Add-logs -text "$ComputerName - Starting Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'"
			$Service_query_return.startservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be started"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Start Service $Service_query - Done."
		}
	}

	$button_RevCloudSvcRestart_Click = {
		# Get the computer name from the text box
		Get-ComputerTxtBox

		# Log the action
		Add-logs -text "$ComputerName - Restart Service"

		# Hardcoding the service name to 'RevCloudSvc'
		$Service_query = 'RevCloudSvc'
		Add-logs -text "$ComputerName - Service to Restart: $Service_query"

		if ($ComputerName -like 'localhost') {
			# Restart the service on localhost
			Add-logs -text "$ComputerName - Restarting Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -Filter "Name='$Service_query'"
			$Service_query_return.stopservice()
			Start-Sleep -Milliseconds 1000
			$Service_query_return.startservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be restarted"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Restart Service $Service_query - Done."
		} else {
			# Restart the service on remote computer
			Add-logs -text "$ComputerName - Restarting Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'"
			$Service_query_return.stopservice()
			Start-Sleep -Milliseconds 1000
			$Service_query_return.startservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be restarted"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Restart Service $Service_query - Done."
		}
	}

	$button_RevPrinterServerSvcStop_Click = {
		# Get the computer name from the text box
		Get-ComputerTxtBox

		# Log the action
		Add-logs -text "$ComputerName - Stop Service"

		# Hardcoding the service name to 'RevPrinterServerSvc'
		$Service_query = 'RevPrtSrv'
		Add-logs -text "$ComputerName - Service to Stop: $Service_query"

		if ($ComputerName -like 'localhost') {
			# Stop the service on localhost
			Add-logs -text "$ComputerName - Stopping Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -Filter "Name='$Service_query'"
			$Service_query_return.stopservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be stopped"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Stop Service $Service_query - Done."
		} else {
			# Stop the service on remote computer
			Add-logs -text "$ComputerName - Stopping Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'"
			$Service_query_return.stopservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be stopped"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Stop Service $Service_query - Done."
		}
	}

	$button_RevPrinterServerSvcStart_Click = {
		# Get the computer name from the text box
		Get-ComputerTxtBox

		# Log the action
		Add-logs -text "$ComputerName - Start Service"

		# Hardcoding the service name to 'RevPrinterServerSvc'
		$Service_query = 'RevPrtSrv'
		Add-logs -text "$ComputerName - Service to Start: $Service_query"

		if ($ComputerName -like 'localhost') {
			# Start the service on localhost
			Add-logs -text "$ComputerName - Starting Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -Filter "Name='$Service_query'"
			$Service_query_return.startservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be started"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Start Service $Service_query - Done."
		} else {
			# Start the service on remote computer
			Add-logs -text "$ComputerName - Starting Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'"
			$Service_query_return.startservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be started"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Start Service $Service_query - Done."
		}
	}

	$button_RevPrinterServerSvcRestart_Click = {
		# Get the computer name from the text box
		Get-ComputerTxtBox

		# Log the action
		Add-logs -text "$ComputerName - Restart Service"

		# Hardcoding the service name to 'RevPrinterServerSvc'
		$Service_query = 'RevPrtSrv'
		Add-logs -text "$ComputerName - Service to Restart: $Service_query"

		if ($ComputerName -like 'localhost') {
			# Restart the service on localhost
			Add-logs -text "$ComputerName - Restarting Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -Filter "Name='$Service_query'"
			$Service_query_return.stopservice()
			Start-Sleep -Milliseconds 1000
			$Service_query_return.startservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be restarted"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Restart Service $Service_query - Done."
		} else {
			# Restart the service on remote computer
			Add-logs -text "$ComputerName - Restarting Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'"
			$Service_query_return.stopservice()
			Start-Sleep -Milliseconds 1000
			$Service_query_return.startservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be restarted"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Restart Service $Service_query - Done."
		}
	}

	$button_PrinterSpoolerSvcStop_Click = {
		# Get the computer name from the text box
		Get-ComputerTxtBox

		# Log the action
		Add-logs -text "$ComputerName - Stop Service"

		# Hardcoding the service name to 'PrinterSpoolerSvc'
		$Service_query = 'Spooler'
		Add-logs -text "$ComputerName - Service to Stop: $Service_query"

		if ($ComputerName -like 'localhost') {
			# Stop the service on localhost
			Add-logs -text "$ComputerName - Stopping Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -Filter "Name='$Service_query'"
			$Service_query_return.stopservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be stopped"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Stop Service $Service_query - Done."
		} else {
			# Stop the service on remote computer
			Add-logs -text "$ComputerName - Stopping Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'"
			$Service_query_return.stopservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be stopped"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Stop Service $Service_query - Done."
		}
	}

	$button_PrinterSpoolerSvcStart_Click = {
		# Get the computer name from the text box
		Get-ComputerTxtBox

		# Log the action
		Add-logs -text "$ComputerName - Start Service"

		# Hardcoding the service name to 'PrinterSpoolerSvc'
		$Service_query = 'Spooler'
		Add-logs -text "$ComputerName - Service to Start: $Service_query"

		if ($ComputerName -like 'localhost') {
			# Start the service on localhost
			Add-logs -text "$ComputerName - Starting Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -Filter "Name='$Service_query'"
			$Service_query_return.startservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be started"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Start Service $Service_query - Done."
		} else {
			# Start the service on remote computer
			Add-logs -text "$ComputerName - Starting Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'"
			$Service_query_return.startservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be started"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Start Service $Service_query - Done."
		}
	}

	$button_PrinterSpoolerSvcRestart_Click = {
		# Get the computer name from the text box
		Get-ComputerTxtBox

		# Log the action
		Add-logs -text "$ComputerName - Restart Service"

		# Hardcoding the service name to 'PrinterSpoolerSvc'
		$Service_query = 'Spooler'
		Add-logs -text "$ComputerName - Service to Restart: $Service_query"

		if ($ComputerName -like 'localhost') {
			# Restart the service on localhost
			Add-logs -text "$ComputerName - Restarting Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -Filter "Name='$Service_query'"
			$Service_query_return.stopservice()
			Start-Sleep -Milliseconds 1000
			$Service_query_return.startservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be restarted"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Restart Service $Service_query - Done."
		} else {
			# Restart the service on remote computer
			Add-logs -text "$ComputerName - Restarting Service: $Service_query ..."
			$Service_query_return = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'"
			$Service_query_return.stopservice()
			Start-Sleep -Milliseconds 1000
			$Service_query_return.startservice()
			Add-Logs -Text "$ComputerName - Command Sent! $Service_query should be restarted"

			# Check the status of the service
			Start-Sleep -Milliseconds 1000
			$Service_query_result = Get-WmiObject Win32_Service -ComputerName $ComputerName -Filter "Name='$Service_query'" | Out-String
			Add-RichTextBox $Service_query_result
			Add-Logs -Text "$ComputerName - Restart Service $Service_query - Done."
		}
	}






	#endregion ###################################################

	
	#----------------------------------------------
	#region Generated Events
	#----------------------------------------------
	$button_outputClear_Click = { Clear-RichTextBox }

	$button_formExit_Click = {
		$prompt = 'Do you really want to Exit ?'
		$title = "$ApplicationName $ApplicationVersion - Exit"
		
		$ExitConfirmation = Show-MsgBox -Prompt $prompt -Title $title -BoxType YesNo
		
		if ($ExitConfirmation -eq 'YES') {
			$form_MainForm.Close()
			$notifyIcon.Dispose()
		}
	}
		
	$button_outputCopy_Click = {
		
		Add-logs -text 'Copying content of Logs Richtextbox to Clipboard'
		$texte = $richtextbox_output.Text
		Add-ClipBoard -text $texte }
	
	$button_ExportRTF_Click = {
		$filename = [System.IO.Path]::GetTempFileName()
		$richtextbox_output.SaveFile($filename)
		Add-logs -text 'Sending RichTextBox to wordpad (RTF)...'
		Start-Process wordpad $filename
		Start-Sleep -Seconds 5
		Remove-Item -Force $filename
	}
	
	
	$textbox_computername_TextChanged = {
		$label_PingStatus.Text = ''
		$label_RevcloudStatus.Text = ''
		$label_HRUpdateStatus.Text = ''
		$label_RevControlStatus.Text = ''
		$label_POSStatus.Text = ''
		$label_RevMonStatus.Text = ''
		$label_RevScreenMgrStatus.Text = ''
		if ($textbox_computername.Text -eq '') {
			$textbox_computername.BackColor = [System.Drawing.Color]::FromArgb(255, 128, 128);
			add-logs -text 'Please Enter a ComputerName'
			$errorprovider1.SetError($textbox_computername, 'Please enter a ComputerName.')
		}
		if ($textbox_computername.Text -ne '') {
			$textbox_computername.BackColor = [System.Drawing.Color]::FromArgb(255, 255, 192)
			$errorprovider1.SetError($textbox_computername, '')
		}
		$tabcontrol_computer.Enabled = $textbox_computername.Text -ne ''
		$button_Check.Enabled = $textbox_computername.Text -ne ''
	}

	
	$richtextbox_output_TextChanged = {
		#Scroll to Bottom when text is changed
		$richtextbox_output.SelectionStart = $richtextbox_output.Text.Length
		$richtextbox_output.ScrollToCaret()
	}
	
	$richtextbox_Logs_TextChanged = {
		$richtextbox_Logs.SelectionStart = $richtextbox_Logs.Text.Length
		$richtextbox_Logs.ScrollToCaret()
        if ($myerror[0] -and $myerror.Count -lt 1000) {Add-logs -text $($myerror[0].Exception.Message)}

	}
	
	$textbox_computername_KeyPress = [System.Windows.Forms.KeyPressEventHandler] {
		#Event Argument: $_ = [System.Windows.Forms.KeyPressEventArgs]
		If ($_.KeyChar -eq 13) {
	 	$button_ping.PerformClick()
			$richtextbox_output.Focus()
		}
	}	


	$Form_StoreValues_Closing =
	{
		#Store the control values
		$script:MainForm_richtextbox_output = $richtextbox_output.Text
		$script:MainForm_textbox_processName = $textbox_processName.Text
		$script:MainForm_textbox_servicesAction = $textbox_servicesAction.Text
		$script:MainForm_textbox_networktracertparam = $textbox_networktracertparam.Text
		$script:MainForm_textbox_pingparam = $textbox_pingparam.Text
		$script:MainForm_textbox_computername = $textbox_computername.Text
		$script:MainForm_richtextbox_Logs = $richtextbox_Logs.Text
	}

	
	$Form_Cleanup_FormClosed =
	{
		#Remove all event handlers from the controls
		try {
			$richtextbox_output.remove_TextChanged($richtextbox_output_TextChanged)
			$button_formExit.remove_Clic($button_formExit_Click)
			$button_outputClear.remove_Click($button_outputClear_Click)
			$button_ExportRTF.remove_Click($button_ExportRTF_Click)
			$button_outputCopy.remove_Click($button_outputCopy_Click)
			$buttonSendCommand.remove_Click($buttonSendCommand_Click)
			
			$button_IPScanner.remove_Click($button_IPScanner_Click)
			$button_VNC.remove_Click($button_VNC_Click)
			$buttonC.remove_Click($buttonC_Click)
			$button_networkconfig.remove_Click($button_networkIPConfig_Click)
			$button_Restart.remove_Click($button_Restart_Click)
			$button_Shutdown.remove_Click($button_Shutdown_Click)
			
			$button_networkPing.remove_Click($button_networkPing_Click)
			
			$textbox_computername.remove_TextChanged($textbox_computername_TextChanged)
			$textbox_computername.remove_KeyPress($textbox_computername_KeyPress)
			$button_Check.remove_Click($button_Check_Click)
			$richtextbox_Logs.remove_TextChanged($richtextbox_Logs_TextChanged)
			$form_MainForm.remove_Load($OnLoadFormEvent)
			$ToolStripMenuItem_CommandPrompt.remove_Click($ToolStripMenuItem_CommandPrompt_Click)
			$ToolStripMenuItem_Powershell.remove_Click($ToolStripMenuItem_Powershell_Click)
			$ToolStripMenuItem_Notepad.remove_Click($ToolStripMenuItem_Notepad_Click)
			$ToolStripMenuItem_compmgmt.remove_Click($ToolStripMenuItem_compmgmt_Click)
			$ToolStripMenuItem_taskManager.remove_Click($ToolStripMenuItem_taskManager_Click)
			$ToolStripMenuItem_services.remove_Click($ToolStripMenuItem_services_Click)
			$ToolStripMenuItem_shutdownGui.remove_Click($ToolStripMenuItem_shutdownGui_Click)
			$ToolStripMenuItem_SSMS.remove_Click($ToolStripMenuItem_SSMS_Click)
			$ToolStripMenuItem_PrintersControl.remove_Click($ToolStripMenuItem_PrintersControl_Click)
			$ToolStripMenuItem_netstatsListening.remove_Click($ToolStripMenuItem_netstatsListening_Click)
			$ToolStripMenuItem_addRemovePrograms.remove_Click($ToolStripMenuItem_addRemovePrograms_Click)
			$ToolStripMenuItem_devicemanager.remove_Click($ToolStripMenuItem_devicemanager_Click)
			$ToolStripMenuItem_systemproperties.remove_Click($ToolStripMenuItem_systemproperties_Click)
			$ToolStripMenuItem_networkConnections.remove_Click($ToolStripMenuItem_networkConnections_Click)
			$ToolStripMenuItem_diskManagement.remove_Click($ToolStripMenuItem_diskManagement_Click)
			$ToolStripMenuItem_scheduledTasks.remove_Click($ToolStripMenuItem_scheduledTasks_Click)
			$ContextMenuStripItem_consoleToolStripMenuItem_ComputerName_Qwinsta.remove_Click($button_Qwinsta_Click)
			
			$ToolStripMenuItem_SET_Backup_Path.remove_Click($ToolStripMenuItem_SET_Backup_Path_Click)
			$ToolStripMenuItem_CREATE_Kitchen_Printers.remove_Click($ToolStripMenuItem_CREATE_Kitchen_Printers_Click)
			$ToolStripMenuItem_CREATE_Station_Printer.remove_Click($ToolStripMenuItem_CREATE_Station_Printer_Click)
			$ToolStripMenuItem_REMOVE_ALL_Printers.remove_Click($ToolStripMenuItem_REMOVE_ALL_Printers_Click)
			$ToolStripMenuItem_SET_Allow_Batch.remove_Click($ToolStripMenuItem_SET_Allow_Batch_Click)
			$ToolStripMenuItem_SET_HungerRush_ShortCuts.remove_Click($ToolStripMenuItem_SET_HungerRush_ShortCuts_Click)
			$ToolStripMenuItem_Test_All_Local_Printers.remove_Click($ToolStripMenuItem_Test_All_Local_Printers_Click)
			$ToolStripMenuItem_SET_Allow_Close_Day.remove_Click($ToolStripMenuItem_SET_Allow_Close_Day_Click)

            $richtextbox_output.Dispose()
            $richtextbox_Logs.Dispose()

			
			$timerCheckJob.remove_Tick($timerCheckJob_Tick2)
			$form_MainForm.remove_Load($Form_StateCorrection_Load)
			$form_MainForm.remove_Closing($Form_StoreValues_Closing)
			$form_MainForm.remove_FormClosed($Form_Cleanup_FormClosed)
		} catch [Exception]
		{ }
	}
	#endregion Generated Events

	#----------------------------------------------
	#region Generated Form Code
	#----------------------------------------------
	#
	# form_MainForm
	#
	# Add controls to the form
	$form_MainForm.Controls.Add($richtextbox_output)
	$form_MainForm.Controls.Add($panel_RTBButtons)
	$form_MainForm.Controls.Add($tabcontrol_computer)
	$form_MainForm.Controls.Add($groupbox_ComputerName)
	$form_MainForm.Controls.Add($richtextbox_Logs)
	$form_MainForm.Controls.Add($statusbar1)
	$form_MainForm.Controls.Add($menustrip_principal)

	# Configure form properties
	$form_MainForm.AutoScaleMode = 'Inherit'
	$form_MainForm.AutoSize = $True
	$form_MainForm.BackColor = 'Control'
	$form_MainForm.ClientSize = '670, 575'
	$form_MainForm.Font = 'Microsoft Sans Serif, 8.25pt'
	$form_MainForm.MainMenuStrip = $menustrip_principal
	$form_MainForm.MinimumSize = '278, 746'
	$form_MainForm.Name = 'form_MainForm'
	$form_MainForm.Text = 'HungerRush InstallXpert'

	# Attach form load event
	$form_MainForm.add_Load($OnLoadFormEvent)

	# Remove minimize, maximize, and close buttons
	$form_MainForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
	$form_MainForm.ControlBox = $false

	
	#
	# richtextbox_output
	#
	$richtextbox_output.Dock = 'Fill'
	$richtextbox_output.Font = 'Consolas, 8.25pt'
	$richtextbox_output.Location = '0, 224'
	$richtextbox_output.Name = 'richtextbox_output'
	$richtextbox_output.Size = '1175, 365'
	$richtextbox_output.TabIndex = 3
	$richtextbox_output.Text = ''
	$richtextbox_output.WordWrap = $false  
	$richtextbox_output.ScrollBars = 'Both'  
	$tooltipinfo.SetToolTip($richtextbox_output, 'Output')
	$richtextbox_output.add_TextChanged($richtextbox_output_TextChanged)
	#
	# panel_RTBButtons
	#
	$panel_RTBButtons.Controls.Add($button_formExit)
	$panel_RTBButtons.Controls.Add($button_outputClear)
	$panel_RTBButtons.Controls.Add($button_ExportRTF)
	$panel_RTBButtons.Controls.Add($button_outputCopy)
	$panel_RTBButtons.Dock = 'Bottom'
	$panel_RTBButtons.Location = '0, 589'
	$panel_RTBButtons.Name = 'panel_RTBButtons'
	$panel_RTBButtons.Size = '1170, 34'
	$panel_RTBButtons.TabIndex = 63
	#
	# button_formExit
	#
	$button_formExit.Dock = 'Right'
	$button_formExit.Font = 'Trebuchet MS, 9.75pt, style=Bold'
	$button_formExit.ForeColor = 'Red'
	#region Binary Data
	$button_formExit.Image = [System.Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAAAARnQU1BAACx
jwv8YQUAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAAAlwSFlz
AAAG6AAABugB4Yi/JwAABShJREFUSEuVlntMU3cUx0+1oEYUHR0KEivKkGEUFOzo5FFACgyGCKgh
yoYzSgaiIupEpw7NHHtEndohTibToGaa/eFjU5Np1M34gPG0IBZExLdzMqrCcHx3TteSjcysa/LJ
vW3v/X7OOf3de0sAyF6IaJg2KKAmampopS5UWzlFG1ipCfSr9J/gW+mp9ijj7/f2Yrnd4VIEv3wO
lBbhSVsLbrfUoK7mR1w89x1OHt2PuXNS5IDuXuz934J9ewthbmtmQTXqql8o+INFwp7/FPBBbu5E
frYO9uzeiscPTWhtroKx+hwunD2GE0ekg2RbB8/5nC7md3sFnrFEDV5EATKiXUWbcP+2ETdM5ait
OIPzZ47g+OFSpKVOF4EtuIP3ha/t6cCzUOViXubU/+pwBSXvMBRYqjfVX0RV2SmcPnkI+3Zvwczp
sTL/TuYZ85R5wpTYJShRu5srJvtixRDH62tzM9HUcMky/8vnv8fhgztRUvQxZkyLFoGES7CZaWd2
y8oYoiVaF0yU35sQBeUH9qFNpV7uz4xh/qjXeCLf2xVHvylGdflpnDp+AIdKDSg2bETym1EikHAJ
bmMeM1+JwNPg7GyuSEpCRUoKfk5IQFl0NMrCdagIC0JNyETU6fxhihiPptAxuKFxxZbAkThYshXH
vi3G/pItKPp8PabHR4pAwiX4V+YRU2wR7FCpzHWLFsGYlYXaefNQlZqK2hmJMCbq0RAXDFP0JDRH
+qBVp8adKSo8CBqAbVp3GArysGfnp9j+2RokxIbLspRwCX7IPGB2WQSFLi7mmvR0VKeloXLWLFQl
TcOVxGjUx4fCFBOIZv043IrwxD3dcPwSPhhtkUo8jSEYdG7YuCoLmzeuRLw+TAS28Pu8f4/5smdE
5XFxuKzX43JEOCrCX0dt2CRcDR3HY/FCS/AI3A1W4ZHOCe3RDuiYpkTHnGHozPBGQYwv8pYuQOzU
YBFI5RJ+l7ndI9jMsztOBOEHJeEnJ0K5C+HKCIJpNKH1VcKDQEJ7BKEj0REd76jRmTMZjUvCkJ0U
gQ2rFkIfrpULTMYi4beYVmanpYO/C073I1xwJlS6EupHEpq9CXcnEB6HcHg8k+6BztwgNK6IQfZM
PQrW5WDt8gxEhmhEIGORym8yN5gd/xCcUBDODiBcGkqodiNc8yTc9PmrevNUDp81BJ3ZfmhapreE
f5Kfi/V5C/HeorkI0waI4I61cgm/3iOYQWTMZhYryJjrSMa8gWRc40zGDSoyfuRGxtoAev40lgVv
e6AxU4PslCgUfJCDDauzsXrpfORkzEbIa/5ym5DqW6zhjbwttOtKPjGB2jviFTClqp+nhvrhwzWL
kb8yC+/nzseyrLeQmZ4Cjb+vCGTuUr2EX2O+sEtw0o/aG6P6dMWrBx5ITY6zBOctmWcJn5kQ1T1m
1Ihnyr59ZfXI7GU0JqaeMfyrQH4Y60vB29HFY6ktyY3bJRqX+EY4cjPTMDs5tnvsGHWXUqn8jT+X
1WMbTxPvNzB1zPYeAb+RMKEP05dxYPoxPtpBlnvKQGa8ZqIvxnqN6nZwUMrtWG4NcnFJ9TaBjOcq
c4XZZhFYgyVUAiXImVExbgw/CkjNeDCjHR0deFVTLrOY4bVBmcy7TAazwMp83go6m0CqdmQGM67W
QB/e+jMaJoiZzPgx3sxI5mXGiZFOFS/649BbMMh6ogRIkAQGWiXyRBvPvMJINy6MdKu0R8DHWOYu
XQxgRPSStRsZkzDcKh9qrby/rXo5+UUd/AkTStTbDGPagwAAAABJRU5ErkJggg==')
	#endregion
	$button_formExit.Location = '1129, 0'
	$button_formExit.Name = 'button_formExit'
	$button_formExit.Size = '41, 34'
	$button_formExit.TabIndex = 15
	$tooltipinfo.SetToolTip($button_formExit, 'Exit')
	$button_formExit.UseVisualStyleBackColor = $True
	$button_formExit.add_Click($button_formExit_Click)
	#
	# button_outputClear
	#
	#region Binary Data
	$button_outputClear.Image = [System.Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAAAARnQU1BAACx
jwv8YQUAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAABDNJREFU
SEutlX1M1HUcx793PEii0nGaNx68kIc8hXjIEBiCLolVym4JE2RsbLJKVmJZrbI/1MZktkAwh8UG
WC7joYelPMlBPByPB4XAeRzHs9xNWooWiUHdu89nww3L2qD7bu/97r6/3/fz+nzen+/v9xViYWTv
l0hOJ9snnk11fi8nSfrE/XmbXXOS7BIuZ4ZbL5+MwrfHQu5kJ0k32Sw4B8pPk2VVntyOK/mpaM3b
joKXXQtsCshJlMY15e6yao7K0HxcgUvHg2aoisdsBslOEKIwXVHSnhuGhvdd0JjljzMpjkdtBuBA
VIW89O2NE/XHPFH57joUp8snaM6puUhEaYuFu01gtIOeLXvTc74sYw2+fGMNtJ+5dU907bU2F4tE
mwA4yLk0h9PVH8kw3hGHuZuZmJ3KRL5aWn5QiOD/BdEWCdFyXpraV+U1ecu0D3/8nIHBymRcfMYf
GqUSWY6OAwSRLBtCNkhaLzhkXqvznTNqQlCS4IP6zSrMqNWo8PXBF/tVf3aWuuZSP1yWDeGFp0LF
iQInCdrXUA+8vVH6fDhGNCmYt+zGLdOL6K8OGCZI0LIhrwpxqEQIfOLhgs5PqQ83XsfvlgOYm4zB
beMmmK9uheH7yGmC7FoW5BUh7F9bIeIHNDum5yZ34t51NWZG4zE7FoPpaypMdKzHcLs3htrUs62f
O+4j0NIHLZIaGyLMvwxtxb3xSNwdew4/9YTgtsEf5m53GBsVGGrxwlh36nz7RdnhJUN4QV/V5q6p
/hD8OhSAaX0gZkxPw6LzwqjWAyNtcgw0eMGk9YVZn2Ht+lpZRGtWLqkUXZm8cLInHJZuN5g7N+Du
aDCGGzxg+dGfGr0Sw21uMDY9CUO9D24MHrHqayMHteelcQT6z63MN+1JTt/liZdGddEwNT6K650U
uMsTNw0RMFyRkz2B6KuWYlS3hUAR6K3aAIvhCHTl7jUEWPGwSjiwI4n3+HqSMjZCbNPXhf1mbPTB
WIcChloFpvpUGGoOxXCrHwGUMNTZwdwfR71IsdYV2JUfUAtXWiv9O4CDP0KSkzxJfKLxZyHiqzxZ
xcTVveivccBgUzAGG1bBot+DnktyTPbuJogKvTWBM4UnpB84OoiNC8mtpqvdYghbwpm7kXxJgRyc
FBMZLNL09VGz+lo/siMIvZVuGNOFYvyHZPRWh8x/8/E6TUy4iKdnnyLxKcgJcqJOiwFMY6qCxFkE
kLaRdpJeyDpsf26kM8lqaonFWFcK2ko87lz4cG3FnmiRTvf5ZeNkgkh+JP6sy0hs9wODq2AI+/84
SUVim8KkUhGd85bk1Jl3JLkHE8Sh1c4iluZ3LATmzLeQvEnsAAd/aJOZdr/RDFq7sEBJVx8S94Ut
YDD/Ziu9SB4kPlrZYrblHw1+oIxFfxjG1nGpvAH4JVq1IOeFOc6UK//XoH8BnFniKnIn4rAAAAAA
SUVORK5CYII=')
	#endregion
	$button_outputClear.Location = '1, 1'
	$button_outputClear.Name = 'button_outputClear'
	$button_outputClear.Size = '38, 31'
	$button_outputClear.TabIndex = 5
	$tooltipinfo.SetToolTip($button_outputClear, 'Clear !')
	$button_outputClear.UseVisualStyleBackColor = $True
	$button_outputClear.add_Click($button_outputClear_Click)
	#
	# button_ExportRTF
	#
	#region Binary Data
	$button_ExportRTF.Image = [System.Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAAAARnQU1BAACx
jwv8YQUAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAA5BJREFU
SEuVVUtPE2EU5Qe4cScxvHZG9xIxupOAKxfqgqiBkKpJSyASSoEGTVxQISEkEh8rgkJSFiRq7IYE
3bg1PErHQoFCKY+W0hct0AL3+p0vM83Q9AGT3MzXZuaee885905Jie4aGxszT01NDZ4nHA7H4OTk
5KDRaKzT5yh4drlcCouLxIV79ln/G8+cnJyweCfV2Nj47FwgFwVAHdvb26woSrqpqelpURAAoDL9
dRyLUvzvH0qlUhSLxc7E8fExBYNBCoVCtLS0lG5ubn5yIYpODw95a6iXwj9H+fT0lEVCBGl3UCQA
eG9vjwKBAC8uLqYMBsPjvCB6itC+b6Cfva8aKGQf4kMBJhLJZNr96OiIRfXs9/slwObmJjudzmR5
efnlnCB6igL2r+TtttC/umsU/PKOBAASZwK0IHZ3dyVNAoD29/flc5WVlVcKAXD093cKTzv4JJFg
T8NtCo7aznSAqqEJKEKAtnQ6jf/wHFVVVeUHANfhRYVifh/HRdt7LidFPG4+ODiQkUwmSQQnEglU
zPF4HAHxZRHimcIAeHF+fp4EXSREo9XVVfL5fCT4pZ2dHRk4r6+v0/LyMrndbhK809zcHEWjUYAX
pijXoEFwdIYQlEgXCUpgXYbQoEXtjqFDQQ2QIFtMCKkXE4KiEzFktLW1JTvCGd2DrmIAGStCTDW5
9DusqNKECUZyaU3YFGdogmE8F4CaXALokusTk0jMGxsbDI1whtCRSKS4TbEqVL4zk6vZUHAOr0s3
CUpk1ZqLhMgcDofzAywsLCjwtMa3NkDZfIMSUbl0F9y0trYmz6ge+lVUVOSeAxUAfMvR1zjHxtTz
jf+tvV1Uc+cm36u/ywbjQ6p7VMMj45+wOvIDCD8roEJ1CQTNFhOcwzFsbHlB74ctPP3rM//49oaM
bQ94+OOALC5vB2LAFKyAYpTAmqaWlzRh7yX7uIkmJvrI+vo59fW/lTupIIAqJqkDJEdfJ6a0IcRs
bTNS7f1qNrTV863a63Sj+ip/GOmXNs4LIMZdwUSqwwN/S0qEgCzEZCEme71eCCzdgrWtzYpmZcxH
XoDZ2VkF9sNk5nIKkmM3raysyD3k8XjwJZM7CzsJTioIMDMzIzvI9jgoERZE1XLKs6vWTKG6jcrK
ynLb1GQytVqtVhuip6dHRnd3t4yuri6bxWKR0dnZmQmz2WxDdHR0yGhvb+8rLS29pH1w/gOdNdPK
bNoi9AAAAABJRU5ErkJggg==')
	#endregion
	$button_ExportRTF.Location = '95, 1'
	$button_ExportRTF.Name = 'button_ExportRTF'
	$button_ExportRTF.Size = '41, 31'
	$button_ExportRTF.TabIndex = 23
	$tooltipinfo.SetToolTip($button_ExportRTF, 'Export to Wordpad (RTF)')
	$button_ExportRTF.UseVisualStyleBackColor = $True
	$button_ExportRTF.add_Click($button_ExportRTF_Click)
	#
	# button_outputCopy
	#
	#region Binary Data
	$button_outputCopy.Image = [System.Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAABgAAAAYCAYAAADgdz34AAAAAXNSR0IArs4c6QAAAARnQU1BAACx
jwv8YQUAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAATdJREFU
SEvFlr+KhDAQxn2Ee5R7Swt9BjvFSrCxvcZSud5rRaw8EAv/z+4XiER3N05uhQt8ojiZn/OZCbEs
ZSRJQmeK45g8z0Pc712f6nz1nogsSFykkJwz8jynLMsA+b7r4xnkLUDTNNR1nRZyCjizCu91drEA
79h1GeCVXZcBqqoShR7/yWWAsiw3JwFJ01SsrssAfd9T27ZU1zUVRSEAYRgCqu8Dbk8cF8K6ruaA
r/yHOJIwx3H0FeAr/loBMtu2/c+AZVl2FXDsQYwcpxWoANhlIpZF8zxvFZgkRywLME3TBkA1XIsQ
ywIMw7ADYCJXLMA4jhsAdpmIBUCQ7APYxbUIsVpAFEXkuq5oFAmAXSbSAo4HAARjMzPRAwBJt53v
cMI4bmTc512jvQLAriAIyPd9Y6mAG6gAZUPR6LYBAAAAAElFTkSuQmCC')
	#endregion
	$button_outputCopy.Location = '45, 1'
	$button_outputCopy.Name = 'button_outputCopy'
	$button_outputCopy.Size = '44, 31'
	$button_outputCopy.TabIndex = 20
	$tooltipinfo.SetToolTip($button_outputCopy, 'Copy to Clipboard')
	$button_outputCopy.UseVisualStyleBackColor = $True
	$button_outputCopy.add_Click($button_outputCopy_Click)
	#
	# tabcontrol_computer
	#
	$tabcontrol_computer.Controls.Add($tabpage_general)
	$tabcontrol_computer.Controls.Add($tabpage_Database)
	$tabcontrol_computer.Controls.Add($tabpage_Services)

	$tabcontrol_computer.Dock = 'Top'
	$tabcontrol_computer.Location = '0, 87'
	$tabcontrol_computer.Multiline = $True
	$tabcontrol_computer.Name = 'tabcontrol_computer'
	$tabcontrol_computer.SelectedIndex = 0
	$tabcontrol_computer.Size = '1170, 137'
	$tabcontrol_computer.TabIndex = 11
	#
	# tabpage_general
	#
	$tabpage_general.Controls.Add($buttonSendCommand)
	$tabpage_general.Controls.Add($button_IPScanner)
	$tabpage_general.Controls.Add($button_VNC)
	$tabpage_general.Controls.Add($buttonC)
	$tabpage_general.Controls.Add($button_networkconfig)
	$tabpage_general.Controls.Add($button_Restart)
	$tabpage_general.Controls.Add($button_Shutdown)
	$tabpage_general.BackColor = 'Control'
	$tabpage_general.Location = '4, 22'
	$tabpage_general.Name = 'tabpage_general'
	$tabpage_general.Size = '1162, 111'
	$tabpage_general.TabIndex = 12
	$tabpage_general.Text = 'General'
	#
	#	
	
	# button_IPScanner
	#
	$button_IPScanner.Font = 'Microsoft Sans Serif, 8.25pt'
	#region Binary Data
	$button_IPScanner.Image = [System.Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAAXNSR0IArs4c6QAAAARnQU1BAACx
jwv8YQUAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAD1lJREFU
aEPdmglUlFeahn9EUJC1oCgotmIp2SxZCllklUUFFZGIiKJGA8jSKhg1amx3E2OSjsm4kY5GBBQo
2VEEARUVMRpN27Enmc7SSU+nZ5wxnU7O9Dk97cw733erCkHbNZ2eky7PPYVVVP3P+y33vvf+SACk
H/P4UcNz4P+xBEhP+8iWTKV8KUlaKm2RCiQdPV+VCqU7NGAYd8Rr+ve2iN/lzzzlY2jJD8vAE39f
vqQlwH00bjvutIGmzgOJvUHIfD8CBZ8kY+lnqSj5fDKWfTEV834Zi+n9WkS1qKF8TcbCbovP8nc8
4eP7CyiUNHTxDos15hh/3AOZ1yZg/s1YLPjneCz6OBFL/mXSfQJW/DYdK383Hat+n4EX/m0mln+Z
hqTOIFivs2AxHTQ0j6vj6QWUSxZ0oV3m5SPvhLSokHk9Atm/iELOLydiHgnIYwEfJQgB+cYM/GaK
yECZQcBqFvDvmVh/axY2/OczeJGeJ/cGY/RKMy65XRJf4xGPpxPwnORLF7iu3GOPqQPBmElRzyIB
s0nAHBKQ+2EM8n4Vh4UkYPG9AijaZf86Dc9TBtaQgHUk4MX/yBICnv9qBoqpzObeiIHbmw6cjesS
X+shjycXUCRFjCgxuRXU6I6090Ix/UoYZrwfLkrnmQ8ikX0jGtkfRCOlU4MJR33gt0cJuymWsKFh
l2YJhxnWCHlHhdTW8Zj/XhxWf5UhBLCgIuoTFj2bviftcgjUVS4wKTa5JdE1H6ThyQQwfOmI70JP
qDD50nhMpYuks4irWswkEWkXQqB51wPO2+0Q9HM3xLcEIGsgAotuJmDppykooRIq+iQVi28kIvNM
BOLrAxG01x3JrRos/DABC6nsOAj8vXF9AdB2ecP5VTsSIX33IBGPL4BSaUKR17R5IOniOKT0azCZ
yocvNnUgFJoqTyi220J7zBuzrkzQl5GhkZ/7ddKgAG7Ycoo21/9aauCSTyYjuV0D9T+5IELni9RL
wYg750/wPvDa6QIrpzGw2DgKJODWXyunxxOQLZlzParrXRB/PhCJF4L0IigL8T2BcN0lg/qAC9Iu
hWKWoZnnUi/Mpz7gRjYKKKUMLB/SwMtIDE+x3C8zBrQIOOQK97ccENymEvA2CmsoNsvhUOkA05dM
9T3BLEMejyegQHrdcbc1Ys76iegYRUR1qCHfZoOQWpW+H7iUDL3AzcyzEde0dqU3Ilf7InrtWMRt
8BdTKIthYTzlsugplM1Y+m6/aiUcS+1g7WQN5y1OkFfK4UK94FzlDJO1Jixi15MJKJBCRpaZ3tGe
9kb0mbGYSCL4QpGnfOGwxQphjV4iE1O4HwwNbcwClxGvBzyVFlIPMPQKinoxNSu/lkvwPP1yKfJ3
ctl4v+Ii4OWlDpAfkkNZpYRHjQd8jvnA8aAjpBJa1YnJKOLRGSiU2j1r5JjQ44tIGlEkIqpHDaeX
bRFY7YpEKikup1RDU08jEcYscBlxefBUygK4iQvomcuK3+PG589xZo3wts42IvJO+5ygfF0JzxpP
Ae9X54eg+iCMeon6gZgeTwApNV81EqGdKnAGwrt9EEEiVBVOcH1Tpi8pmi2GiuDpbwaVksgCTalc
Is/SisyLGQvhvuDX+Xc4c0Z4n1eUYHiXrQo4HSF4irznHoKv8IF/nT/G6cYhtCEUqhoVpFLyVYYs
PDwDhVKFyyE7BJMAFhHW5QVNqwfsNllCe8obUb1qUVLcFwmGTPD0ylNrBkU3/WIYohvGwjnLTsz/
DhlWUMyxg1bnjbieAPFZbacP7oV3pcxy5H1rfOH/lj80tRoBP6FxAqKbo2G+3ZyzUMFZeLAAWsZN
iqTbfm2u0HR4YPwpTyFE+ZY9PN92FBmZQBnhsuLe4Brm5hbl1D8ewQSg2u2EiS3+SOsLwaxrERT1
cCR0ByK4XkUrrQy+h5UC3s7FVkRecUQBhlcdVcH3GMFT5DXvEvy7oYhoisDE5olIaE2AR6UHyMne
ZqvxYAGFUqzFZnMEnnBDEI1xJ90R2O4Oqw2jMa7NHSGGjISzEO4NyoaxpLwPKOBPU2IarQ88M3FG
eL3gkuFMRfWORehJbyhfkMNWYQvlVuf74APqAqDRaRCmC0NEBcE36eGT25MR2RQJgucsxD5YAHl1
2X4r+Lcp4d/uigAaHu86wnGXtRAzbkhWQqm0WAj3h+9BZ3i/rcAkysQkWi94cI/EU6+wwMhuX4Rx
2exyFZF3XkWR36uAW7WbiLy6Vo1B+AaCp8jHVMYgQZeAlPYUTD05FdM7psNsixlnYcvDMtCirLGH
utVFjLE0HN+wgevPZXpBlBXODovhEgumEgtqdofTLltMOO0rxHBmeLgtkcEt3wGu+TIo6dlnlxL2
SjsReedKZ7jtJvgjd+HH68YjjOA50jEtMUisT0RKrR5+xqkZmNU5C/K35JyBlocJuOmmc4B3swI+
PFqcYbPDEh7VjlDTz0IUZcfPkCEW43pABhXN3SyKy45f48zphXpAc5JqmyIv4LfpFyeOvNc7XlAf
VCOQvBHDaxu0d+HbCL45BWnH0gR8VlcW5pyeA99KXxZw82ECbnscd4SqUa4fTU4wmzQSnvVyeNHP
3jRkeVaD4liUxRRzeB5zFO/zZ2znWcL9uAM8G+RQN7uSPdBH3nW7EtbZ1nCvcYfXUS+MrRkLp0yn
YfCeeZ5IJPjUE6lIO5GGgBwyhgb4+T3zEVoXKnZyDxPwZze6OAO4NziKMTLRlP6v/9mDhl3eGPHs
aRjmqSPhUmcPRZ0d5MdsYJljDlmNNZyO2sNljxwyV3u4UuTZGtjm2Orha8cisC4QLlkuIvJRTVGI
bYmF9yJvPfzJNGScykBQbhByunPA8M+eeVb8Hgn480MFuOioZoeMkZNMoSRAFsVl5byE1giqfS4Z
FYkwnzwS9lVjYFNlCavK0TCfYwbrw2Nge9gGssMswlnAc+Rl82QCnlfXYF0w3Ga7DcJPapsE9WI1
0jvSBfwzXc8gOC8Yeb15Aj7/XD5immMeKeC2Uy3NEhRNjiiPkcmmUOkcEUNzPm9gNOUeyCL/zn6G
p0vlfHvIj1jD4pAZRh8aBTMSYHXISsArqhQCnn2NN1lueZ5cD388GOG6cHjO9URcSxwYfvKJyfDP
98fMzpkCPqcrB2GLwgR8wbkCFJ8vpgUy+pEldFNWZSVKgYcjP79mi9S+8WL7WPRRBjb9phDbvyzF
xs/zkX9zGtLPhSKu0x8ONTawOGgBa4J3qJTRHK+3BkZ4o68JOR6C8MZwRNdGI642DkltSQKeI2+E
n9s9F3ldeVjctngQfvnF5Qg5GvLIJm6xJgiHGoogDed6e8S2UVT6I7D1i2I0fLsXjd/uGxy6b/Zg
46eFmN6tReyZQMirHQQ8+xqbbBvY5ZCdmEcOkyLPvobhhTVoIvgqgm/Ww0/rmCbgZ5+eDQFPZbO4
k+BPFaDkfAkY/vlLz8N9n/sjplFaJEbvNoNd9Riqa0sx90+/qMWqG3nDwFlEg3H8cS9W3VyAjL5I
BLV6ibIRpszgKI2mbBCefE38sXgk6ZIw5cSU++AX9C7A4rOLUdhRiJLeEqy4uELArxlYA4ttdATz
iIUs1nTDCNgcsYA9ZYCtQtbVKFT9/jUhoOnb/fjivz/C/9A/fm78437xes3XryP7QjwS20PgedT9
PnijKWNrIOBr78JndmaKyOf25ILhl5xdgsJzBH/iLvzay2vx3LnnHsNK8JkMmTnLw6NEFtgOLLiR
ioav96LhD/vQ/6eTNIPdffD/m0kUj/wPZyC9NxK++7zJWpApqyFTRr6G4SN05GtqCb4qHsm6ZBF5
tgYMn306ezh8XyFKu0uxomcFVl1aBYb/6ZWfIqaBZqBHmjn2qmRZzd40FVlgp5n3ixQ0fEMCbu9F
/38NFzDwpw6CPyBG4c0MZAxMRECtH+1zA6CYRaWUpYT7bJpuc1VIqCdT1po86GuGwi88s1BEfmnf
UpSeL0VZZxlW9d+F33R1E2zo6PLRdpoF0KbBpEwCZ4Ht8ww6bai6/arIQuPX+/G7v3yK/6US+uov
n6Hl27cJvgK1f9hNQmkBOh+NcceD9I7SaMrI1xgdpdGUsa/hyM/rmQeG5/IQ8BcIvpvgz67Cusvr
ROS3vr8V2V3ZT7Ch0Weh3XS3iVh9eeO98uN5OE7N2vg1zUDf7CdwfdQZvvm7Cmz8rBDzP0im6TRc
WIN74Y2O0mjK2NfcC/+TCz9B2dkyrO5ZLeA3Xtko4Le9vw2OP6N98WNvKQ1ZkJZJd0YfNBObl2nv
abH58yJRSk2UheZv9PDc1Du/LBPRnzVAJxFNocMdJZsyssNsDe6FX3RmkYh80fkiMHx5XzlWdxP8
wF34l6+/jPT29KfY1LOIpdJuk00mkFVbIbFvHDKu0EL2q5nY8mkxXv64DFs/KcXyj+ZQ5FOQfWUS
otq0g46SfY3XAi/4LvKF3xI/BOYHDjNlDM/WYBD+nB5+/aX1IvIcdYYv7y+H6To6G6Ijnic7VuHf
Nhxsmb46AooaGW1KApB5JRqzr8VhztUE5J6nI5ILSUg7G4PI1uHwg47SYMrYURpN2VD4ZeeXobyn
HGt61mD9wHB4Lh8n2p4+/cEWi+BTYjreM3vDDC41TvCppz1yqz8iTmoQ2R6M0Cqq9/2h0FaSo2zU
O0r2NewojaZsKLzRlBX3FWNZL8F3Evw5gr+8HjzTcOR3Xt8pou+53/N7Hi0ac8anxEXSd6N+Zi42
32zKBh0lm7L6cERVRiHuHTJl1QSvI/hWcpQdekfJkc/rIUfZTY6yKx/Fpwi+YxlW9q7Emv41ePG9
FwX89mvbBTxHXlVBxyh0ze9/uDtcxC3znebCz7OjNJoy9ujCUbaSo2wkU6YjU1Y3E0FzyXXOoywt
CEX4onAUnCBH2VWM5WeXY2X/Srxw+YX74HnhcnyDZhw+1P2bHa8bRRhucIxYOwKuh11Fw/J5DcMb
HaXRlHHkB00Z+Rq2w0ZTtvLSXfjNVzeLyL90/SVMP0Gb9vW0af9BbnAYRbDV4BmBziotXrGAf63/
ffBGR2k0ZUPh2ZRx5Ddc2QCG33FtB3K7c6F4Q6GfKn/QW0xD5zHDTT4+7rPYYQF1tVqc3dwLX0i+
hiNvdJTsaxieNydspW132upX2L/bTb577/nob7NWiFumdOg0atsouO6lE4nKQFFaPJ2yMJ6VtDVa
+BzwwZgdY4yukm+zVvz/3Ga9V8jQG91LpcYH3ujWv/fD3ej+Mf7Rxz/W30r8GDPwf326/12X7jtk
AAAAAElFTkSuQmCC')
	#endregion
	$button_IPScanner.ImageAlign = 'TopCenter'
	$button_IPScanner.Location = '3, 4'
	$button_IPScanner.Name = 'button_IPScanner'
	$button_IPScanner.Size = '74, 77'
	$button_IPScanner.TabIndex = 0
	$button_IPScanner.Text = 'IP Scanner'
	$button_IPScanner.TextAlign = 'BottomCenter'
	$tooltipinfo.SetToolTip($button_IPScanner, 'IP Scanner')
	$button_IPScanner.UseVisualStyleBackColor = $True
	$button_IPScanner.add_Click($button_IPScanner_Click)
	#
	# button_VNC
	#
	#region Binary Data
	$button_VNC.Image = [System.Convert]::FromBase64String('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')
	#endregion	
	
	$button_VNC.Font = 'Microsoft Sans Serif, 8.25pt'
	$button_VNC.ImageAlign = 'TopCenter'
	$button_VNC.Location = '77, 4'
	$button_VNC.Name = 'button_VNC'
	$button_VNC.Size = '74, 77'
	$button_VNC.TabIndex = 4
	$button_VNC.Text = 'VNC'
	$button_VNC.TextAlign = 'BottomCenter'
	$tooltipinfo.SetToolTip($button_VNC, 'VNC Computer')
	$button_VNC.UseVisualStyleBackColor = $True
	$button_VNC.add_Click($button_VNC_Click)

	#
	# buttonC
	#
	#region Binary Data
	$buttonC.Image = [System.Convert]::FromBase64String('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
jNa7tTOOdvEAAAAASUVORK5CYII=')
	#endregion
	$buttonC.ImageAlign = 'TopCenter'
	$buttonC.Location = '225, 4'
	$buttonC.Name = 'buttonC'
	$buttonC.Size = '74, 77'
	$buttonC.TabIndex = 43
	$buttonC.Text = 'Revention Folder'
	$buttonC.TextAlign = 'BottomCenter'
	$tooltipinfo.SetToolTip($buttonC, 'Open Explorer.exe to the C: Drive')
	$buttonC.UseVisualStyleBackColor = $True
	$buttonC.add_Click($buttonC_Click)
	#
	# button_networkconfig
	#
	$button_networkconfig.Font = 'Microsoft Sans Serif, 8.25pt'
	#region Binary Data
	$button_networkconfig.Image = [System.Convert]::FromBase64String('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')
	#endregion
	$button_networkconfig.ImageAlign = 'TopCenter'
	$button_networkconfig.Location = '151, 4'
	$button_networkconfig.Name = 'button_networkconfig'
	$button_networkconfig.Size = '74, 77'
	$button_networkconfig.TabIndex = 42
	$button_networkconfig.Text = 'IP Config'
	$button_networkconfig.TextAlign = 'BottomCenter'
	$tooltipinfo.SetToolTip($button_networkconfig, 'Get the ip Configuration')
	$button_networkconfig.UseVisualStyleBackColor = $True
	$button_networkconfig.add_Click($button_networkIPConfig_Click)
	#
	# button_Restart
	#
	$button_Restart.Font = 'Microsoft Sans Serif, 8.25pt'
	#region Binary Data
	$button_Restart.Image = [System.Convert]::FromBase64String('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
yulPgf4biUjLzYjxGOQAAAAASUVORK5CYII=')
	#endregion
	$button_Restart.ImageAlign = 'TopCenter'
	$button_Restart.Location = '299, 4'
	$button_Restart.Name = 'button_Restart'
	$button_Restart.Size = '74, 77'
	$button_Restart.TabIndex = 0
	$button_Restart.Text = 'Restart'
	$button_Restart.TextAlign = 'BottomCenter'
	$tooltipinfo.SetToolTip($button_Restart, 'Restart Computer')
	$button_Restart.UseVisualStyleBackColor = $True
	$button_Restart.add_Click($button_Restart_Click)
	#
	# button_Shutdown
	#
	$button_Shutdown.Font = 'Microsoft Sans Serif, 8.25pt'
	#region Binary Data
	$button_Shutdown.Image = [System.Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAAXNSR0IArs4c6QAAAARnQU1BAACx
jwv8YQUAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAEn5JREFU
aEPdmXd0VNW+xwcSqlQREKR3RJqAqCD2Xt69+uyKvVLsgqJcsCBiu/YKiF71KkU6oSQhIb3MTJIJ
SWYyyaRMMpk0IPT2fZ89JNyQGXyu949rvb3Wd52Zc86c8/vs32//9m/vsVj+v7ZJFsvN88eOXbbs
4Ycdv778stPot1mznMtnz3Yuf+UV5/JXX3UunzPHufL1150r5851rjKaN8/5u9H8+c7Vb77pXP3W
W841b7/tXLNggXOt0TvvONcuXBjQ+kWLnOvfe8+5/v33T+iDD/5z5PMGtGLWLMfCyy5bNiks7OY/
3c9nWiy95o0cuTZv8WJVZ2WpxuVSLdrldmt3QYH2eDyqKyrS3pIS7Sst1f6yMh0oL9fBigod9Pt1
qKpKR6qrdaSmRkd37dKx3bt1rK5Ox/fulfbtk/bvlw4ckA4elA4flo4ckY4elY4fP6EQrTY5WYuu
vHKtse0PQcwN30yZklUSGan8HTtk/+03pS5dqlRg0jlav/9e1mXLZP/hB2X8+KMy//UvZf30kxw/
/6zsX37Rzn//Wzt//VW5/C5v+XLlrVgh58qVcq1aJdfvvyt/9Wq516yRe+1aFaxbp4L161WwYYMK
N25U4aZNKoyIkGfzZnm2bAmoODpaFVarDtIJBvqXqVOz2vwBRPhLffuudvHidAyK/fBD7fjgA8V9
9JESPv5YiSjp00+VjFI++0xpn3+utC++UPqXX8r21Veyf/21MlDmN98o89tv5fjuO2UvWaKdgAcE
fA7wucDnAp8HvNOIDnAC7wLeBbwL+HxsMHa4TAdwzAe+kmg4jnfnjh+/Gi+EB3liiMVyXfS0aUqh
t6MXLFDsokXa8d57inv/fSUAkghQEjAp//ynUoFJ++QTpQNjBcYGjB1lAJQJkAOgbGDsXHfw3YRj
DsoFKA+YPGCcwLiAcQGTbwRMPjD5dJ4bIDdAboDcBgg5+V6VkRG4ZmxtCtDsvg4dFie8+aai3n5b
0W+9pRiOsYDseOcdxS9cqIR331UiUMlApQCVitKAsgJlQ3agMoDKxGg737fx20iMj+J7Ar/LBSoX
qDwjvOTEQy6gXEDlA5UPlNsIMDdgbqAKgCoAqsBAGQFRExenxwcMWAxAs8YQbR9t1y5528svK2re
PEX/4x/azjF2/nzteOMNxQEWD1QiUEkYlgJUKlBpQKUjK1A2ZAcqEyUCUl5YGBiOhxmkObGxsnE+
D2/l4SknnjJyAWWUD5CbsDMqACogwAoAKwSqEKhCoDwAFfH9xWHDkjG+bWOALndbLNaVd98dMD7q
1VcVPWeOYl57TbGvv664uXMVx/kEoJKASgYqBag0oNKBsgJlA8oOlI3rvpSUoFySj+tzgXQSgk68
5QIyH+/kA+UGqsAIqEK8VgiUB095APMA5cFbHqBK8Ebmc8/pqQ4drBjfpTFAtzstFtv3l18eMDzy
pZcUPWuWts+erRi045VXFAdUAtcSgUoCKgWoVJQGmBUwG1B2oGxcr2XANW3lZJ0cgJ1AuPBGPuPK
TQi6CbcCoAqBKgTKA5RREWBFQBUBVQRUEVBleCHlrrv0SLNmNozvdgrAXQB8MXKkojB+27PPKgrS
6Oef1/YXXlDsiy8qjvPxhFgiYElApQCVClQaUFZkA8qObFyvtduDAMrIJDnAOvFWPp4qIPQaVAiU
kQewIqCKgSoGqhioEqACAqocTyRcfbUexNYgAELI9lHfvorE+G0zZigSRc+cqZhnnlEsiuN8PFAJ
QCUBlQJUOkBWjnaMtgOVAZSNe2rT04MBSIm5AOfjqWwDz3PMsYgQLAKqiBAsAqwYsBIGvVEpQAHh
LS9QPryxY9w4PRQK4F5Ovte1qzY/8YS2PfmkIlHUU09p+9NPK5b0Gjd9uuKBSgQqBZhErm185BGt
A27D448riXsy8JKN+2rS0oJDiJTo5Ho6hicSGg4mrzQGZyIdUIAHSwi/YlRCmJUC5TUCzAtYGWDl
APmAiKWTHwkFcB8nF3XurI0PPKBtjz6qbRgXxXH7Y48pBgPjAIsDKgmg7dyzid4vIi/XUS6UU2rE
8TIrUHbuqw0xiMsZgDu5bmbmxs2Xl6dExlA+YF5CrBR5+V5GMijHWz6gjPyEWPFDD2l7WJgeDwVw
PyffbddO6+68U1sNBIp68EFFoxh+GPvww4oHKIpMFckD92J441ZHHWTFM3bur01KCvYAve0E/jCz
adO2b8+ewHxSgHfLCTMjH17xMaYqSBR+QPyEaE6XLtphsejJUABTTQi1bas1f/+7tt5zT0CR996r
aBRz//2KmzpV0bffrkgeetAUZCFarhnEZInaxMSgqz5yuosOOFRcHPK35pkZ9HIJIViBdysYV35U
CUwVEEXDh2snxjMB6KnTAbwPwO833aStGGoUiaLuuEMxGBVz223ajAG7Q/SgsWgfYZSJlzK4vzY+
PsjICjPr0hnlZBdTnYZqe6lgs43hQFQSUlUki2o8UTZ5sjwY7kJMAKcH+LBNG6269lpt+dvfAtqG
N6JuvVUxKOLGG+VJSAj54rrsbGUziO2AZgBaSyXbtFUwMbnvu08FeNOLkQdyc0M+y1SfHjqqhnCq
YdBXkDaLMbq0eTPlh4cpo0X46QE+bt1aK6+4Qlsw1mgb3oi6+WZF8pB4wiNUtb4rNVU2xo0N4CyO
mbfcotqYmGAAUqAb73gYW0WEZylJ4kCI+cK8o4j8X00yqOS9pWHNVdoiTGVtW8l9RhtltWurp0JN
ZGZy+KRVK62YMkWbr7kmoK14IwptvvJKlYXI7QdY1JiYt95wgzLwVhaeyrzuOu2ijg/yABNRAfcU
E0aleKIUWB/Z7QgLoqZtF5mp5JLJ8rYMk7d1C3nbt1V553Yq6NJBDjSteYiZ2AB8ZgAuukgRlBSb
0Va8se2SSxRLFjpiVk+NG6snpykpLrtMNryVgbey8FYmsLtCeKDSlArcU4IXSpEX8DLjLfJ705XY
UVZonokT5A2zqKxze5VhtK97ZxX2OFM5aFpY8+CZ+GEAvgRg+fjximDQbEZbMX4LM5+Dqbxpq9u5
UylApl11lWx4KwNPZdH7WZdeKj8Z5xRWDPIyMIvwVAmh5sUTZXjLhyr4fJgeD/LYa6/IG25RebdO
8vXoooreXVXUp5ty0fTwEABPAPB1y5ZaPmaMNk2cqAi05cILFTFqlLws75q2YmI6CTgrEHaUibcc
9H42xzwMraF0OOzz6RDraD+zqQfQYs6X4gUvnvLR+xXIT5zvY5Jr2vasWqnSM1rI1xPjMdo/oIeK
B50j58CemhEeFuwBk1u/NQDnnaeN55+vCLRl7Fht5VhjswW9IIdJKZlr1kmTZMdbmYwdB9pJSOVw
zL34Yrmvv14FGFjA9SKOJXjKi6fK8VQF1yqBqQS4hrHQtB1ISlR5zzPl69NVFRhdOaSXSob3Uf6w
3gCEBwPMBGBxixZaMXSoNlKVRqDNwEQSUnXsSJwa/sflIJOk4B3rBRfIhrcy8ZaD8bMTw3OBcmK0
i6Pb5HDCqhiwUjxVhsE+vOEHpILfeDt2UMWE86Vjx055x2FnniqG9FFF/+7yD+2tqhF95R3VX+6R
/TWjZQiA5816IDxcKwYO1MZhw7QJRQwZokiM3Msk1bgd42UmZSYzO1rxkp1QyjRjBdidEyYoFygX
UG4MLASqCKgSYLx4phwQH9fKevUiPYarhBxfcfFEHW8CcCQvV/5hfVUxiN4/t5+qRg9U2fmDVThm
kGaGApgFwA8ALKfa22AgUMSAAdqCmhZnJlebWTeZa+l4ygZk5ujRymb85KA8oFyElxuoQqCKMLgE
mFKulZ5zjkp4jzHc26qFSpuRaW65KWiOOZycKD/G+wmbylEDVI3xvglD5Rk3RDNbhfDAHAB+bN5c
y3v00Po+fbQRRQCz6ayzVNakgjTecJttFu614ik7ysIbjnPPVc6IEcoj9FxAuQHxYLQHT3oo1T1U
kkUYXtKsmUox3ntG6wCIf+GC4DGwegWDtwvG91cVxldfMEz+i85V8cThmtk6BMBcAH4GYCUvWo9h
G1FEz57a1KGDcll4NG21pNG4fv1kRfZBg5Q1eLCyMTQHmDxgXJxz8fv8M85QPkYWoJPGEzreNq0C
s2tBp3aqy3YEp+n5c+Tv11VVYwepip6vwfjKyeep5OIRALQMHsRvAvCLAWBNsI5e3wBIRLduiujY
UQm4/5jZDmzUTBjZqX+SuZ4BRCZyENfZ/DYbo3fyrNz6AszN0RRjgZrGlAb0flm7NoHe9zz+SFD4
HD94QDU3XKbK4b1URchUTxymmkkjVH0pKf2SkaEB3gHgNwPQvr3WYNT6Tp20CZjNaAtVqp8VVNO2
lz3RHYRNKjFtIwXbCI1MjHKgHJSHTO8XntL7lAf0vrc5188dqv3lwaXEoW2b5R/c82TvV9P7NRhe
e/kYlQMxs00ID7wHwAoDQEG3Gq2jMt2ANmH8JgxIJXscN5uwTVoVq6/t3bsH6nRjfBbKRqb3neiU
3uf5ZS1bBDyR06+3dtusQc8z6bT2vtvkH9KjvveHq5rer8HwXVeeLz8Qz4cC+BCAVTx4OTLHNWg9
2ogi6mV2BkK1XZTTSaTJBO7LaGR8Q+8HQqc+hAxU7hWXqy43J+Sz9v/0PbMusU+6NLFffSG9T+zX
XDZau68epyogXgoF8AkAxugV6He0Fm1Apvc3o61oO7G9J8Ry0VhylGKviEVLGuMlxYRUvUeMN8xK
KptzuRdfpHLqpKNmSz1EO5xpU+XowaROJq76zFPNoG0In93XjlctELPbtAoexF8CYHp8JWL79xSA
LXyPRNtQInl8L4v50zUzuHc7HCqjvilmO6QE+fhcx7nQu/8nnnQEj1RdPFb+gd1VaXo/MHiHM3jp
/SmjVHvFWBmAXdeM15xQAN8CYMKlAWBdo/BpAIjmnFEyELtD1PynpfpfLhxKjFflBaNO5P3zyPuj
/wNQbQAuHa1aQmf3dRNUd+0EzQ0FsAQAE+sN8d8YwISP8cB2FIvMzkASA93LbsFRdhT+r+343jrt
/ej9QLFW0fvME7OuATAeGI8HLsQDk0cG4r8BYB8Qb4QC+KVlS/tW4rTxAG4c/w0AxngzWBPrlc2s
W8Um7NHTLPZDwR2rrtK+ZUtVOeVClXdsjfFnkTZ7nQSoHDOw0QCuB7jqhAf233iRFnRsb2+6tdj1
97Ztk+OZuMwgNgO4IQOZAWxiPwrF1Pd+vPEASq1XuhmozLolLBdr2U3ezx7+YSrYY+wyGB3h86H4
OO1jy7zm4QflG0ph1iacZWJb+VioVPTv0QSgcQZq5IFrxmnf7Vfr7fbtzPZ614bN3TA+dFrYrNnS
Ygqy5eTqphnIAJjYbwAwHmgAMNscdEcgfZp5wGSdQP5nDvEwGZagUuYSMwObmdekU2+71irvemKl
5etlAM4+BeBkCJlBXJ9CzSCuu/FCVd1xk6Ziq7EZGdstzdEZIy2WB/YMHnw0hurRpFGTQs2YMAO4
MUBcfQg1BWg8AxsAs4fTMIkFDGdbxNumZWCBbta5JwECHgCA1ZafxcopY+BkFmIWnjJCB595QKmj
Rhztia3G5nrbA45oiUYsat5s7aEbrtf2SZO1jrLAZKWGOcCEkBnEZgyYEDJjIAWZ8DE533jAlBAm
5zeUECcLOANA2exle8RLAVfWoU1gl6G8K4t1FulmvXvCC9T+zAGVLFqqGAfV46lCJwwOpNH9Lz6m
2ntuF2t3AsQyot7mk38RmP+buuKPm39r18Z6+Nb/kuP+qYqhpo+iTIimHortfKbiUCJKRqkoHdlR
JnKgHJSHXMiNClExKu3cRV6KQ2+P7irr3VPl/XvLN7iffMMHquK8IfKPGS7/+PNUOXGkqiaNUdWU
caq+fIJqr5+sPY/eqUML5mjP3f+tt8PCrMbG+vg/5T+yBi8M4MOd81qHb6qcOPbg/oemskM2XVUz
pqkG1aLdfN+D6tA+tB8dQAfRIXSYe46gY0bTp0nTn5amIXPkup6ZIT2Lnp8pvfCM9OKz0kvPSbOe
l2a/IL36kvTay9Lc2dLrs3Tk0QflGD704GMWC0nRwh9JFmOjiZiQrTVnB6Lr+1ksc2e0a73mu95d
MxYP6OVYMqiXY/HgPo4lQ/o6lgxtpGGNPptr5h7uXWJ+0/8cx5J+PR1L+/RwLO3VzbG0Jzr7LMfS
bl0cS7t0cizt1NGxtGN7x9K2bR2L0bfoK/Q5+hR9EB6ewa75mrOxxdhUb5ux8Q9bC66a/59Go6vR
bYh/oP4SmXcbG4wtxiZj259qJr5aoU6oOzrnL5J5t7HB2BIU83+GxKRYQ21i7q+Qebex4bTtfwBd
yOl5co93qgAAAABJRU5ErkJggg==')

	#endregion
	$button_Shutdown.ImageAlign = 'TopCenter'
	$button_Shutdown.Location = '373, 4'
	$button_Shutdown.Name = 'button_Shutdown'
	$button_Shutdown.Size = '74, 77'
	$button_Shutdown.TabIndex = 1
	$button_Shutdown.Text = 'Shutdown'
	$button_Shutdown.TextAlign = 'BottomCenter'
	$tooltipinfo.SetToolTip($button_Shutdown, 'Shutdown Computer')
	$button_Shutdown.UseVisualStyleBackColor = $True
	$button_Shutdown.add_Click($button_Shutdown_Click)
	#
	#
	#Tabpage_Database
	$tabpage_Database.Controls.Add($groupbox_POSSettings)
	$tabpage_Database.Controls.Add($groupbox_POSAudit)
	$tabpage_Database.Location = '4, 22'
	$tabpage_Database.Name = 'tabpage_Database'
	$tabpage_Database.Size = '1162, 111'
	$tabpage_Database.TabIndex = 10
	$tabpage_Database.Text = 'Database'
	$tabpage_Database.UseVisualStyleBackColor = $True
		
	#
	# groupbox_POSsetting
	#
	$groupbox_POSSettings.Controls.Add($button_DbPrinters)
	$groupbox_POSSettings.Controls.Add($button_BusinessInfo)
	$groupbox_POSSettings.Controls.Add($button_DBStages)

	$groupbox_POSSettings.Location = '2, 1'
	$groupbox_POSSettings.Name = 'groupbox_POSSetting'
	$groupbox_POSSettings.Size = '204, 102'
	$groupbox_POSSettings.TabIndex = 59
	$groupbox_POSSettings.TabStop = $False
	$groupbox_POSSettings.Text = 'POS Settings'
	#
	# button_BusinessInfo
	#
	$button_BusinessInfo.Location = '6, 19'
	$button_BusinessInfo.Name = 'button_BusinessInfo'
	$button_BusinessInfo.Size = '93, 23'
	$button_BusinessInfo.TabIndex = 51
	$button_BusinessInfo.Text = 'Business Info'
	$button_BusinessInfo.UseVisualStyleBackColor = $True
	$button_BusinessInfo.add_Click($button_BusinessInfo_Click)


	# button_DbPrinters
	#
	$button_DbPrinters.Location = '6, 45'
	$button_DbPrinters.Name = 'button_DbPrinters'
	$button_DbPrinters.Size = '93, 23'
	$button_DbPrinters.TabIndex = 51
	$button_DbPrinters.Text = 'DB Printers'
	$button_DbPrinters.UseVisualStyleBackColor = $True
	$button_DbPrinters.add_Click($button_DbPrinters_Click)
	#
	# button_DBStages
	#
	$button_DBStages.Location = '106, 19'
	$button_DBStages.Name = 'button_DBStages'
	$button_DBStages.Size = '93, 23'
	$button_DBStages.TabIndex = 51
	$button_DBStages.Text = 'DB Stages'
	$button_DBStages.UseVisualStyleBackColor = $True
	$button_DBStages.add_Click($button_DBStages_Click)
	#

	# groupbox_POSAudit
	#
	$groupbox_POSAudit.Controls.Add($button_OrderHistory)
	$groupbox_POSAudit.Controls.Add($button_CCBatch)
	$groupbox_POSAudit.Controls.Add($button_SyncRecords)
	$groupbox_POSAudit.Controls.Add($button_TotalSyncRecords)


	$groupbox_POSAudit.Location = '352, 1'
	$groupbox_POSAudit.Name = 'groupbox_POSAudit'
	$groupbox_POSAudit.Size = '204, 102'
	$groupbox_POSAudit.TabIndex = 59
	$groupbox_POSAudit.TabStop = $False
	$groupbox_POSAudit.Text = 'POS Audit'
	#
	# button_SyncRecords
	#
	$button_SyncRecords.Location = '6, 19'
	$button_SyncRecords.Name = 'button_SyncRecords'
	$button_SyncRecords.Size = '93, 23'
	$button_SyncRecords.TabIndex = 51
	$button_SyncRecords.Text = 'Sync Records'
	$button_SyncRecords.UseVisualStyleBackColor = $True
	$button_SyncRecords.add_Click($button_SyncRecords_Click)

	# button_TotalSyncRecords
	#
	$button_TotalSyncRecords.Location = '6, 45'
	$button_TotalSyncRecords.Name = 'button_TotalSyncRecords'
	#endregion
	$button_TotalSyncRecords.Size = '93, 23'
	$button_TotalSyncRecords.TabIndex = 51
	$button_TotalSyncRecords.Text = 'Sync Summary'
	$button_TotalSyncRecords.UseVisualStyleBackColor = $True
	$button_TotalSyncRecords.add_Click($button_TotalSyncRecords_Click)

	# button_CC Batch
	#
	$button_CCBatch.Location = '106, 19'
	$button_CCBatch.Name = 'button_CCBatch'
	$button_CCBatch.Size = '93, 23'
	$button_CCBatch.TabIndex = 51
	$button_CCBatch.Text = 'CC Batch'
	$button_CCBatch.UseVisualStyleBackColor = $True
	$button_CCBatch.add_Click($button_CCBatch_Click)

	# button_OrderHistory
	#
	$button_OrderHistory.Location = '106, 45'
	$button_OrderHistory.Name = 'button_OrderHistory'
	$button_OrderHistory.Size = '93, 23'
	$button_OrderHistory.TabIndex = 51
	$button_OrderHistory.Text = 'Order#'
	$button_OrderHistory.UseVisualStyleBackColor = $True
	$button_OrderHistory.add_Click($button_OrderHistory_Click)

	#region Tabpage_Services#############################

	$tabpage_services.Controls.Add($button_mmcServices)
	$tabpage_services.Controls.Add($button_HRServices)
	$tabpage_services.Controls.Add($button_servicesAutoNotStarted)

	$tabpage_services.Controls.Add($groupbox_RevCtrl)
	$tabpage_services.Controls.Add($groupbox_RevCloud)
	$tabpage_services.Controls.Add($groupbox_RevPrinterServer)
	$tabpage_services.Controls.Add($groupbox_PrinterSpooler)


	$tabpage_Services.Location = '4, 50'
	$tabpage_Services.Name = 'tabpage_Services'
	$tabpage_Services.Size = '1162, 111'
	$tabpage_Services.TabIndex = 10
	$tabpage_Services.Text = 'Local Services'
	$tabpage_Services.UseVisualStyleBackColor = $True

	# button_mmcServices
	#
	$button_mmcServices.ForeColor = 'ForestGreen'
	$button_mmcServices.Location = '10, 8'
	$button_mmcServices.Name = 'button_mmcServices'
	$button_mmcServices.Size = '125, 23'
	$button_mmcServices.TabIndex = 0
	$button_mmcServices.Text = 'MMC: Services.msc'
	$tooltipinfo.SetToolTip($button_mmcServices, 'Launch Services.msc')
	$button_mmcServices.UseVisualStyleBackColor = $True
	$button_mmcServices.add_Click($button_mmcServices_Click)

	# button_HRServices
	#
	$button_HRServices.Location = '10, 31'
	$button_HRServices.Name = 'button_HRServices'
	$button_HRServices.Size = '125, 23'
	$button_HRServices.TabIndex = 0
	$button_HRServices.Text = 'HungerRush Services'
	$button_HRServices.add_Click($button_HRServices_Click)

	# button_servicesAutoNotStarted
	#
	$button_servicesAutoNotStarted.Location = '10, 54'
	$button_servicesAutoNotStarted.Name = 'button_servicesAutoNotStarted'
	$button_servicesAutoNotStarted.Size = '125, 23'
	$button_servicesAutoNotStarted.TabIndex = 9
	$button_servicesAutoNotStarted.Text = 'Auto & NOT Running'
	$tooltipinfo.SetToolTip($button_servicesAutoNotStarted, 'Services with StartupType "Automatic" and Status different of "Running"')
	$button_servicesAutoNotStarted.UseVisualStyleBackColor = $True
	$button_servicesAutoNotStarted.add_Click($button_servicesAutoNotStarted_Click)


	#region GroupBox_RevCtrl
	#GroupBox_RevCtrl
	$groupbox_RevCtrl.Controls.Add($button_RevControlSvcStart)
	$groupbox_RevCtrl.Controls.Add($button_RevControlSvcStop)
	$groupbox_RevCtrl.Controls.Add($button_RevControlSvcRestart)
	$groupbox_RevCtrl.Location = '170, 1'
	$groupbox_RevCtrl.Name = 'groupbox_RevCtrl'
	$groupbox_RevCtrl.Size = '75, 102'
	$groupbox_RevCtrl.TabIndex = 59
	$groupbox_RevCtrl.TabStop = $False
	$groupbox_RevCtrl.Text = 'RevControl'
	# button_RevControlSvcRestart
	#
	$button_RevControlSvcRestart.Font = 'Microsoft Sans Serif, 8.25pt, style=Bold'
	$button_RevControlSvcRestart.Location = '10, 20'
	$button_RevControlSvcRestart.Name = 'button_RevControlSvcRestart'
	$button_RevControlSvcRestart.Size = '55, 23'
	$button_RevControlSvcRestart.TabIndex = 10
	$button_RevControlSvcRestart.Text = 'Restart'
	$tooltipinfo.SetToolTip($button_RevControlSvcRestart, 'Restart the service specified')
	$button_RevControlSvcRestart.UseVisualStyleBackColor = $True
	$button_RevControlSvcRestart.add_Click($button_RevControlSvcRestart_Click)
	# button_RevControlSvcStart
	#
	$button_RevControlSvcStart.Font = 'Microsoft Sans Serif, 8.25pt, style=Bold'
	$button_RevControlSvcStart.ForeColor = 'DarkBlue'
	$button_RevControlSvcStart.Location = '10, 47'
	$button_RevControlSvcStart.Name = 'button_RevControlSvcStart'
	$button_RevControlSvcStart.Size = '55, 23'
	$button_RevControlSvcStart.TabIndex = 6
	$button_RevControlSvcStart.Text = 'Start'
	$tooltipinfo.SetToolTip($button_RevControlSvcStart, 'Start the service specified')
	$button_RevControlSvcStart.UseVisualStyleBackColor = $True
	$button_RevControlSvcStart.add_Click($button_RevControlSvcStart_Click)
	# button_RevControlSvcStop
	#
	$button_RevControlSvcStop.Font = 'Microsoft Sans Serif, 8.25pt, style=Bold'
	$button_RevControlSvcStop.ForeColor = 'Red'
	$button_RevControlSvcStop.Location = '10, 74'
	$button_RevControlSvcStop.Name = 'button_RevControlSvcStop'
	$button_RevControlSvcStop.Size = '55, 23'
	$button_RevControlSvcStop.TabIndex = 5
	$button_RevControlSvcStop.Text = 'Stop'
	$tooltipinfo.SetToolTip($button_RevControlSvcStop, 'Stop the service specified')
	$button_RevControlSvcStop.UseVisualStyleBackColor = $True
	$button_RevControlSvcStop.add_Click($button_RevControlSvcStop_Click)
	#endregion

	#region GroupBox_RevCloud
	#GroupBox_RevCloud
	$groupbox_RevCloud.Controls.Add($button_RevCloudSvcStart)
	$groupbox_RevCloud.Controls.Add($button_RevCloudSvcStop)
	$groupbox_RevCloud.Controls.Add($button_RevCloudSvcRestart)
	$groupbox_RevCloud.Location = '260, 1'
	$groupbox_RevCloud.Name = 'groupbox_RevCloud'
	$groupbox_RevCloud.Size = '75, 102'
	$groupbox_RevCloud.TabIndex = 59
	$groupbox_RevCloud.TabStop = $False
	$groupbox_RevCloud.Text = 'RevCloud'
	# button_RevCloudSvcRestart
	#
	$button_RevCloudSvcRestart.Font = 'Microsoft Sans Serif, 8.25pt, style=Bold'
	$button_RevCloudSvcRestart.Location = '10, 20'
	$button_RevCloudSvcRestart.Name = 'button_RevCloudSvcRestart'
	$button_RevCloudSvcRestart.Size = '55, 23'
	$button_RevCloudSvcRestart.TabIndex = 10
	$button_RevCloudSvcRestart.Text = 'Restart'
	$tooltipinfo.SetToolTip($button_RevCloudSvcRestart, 'Restart the service specified')
	$button_RevCloudSvcRestart.UseVisualStyleBackColor = $True
	$button_RevCloudSvcRestart.add_Click($button_RevCloudSvcRestart_Click)
	# button_RevCloudSvcStart
	#
	$button_RevCloudSvcStart.Font = 'Microsoft Sans Serif, 8.25pt, style=Bold'
	$button_RevCloudSvcStart.ForeColor = 'DarkBlue'
	$button_RevCloudSvcStart.Location = '10, 47'
	$button_RevCloudSvcStart.Name = 'button_RevCloudSvcStart'
	$button_RevCloudSvcStart.Size = '55, 23'
	$button_RevCloudSvcStart.TabIndex = 6
	$button_RevCloudSvcStart.Text = 'Start'
	$tooltipinfo.SetToolTip($button_RevCloudSvcStart, 'Start the service specified')
	$button_RevCloudSvcStart.UseVisualStyleBackColor = $True
	$button_RevCloudSvcStart.add_Click($button_RevCloudSvcStart_Click)
	# button_RevCloudSvcStop
	#
	$button_RevCloudSvcStop.Font = 'Microsoft Sans Serif, 8.25pt, style=Bold'
	$button_RevCloudSvcStop.ForeColor = 'Red'
	$button_RevCloudSvcStop.Location = '10, 74'
	$button_RevCloudSvcStop.Name = 'button_RevCloudSvcStop'
	$button_RevCloudSvcStop.Size = '55, 23'
	$button_RevCloudSvcStop.TabIndex = 5
	$button_RevCloudSvcStop.Text = 'Stop'
	$tooltipinfo.SetToolTip($button_RevCloudSvcStop, 'Stop the service specified')
	$button_RevCloudSvcStop.UseVisualStyleBackColor = $True
	$button_RevCloudSvcStop.add_Click($button_RevCloudSvcStop_Click)
	#endregion

	#region GroupBox_RevPrinterServer
	#GroupBox_RevPrinterServer
	$groupbox_RevPrinterServer.Controls.Add($button_RevPrinterServerSvcStart)
	$groupbox_RevPrinterServer.Controls.Add($button_RevPrinterServerSvcStop)
	$groupbox_RevPrinterServer.Controls.Add($button_RevPrinterServerSvcRestart)
	$groupbox_RevPrinterServer.Location = '350, 1'
	$groupbox_RevPrinterServer.Name = 'groupbox_RevPrinterServer'
	$groupbox_RevPrinterServer.Size = '85, 102'
	$groupbox_RevPrinterServer.TabIndex = 59
	$groupbox_RevPrinterServer.TabStop = $False
	$groupbox_RevPrinterServer.Text = 'Printer Server'
	# button_RevPrinterServerSvcRestart
	#
	$button_RevPrinterServerSvcRestart.Font = 'Microsoft Sans Serif, 8.25pt, style=Bold'
	$button_RevPrinterServerSvcRestart.Location = '15, 20'
	$button_RevPrinterServerSvcRestart.Name = 'button_RevPrinterServerSvcRestart'
	$button_RevPrinterServerSvcRestart.Size = '55, 23'
	$button_RevPrinterServerSvcRestart.TabIndex = 10
	$button_RevPrinterServerSvcRestart.Text = 'Restart'
	$tooltipinfo.SetToolTip($button_RevPrinterServerSvcRestart, 'Restart the service specified')
	$button_RevPrinterServerSvcRestart.UseVisualStyleBackColor = $True
	$button_RevPrinterServerSvcRestart.add_Click($button_RevPrinterServerSvcRestart_Click)
	# button_RevPrinterServerSvcStart
	#
	$button_RevPrinterServerSvcStart.Font = 'Microsoft Sans Serif, 8.25pt, style=Bold'
	$button_RevPrinterServerSvcStart.ForeColor = 'DarkBlue'
	$button_RevPrinterServerSvcStart.Location = '15, 47'
	$button_RevPrinterServerSvcStart.Name = 'button_RevPrinterServerSvcStart'
	$button_RevPrinterServerSvcStart.Size = '55, 23'
	$button_RevPrinterServerSvcStart.TabIndex = 6
	$button_RevPrinterServerSvcStart.Text = 'Start'
	$tooltipinfo.SetToolTip($button_RevPrinterServerSvcStart, 'Start the service specified')
	$button_RevPrinterServerSvcStart.UseVisualStyleBackColor = $True
	$button_RevPrinterServerSvcStart.add_Click($button_RevPrinterServerSvcStart_Click)
	# button_RevPrinterServerSvcStop
	#
	$button_RevPrinterServerSvcStop.Font = 'Microsoft Sans Serif, 8.25pt, style=Bold'
	$button_RevPrinterServerSvcStop.ForeColor = 'Red'
	$button_RevPrinterServerSvcStop.Location = '15, 74'
	$button_RevPrinterServerSvcStop.Name = 'button_RevPrinterServerSvcStop'
	$button_RevPrinterServerSvcStop.Size = '55, 23'
	$button_RevPrinterServerSvcStop.TabIndex = 5
	$button_RevPrinterServerSvcStop.Text = 'Stop'
	$tooltipinfo.SetToolTip($button_RevPrinterServerSvcStop, 'Stop the service specified')
	$button_RevPrinterServerSvcStop.UseVisualStyleBackColor = $True
	$button_RevPrinterServerSvcStop.add_Click($button_RevPrinterServerSvcStop_Click)
	#endregion

	#region GroupBox_PrinterSpooler
	#GroupBox_PrinterSpooler
	$groupbox_PrinterSpooler.Controls.Add($button_PrinterSpoolerSvcStart)
	$groupbox_PrinterSpooler.Controls.Add($button_PrinterSpoolerSvcStop)
	$groupbox_PrinterSpooler.Controls.Add($button_PrinterSpoolerSvcRestart)
	$groupbox_PrinterSpooler.Location = '455, 1'
	$groupbox_PrinterSpooler.Name = 'groupbox_PrinterSpooler'
	$groupbox_PrinterSpooler.Size = '85, 102'
	$groupbox_PrinterSpooler.TabIndex = 59
	$groupbox_PrinterSpooler.TabStop = $False
	$groupbox_PrinterSpooler.Text = 'Printer Spool'
	# button_PrinterSpoolerSvcRestart
	#
	$button_PrinterSpoolerSvcRestart.Font = 'Microsoft Sans Serif, 8.25pt, style=Bold'
	$button_PrinterSpoolerSvcRestart.Location = '15, 20'
	$button_PrinterSpoolerSvcRestart.Name = 'button_PrinterSpoolerSvcRestart'
	$button_PrinterSpoolerSvcRestart.Size = '55, 23'
	$button_PrinterSpoolerSvcRestart.TabIndex = 10
	$button_PrinterSpoolerSvcRestart.Text = 'Restart'
	$tooltipinfo.SetToolTip($button_PrinterSpoolerSvcRestart, 'Restart the service specified')
	$button_PrinterSpoolerSvcRestart.UseVisualStyleBackColor = $True
	$button_PrinterSpoolerSvcRestart.add_Click($button_PrinterSpoolerSvcRestart_Click)
	# button_PrinterSpoolerSvcStart
	#
	$button_PrinterSpoolerSvcStart.Font = 'Microsoft Sans Serif, 8.25pt, style=Bold'
	$button_PrinterSpoolerSvcStart.ForeColor = 'DarkBlue'
	$button_PrinterSpoolerSvcStart.Location = '15, 47'
	$button_PrinterSpoolerSvcStart.Name = 'button_PrinterSpoolerSvcStart'
	$button_PrinterSpoolerSvcStart.Size = '55, 23'
	$button_PrinterSpoolerSvcStart.TabIndex = 6
	$button_PrinterSpoolerSvcStart.Text = 'Start'
	$tooltipinfo.SetToolTip($button_PrinterSpoolerSvcStart, 'Start the service specified')
	$button_PrinterSpoolerSvcStart.UseVisualStyleBackColor = $True
	$button_PrinterSpoolerSvcStart.add_Click($button_PrinterSpoolerSvcStart_Click)
	# button_PrinterSpoolerSvcStop
	#
	$button_PrinterSpoolerSvcStop.Font = 'Microsoft Sans Serif, 8.25pt, style=Bold'
	$button_PrinterSpoolerSvcStop.ForeColor = 'Red'
	$button_PrinterSpoolerSvcStop.Location = '15, 74'
	$button_PrinterSpoolerSvcStop.Name = 'button_PrinterSpoolerSvcStop'
	$button_PrinterSpoolerSvcStop.Size = '55, 23'
	$button_PrinterSpoolerSvcStop.TabIndex = 5
	$button_PrinterSpoolerSvcStop.Text = 'Stop'
	$tooltipinfo.SetToolTip($button_PrinterSpoolerSvcStop, 'Stop the service specified')
	$button_PrinterSpoolerSvcStop.UseVisualStyleBackColor = $True
	$button_PrinterSpoolerSvcStop.add_Click($button_PrinterSpoolerSvcStop_Click)
	#endregion

	#endregion    
	#
	# textbox_pingparam
	#
	$textbox_pingparam.Location = '84, 29'
	$textbox_pingparam.Name = 'textbox_pingparam'
	$textbox_pingparam.Size = '34, 20'
	$textbox_pingparam.TabIndex = 1
	$textbox_pingparam.Text = '-t'
	#
	#
	# groupbox_ComputerName
	#
	$groupbox_ComputerName.Controls.Add($label_UptimeStatus)
	$groupbox_ComputerName.Controls.Add($textbox_computername)
	$groupbox_ComputerName.Controls.Add($button_Check)
	$groupbox_ComputerName.Controls.Add($label_PingStatus)
	$groupbox_ComputerName.Controls.Add($label_Ping)
	$groupbox_ComputerName.Controls.Add($label_POSStatus)
	$groupbox_ComputerName.Controls.Add($label_POS)
	$groupbox_ComputerName.Controls.Add($label_RevControlStatus)
	$groupbox_ComputerName.Controls.Add($label_RevControl)
	$groupbox_ComputerName.Controls.Add($label_RevcloudStatus)
	$groupbox_ComputerName.Controls.Add($label_Revcloud)
	$groupbox_ComputerName.Controls.Add($label_HRUpdateStatus)
	$groupbox_ComputerName.Controls.Add($label_HRUpdate)
	$groupbox_ComputerName.Controls.Add($label_RevScreenMgrStatus)
	$groupbox_ComputerName.Controls.Add($label_RevScreenMgr)
	$groupbox_ComputerName.Controls.Add($label_RevMonStatus)
	$groupbox_ComputerName.Controls.Add($label_RevMon)
	

	$groupbox_ComputerName.Dock = 'Top'
	$groupbox_ComputerName.Location = '0, 26'
	$groupbox_ComputerName.Name = 'groupbox_ComputerName'
	$groupbox_ComputerName.Size = '1170, 61'
	$groupbox_ComputerName.TabIndex = 62
	$groupbox_ComputerName.TabStop = $False
	$groupbox_ComputerName.Text = 'ComputerName'
	#
	# textbox_computername
	#
	$textbox_computername.AutoCompleteMode = 'SuggestAppend'
	$textbox_computername.AutoCompleteSource = 'CustomSource'
	$textbox_computername.BackColor = 'LemonChiffon'
	$textbox_computername.BorderStyle = 'FixedSingle'
	$textbox_computername.CharacterCasing = 'Upper'
	$textbox_computername.Font = 'Consolas, 18pt'
	$textbox_computername.ForeColor = 'WindowText'
	$textbox_computername.Location = '6, 14'
	$textbox_computername.Name = 'textbox_computername'
	$textbox_computername.Size = '120, 36'
	$textbox_computername.TabIndex = 2
	$textbox_computername.Text = 'LOCALHOST'
	$textbox_computername.TextAlign = 'Center'
	$tooltipinfo.SetToolTip($textbox_computername, 'Please enter a Computer name')
	$textbox_computername.add_TextChanged($textbox_computername_TextChanged)
	$textbox_computername.add_KeyPress($textbox_computername_KeyPress)
	#
	# button_Check
	#
	$button_Check.Font = 'Microsoft Sans Serif, 8.25pt, style=Bold'
	#region Binary Data
	$button_Check.Image = [System.Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABGdBTUEAAK/INwWK6QAAABl0RVh0
U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAAKsSURBVDhPpZPrS5NRHMf9O/Zse0xBAhlR
iCAh1F4FicSm2VDMy7I03d0rbTOGzbQoI+dljJTSMkutNufMpk5tbk0pE5c9Soi5N12oNowu9u08
D7RpQS/qxRfOi/P5/M45v9+JAxD3P/kDLvIdSMyf2a/P9aQxWY/2hiUPRWGJK5mROJP1mfbdib8X
2yEo8KZLZZ7UkM4jw/WgBQMrPVy6l1pR5joCcT8dEvfR0u2SqIBUlWZPpEQuzxvhXBuE7cUVmOar
ubBrx9oAmmdrsM8miKTaBFEJJ8jzpCVku1M2WJjdWBeoQJW/DJrZU9CRVJLU+k7D/uoOzk9XQWTh
b4iu8hNYlhPI3CkG1XgOV5mFWVDlPQHFTDEU00VQTxfDvT4Mg1cJB5Hk9x1C0iW+ISrIeihiuoOt
sAZbUOUrhfKxnICFUE6ReAox8dpF9gKhyDo6njXDNt+M+EY+ExUctidt3lu9ifqABlpvCTnJEJbe
L0A1WYzx9REO/r71DR1PL8AwWYqBYDeERmozKhDfpTcHV3ph9KtQ79fi45cPHPTu85sobJlrhNqV
C737JAaDXRDWbRf00cy1hRZ0Ll6EbkoOs68Wka+fOHjrxxYsT86hwpkDDRG0BRrQ6TWDrqFiV0i/
ITTIhzJgX72N2kk51O7jaJipxPLbRXTMNaF8+CgUjmPQOfNgf9mLTOtB0NVU7BFTrYKEPaQ1Zo8G
95lbqB4rgHY0D6oRGZQONiyciwfLPTCOlEKo5m3QairWRvYxklv40vgmKmJyV8BBJO0BM/RjJTgz
Kkc7uYKdwHpnCQTlvAiBdw7Sr9Hc1cSX0iYqJOkSo9NvRv9zK/oXrLB4TchoS4dQwQvRqhgc7cL2
2abP8hNpA6Wn6yhGqOWFhSpemFRkSPR0OfX3z/Qv3/onZ9Cs5bE2LHMAAAAASUVORK5CYII=')
	#endregion
	$button_Check.ImageAlign = 'MiddleLeft'
	$button_Check.Location = '132, 15'
	$button_Check.Name = 'button_Check'
	$button_Check.Size = '76, 35'
	$button_Check.TabIndex = 51
	$button_Check.Text = 'Check'
	$tooltipinfo.SetToolTip($button_Check, 'Check the connectivity and basic information')
	$button_Check.UseVisualStyleBackColor = $True
	$button_Check.add_Click($button_Check_Click)
	#
	# label_PingStatus
	#
	$label_PingStatus.Location = '249, 18'
	$label_PingStatus.Name = 'label_PingStatus'
	$label_PingStatus.Size = '33, 16'
	$label_PingStatus.TabIndex = 50
	#
	# label_Ping
	#
	$label_Ping.Font = 'Trebuchet MS, 8.25pt, style=Underline'
	$label_Ping.Location = '213, 16'
	$label_Ping.Name = 'label_Ping'
	$label_Ping.Size = '33, 16'
	$label_Ping.TabIndex = 49
	$label_Ping.Text = 'Ping:'
	#
	# label_POSStatus
	#
	$label_POSStatus.Location = '249, 35'
	$label_POSStatus.Name = 'label_POSStatus'
	$label_POSStatus.Size = '40, 14'
	$label_POSStatus.TabIndex = 57
	#
	# label_POS
	#
	$label_POS.Font = 'Trebuchet MS, 8.25pt, style=Underline'
	$label_POS.Location = '213, 32'
	$label_POS.Name = 'label_POS'
	$label_POS.Size = '81, 20'
	$label_POS.TabIndex = 55
	$label_POS.Text = 'POS:'
	####################################################################
	#
	# label_RevControlStatus
	#
	$label_RevControlStatus.Location = '365, 35'
	$label_RevControlStatus.Name = 'label_RevControlStatus'
	$label_RevControlStatus.Size = '40, 18'
	$label_RevControlStatus.TabIndex = 53
	#
	# label_RevControl
	#
	$label_RevControl.Font = 'Trebuchet MS, 8.25pt, style=Underline'
	$label_RevControl.Location = '295, 33'
	$label_RevControl.Name = 'label_RevControl'
	$label_RevControl.Size = '80, 20'
	$label_RevControl.TabIndex = 52
	$label_RevControl.Text = 'RevControl:'
	#
	# label_RevcloudStatus
	#
	$label_RevcloudStatus.Location = '365, 18'
	$label_RevcloudStatus.Name = 'label_RevcloudStatus'
	$label_RevcloudStatus.Size = '40, 19'
	$label_RevcloudStatus.TabIndex = 56
	#
	# label_Revcloud
	#
	$label_Revcloud.Font = 'Trebuchet MS, 8.25pt, style=Underline'
	$label_Revcloud.Location = '295, 16'
	$label_Revcloud.Name = 'label_Revcloud'
	$label_Revcloud.Size = '60, 20'
	$label_Revcloud.TabIndex = 54
	$label_Revcloud.Text = 'RevCloud:'

	# label_RevMonStatus
	#
	$label_RevMonStatus.Location = '465, 35'
	$label_RevMonStatus.Name = 'label_RevMonStatus'
	$label_RevMonStatus.Size = '40, 19'
	$label_RevMonStatus.TabIndex = 56
	#
	# label_RevMon
	#
	$label_RevMon.Font = 'Trebuchet MS, 8.25pt, style=Underline'
	$label_RevMon.Location = '405, 33'
	$label_RevMon.Name = 'label_RevMon'
	$label_RevMon.Size = '60, 20'
	$label_RevMon.TabIndex = 54
	$label_RevMon.Text = 'RevMon:'

	# label_RevScreenMgrStatus
	#
	$label_RevScreenMgrStatus.Location = '585, 18'
	$label_RevScreenMgrStatus.Name = 'label_RevScreenMgrStatus'
	$label_RevScreenMgrStatus.Size = '40, 19'
	$label_RevScreenMgrStatus.TabIndex = 56
	#
	# label_RevScreenMgr
	#
	$label_RevScreenMgr.Font = 'Trebuchet MS, 8.25pt, style=Underline'
	$label_RevScreenMgr.Location = '505, 16'
	$label_RevScreenMgr.Name = 'label_RevScreenMgr'
	$label_RevScreenMgr.Size = '90, 33'
	$label_RevScreenMgr.TabIndex = 54
	$label_RevScreenMgr.Text = 'RevScreenMgr:'


	####################################################################
	# label_HRUpdate
	#
	$label_HRUpdate.Font = 'Trebuchet MS, 8.25pt, style=Underline'
	$label_HRUpdate.Location = '405, 16'
	$label_HRUpdate.Name = 'label_HRUpdate'
	$label_HRUpdate.Size = '80, 20'
	$label_HRUpdate.TabIndex = 57
	$label_HRUpdate.Text = 'HRUpdater:'
	#
	# label_HRUpdatedStatus
	#
	$label_HRUpdateStatus.Location = '465, 18'
	$label_HRUpdateStatus.Name = 'label_HRUpdate'
	$label_HRUpdateStatus.Size = '40, 19'
	$label_HRUpdateStatus.TabIndex = 56



	####################################################################
	# richtextbox_Logs
	#
	$richtextbox_Logs.BackColor = 'InactiveBorder'
	$richtextbox_Logs.Dock = 'Bottom'
	$richtextbox_Logs.Font = 'Consolas, 8.25pt'
	$richtextbox_Logs.ForeColor = 'Green'
	$richtextbox_Logs.Location = '0, 623'
	$richtextbox_Logs.Name = 'richtextbox_Logs'
	$richtextbox_Logs.ReadOnly = $True
	$richtextbox_Logs.Size = '1170, 70'
	$richtextbox_Logs.TabIndex = 35
	$richtextbox_Logs.Text = ''
	$richtextbox_Logs.add_TextChanged($richtextbox_Logs_TextChanged)
	#
	# statusbar1
	#
	$statusbar1.Location = '0, 693'
	$statusbar1.Name = 'statusbar1'
	$statusbar1.Size = '1170, 26'
	$statusbar1.TabIndex = 16
	#
	# menustrip_principal
	#
	$menustrip_principal.Font = 'Trebuchet MS, 9pt'
	[void]$menustrip_principal.Items.Add($ToolStripMenuItem_AdminArsenal)
	[void]$menustrip_principal.Items.Add($ToolStripMenuItem_localhost)
	[void]$menustrip_principal.Items.Add($ToolStripMenuItem_scripts)
	$menustrip_principal.Location = '0, 0'
	$menustrip_principal.Name = 'menustrip_principal'
	$menustrip_principal.Size = '1170, 26'
	$menustrip_principal.TabIndex = 1
	$menustrip_principal.Text = 'menustrip1'
	#
	# ToolStripMenuItem_AdminArsenal
	#
	[void]$ToolStripMenuItem_AdminArsenal.DropDownItems.Add($ToolStripMenuItem_PrintersControl)
	[void]$ToolStripMenuItem_AdminArsenal.DropDownItems.Add($toolstripseparator4)
	[void]$ToolStripMenuItem_AdminArsenal.DropDownItems.Add($ToolStripMenuItem_CommandPrompt)
	[void]$ToolStripMenuItem_AdminArsenal.DropDownItems.Add($ToolStripMenuItem_Powershell)
	[void]$ToolStripMenuItem_AdminArsenal.DropDownItems.Add($toolstripseparator5)
	[void]$ToolStripMenuItem_AdminArsenal.DropDownItems.Add($ToolStripMenuItem_shutdownGui)
	[void]$ToolStripMenuItem_AdminArsenal.DropDownItems.Add($ToolStripMenuItem_SSMS)
	[void]$ToolStripMenuItem_AdminArsenal.DropDownItems.Add($ToolStripMenuItem_Notepad)
	#region Binary Data
	$ToolStripMenuItem_AdminArsenal.Image = [System.Convert]::FromBase64String('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
AAAASUVORK5CYII=')
	#endregion
	$ToolStripMenuItem_AdminArsenal.Name = 'ToolStripMenuItem_AdminArsenal'
	$ToolStripMenuItem_AdminArsenal.Size = '109, 22'
	$ToolStripMenuItem_AdminArsenal.Text = 'AdminArsenal'
	#
	# ToolStripMenuItem_CommandPrompt
	#
	#region Binary Data
	$ToolStripMenuItem_CommandPrompt.Image = [System.Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACx
jwv8YQUAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAAa5JREFU
OE+tk8tLAlEUxp2oCFpFtNBV+xw3hjkmFfQuDWpyfGfRUyRa9CKT/oGKXvQUalMtsn+gFrUrCqlF
7QoUF+6avRu/5txwyEXQUBc+5tx7zu87h8tcne4fFldSUXlSbmz8KK1vlUuELpmz98q6Jqesa+77
khJzdgfLUQ3VEqP05qg/Xz0QRvfFHRyJ+1+JaqvFMBTWSAaWyp4xVM3saRIxCmtmBjWmFtS2D2sS
MaoBz5vQ1tquScSoBg1WAeKgpEnEqAaCrRGS24vRsXFsbm1jZ2cXC4tL7Iy+s7PzLP4uYlQDm80O
t8eHTCaDZDKJq6trrK6ts7O5uQWk02l4fQG2L4iYogl8/iDy+TxCoRG103JsRQH9uLm5xf7B4c8T
WAUbK6TlDwxh0OVmenh4RCAYwsRkGNlstihHjDqBxdLALjCXyyEajWEqHEFwaBiRyDRE0YX+ARGJ
y0ucnp2zmESMamA218Ph7MPGxibe3t6RSqVwFI/j5eUVkuRhOcntwdPTMzOkPTEFA77OaERHR6cm
EVP4lbmysvJjvd7wYTAY5N+IaokpPKY/PehPwtGRPXo66K0AAAAASUVORK5CYII=')
	#endregion
	$ToolStripMenuItem_CommandPrompt.Name = 'ToolStripMenuItem_CommandPrompt'
	$ToolStripMenuItem_CommandPrompt.Size = '290, 22'
	$ToolStripMenuItem_CommandPrompt.Text = 'Command Prompt'
	$ToolStripMenuItem_CommandPrompt.add_Click($ToolStripMenuItem_CommandPrompt_Click)
	#
	# ToolStripMenuItem_Powershell
	#
	#region Binary Data
	$ToolStripMenuItem_Powershell.Image = [System.Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAYAAABccqhmAAAAAXNSR0IArs4c6QAAAARnQU1BAACx
jwv8YQUAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAA/45JREFU
eF7s/QdUFmfX9o2/gF2jxmhMjDHFxN5777333nvvvfcGKiBdBLGLqIAgvcNH72AHFXt67vo8z/uu
Nd9vzzVzcYFoNOV+/99/kbWOdZ4zV4GMHMc+9j73nPO//lfpf6VXoPQKlF6B0itQegVKr0DpFSi9
AqVXoPQKlF6B0itQegVKr0DpFSi9AqVXoPQKlF6B0itQegVKr0DpFSi9AqVXoPQKlF6B0itQegVK
r0DpFSi9AqVXoPQKlF6B0itQegVKr0DpFSi9AqVXoPQKlF6B0itQegVKr0DpFSi9AqVXoPQKlF6B
0itQegVKr0DpFSi9AqVXoPQKlF6B0itQegVKr0DpFSi9AqVXoPQKlF6B0itQegVKr0DpFSi9AqVX
oPQKlF6B0itQegVKr0DpFSi9AqVXoPQKlF6B0itQegVKr0DpFSi9AqVXoPQKlF6B0itQegVKr0Dp
FSi9AqVXoPQKlF6B0itQegVKr0DpFSi9AqVXoPQKlF6B0itQegVKr0DpFSi9AqVXoPQKlF6B0itQ
egVKr0DpFSi9AqVXoPQKlF6B0itQegVKr0DpFSi9AqVXoPQKlF6B0itQegVKr0DpFSi9AqVXoPQK
lF6B0itQegVKr0DpFSi9AqVXoPQKlF6B0itQegVKr0DpFSi9AqVXoPQKlF6B0itQegVKr0DpFSi9
AqVXoPQKlF6B0itQegVKr0DpFSi9AqVXoPQKlF6B0itQegVKr0DpFXi3K2DG20pReg3+yr+Bd/tL
LH3XX3oFSvoHNucnvg0WvF6K0mvwLn8Dv/W3VNLf31/6B1/65UWjmuk/kP4PWoaLZIqyHJei9Br8
GX8Dpn9XpgKi/x0WF4T/LF8brr9uNvdylvk2zxSL44G5Fm5ReWXOpj0ucyntUZmrmU/K+mQ9K+t/
6yV4Xtbv1quyQXe+Lxd89/tygfdk/K5c6L0fyoXn/Vgu7MGP5SLuf182Mu/HslGPfi4b/fCnstH5
P5WJefSTRdyjn8tE5v9oEZn3k3n0w5/No/J/Nlfn+T+axzz6WUUs5+Me/aIiQcbHP5slFPxilvD4
F7N4GQt+lgv1Pv+ZXlj9YpsSXv/HLceXCsqDCsVQkeNSlF6D3/M3YPq3JH9bAvk70//uRBj0v8eS
xOB9/tbf/719PYPMtt/IMLeKvm9xJjrP4lxKflmv7O/KeWU+Le+Z/qTC1axnFX1vfV/JJ+dllevZ
Tz/wvvXiA7/b31e7cetVdVDD7873H/rd/f4j/zvf1Qy8+13NoLs/1EIUagfd/f6ToHs/fhp8/8c6
Ifd//Cz0/g91w/J+qodI1At/8NPnkfk/14vM+/nziLyfPo/K+/FzBOHz6Ec/143J/7lu7MNfPgOf
xoPYRz9/Ev/4l4/jH/1SO+7xL7XiC36umVjw64cJBb9WSyz4pSqvVYl99EsVBKMK88oCzldKfPJr
Je/E3IrXE3IqOnoFqDjscq7S+v1HK81esa5Sk41nBjbYdH7fN5svRX6z+WL6N1su/x+glKL0Gvy5
fwOXfuJvLK3+xvPXv153ek2dyVu/haWVtIAi4mAqCLoYFBeC9yf2b32is4On2VrPeHObgHTzc4kF
Fl6Zz8tcIcpfySoo55X1vPzVnFcVr2Y9r3Q1+3nlazmvqlzJeVn1Ss6Lal7ZL6tfy35V42ruyxpe
OS8/8sp5Vetazne1r+W8rM35T67mvvr06q3v6vCZutdyX9a7nvvqi+u53391Pee7b7xzv//W5/b3
Dbxv/dDA59b3DX3vfN/4BvC7/UMTvzvfNfW790Mz/zs/trp55/s2N+/+0Dbg3o/tQceAe993Cbz3
Q4+g+z/0DnrwQx9EpX/Igx8Hhj74cRCOY3B43s9DwNCI/J+GRT78aXjY/e9GRTz4fkSkhtA7z0cG
ZhcMPxqYMavfcf/LjXZ4/TLaOULZ6ZelXMl8qvjffqnkfvdP5fb3/yqKHzg2wS1tfoexOO5yrij+
rdz98S/GD3y/DvlZ2vwOYyH4Xb//N/8fb4P+//lb7/sTX5ff6U0w/V3198g50/lb/3/+rdzi9fcC
333LBLnMjfiO+Tsg57t/KcWRUPA3heCpnIzPV1ZdSVY6HPRVvtl0/toXi20Hw9EqxcRAdwamQqA7
2N+i9Lu/PuWgn9m+0CzzU2mPLDzjHpc5n/Co7MXMF2Uv5LwofyHlaYVLmU8rema8qHw+40UVUPVC
xrNq57NeVD+X9eLD85nPa1zIfF7zfOarj89nvvzkXMbzOucyX9Q9n/WyHu/54lzGi6/OZ7ysfyH7
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
Dsj3SEy+U+Js5Dtmgl6+e+KMBPiPY/ZeX5SrE/w/APQf+tH9SEDiKJFUwq7CsiYRyAcgH4SwsHwo
og7EhBic5nwG/+p3wPw+yfdLvmdS1jNBL99B0+OLgzKBb5b6nJ7/30gC8lDNkMAkAkmyyAcg7Csf
hjCxqAMx+ZCc5nwG/8p3wPwuyVW+W/Idk++afOfku2fG+fcDvtno45T9/wQR2CsB+7yASQSiCOTB
CxkI+8qHIR+KafIhOc35DP6V74D990m+X2LyXZPvnHz35DsoTsnR49sD3wn+fwL85h8xScAsEdoT
gSQJTTKQD8EkBPlgTGKQD8ppzmfwz34HzO+SCXZ7wNuD3pT6TuD/C2D/oT/aHhGYZGA2DwkhmCYf
jtOcz+Df9R2w/27J9800+Q46gt7p8f9DJNCeKnAME8wPxP5q/4E571u/vM5ncf9n0d73yP49e4dk
3v+Hv/bO//yPPYH2PhTne3qLtdP+fc/gx76Hzp87n4DzCTifgPMJOJ+A8wk4n4DzCTifgPMJOJ+A
8wk4n4DzCTifgPMJOJ+A8wk4n4DzCTifgPMJOJ+A8wk4n4DzCTifgPMJOJ+A8wk4n4DzCTifgPMJ
OJ+A8wk4n4DzCTifgPMJOJ+A8wk4n4DzCTifgPMJOJ+A8wk4n4DzCTifgPMJOJ+A8wk4n4DzCTif
gPMJOJ+A8wk4n4DzCTifgPMJOJ+A8wk4n4DzCTifgPMJOJ+A8wk4n4DzCTifgPMJOJ+A8wk4n4Dz
CTifgPMJOJ+A8wk4n4DzCTifgPMJOJ+A8wk4n4DzCTifgPMJOJ+A8wk4n4DzCTifgPMJOJ+A8wk4
n4DzCTifgPMJOJ+A8wk4n4DzCTifgPMJOJ+A8wk4n4DzCTifgPMJOJ+A8wk4n4DzCTifgPMJOJ+A
8wk4n4DzCTifgPMJOJ+A8wk4n4DzCTifgPMJOJ+A8wk4n4DzCTifgPMJOJ+A8wk4n4DzCTifgPMJ
OJ+A8wk4n4DzCTifgPMJ/HqfwP8Pj5iqKRcA/fIAAAAASUVORK5CYII=')
	#endregion
	$ToolStripMenuItem_Powershell.Name = 'ToolStripMenuItem_Powershell'
	$ToolStripMenuItem_Powershell.Size = '290, 22'
	$ToolStripMenuItem_Powershell.Text = 'Powershell'
	$ToolStripMenuItem_Powershell.add_Click($ToolStripMenuItem_Powershell_Click)
	#
	# ToolStripMenuItem_Notepad
	#
	#region Binary Data
	$ToolStripMenuItem_Notepad.Image = [System.Convert]::FromBase64String('R0lGODlhEAAQAIcAAH6TmkROUr7h6cXk68rn7dHEp4/N2pLO26bX4abP2JnQ3YvDz6zS2rbW3qDN
18Di6pbI1Nbs8Z7M1qXW4afX4dzu87rg6GemtYfJ2Mjm7JDN2qzZ477a4KrR2rvg6Y7L2bzZ4KjP
2dve4NDo7bbe5oC9y0VRVbff54bBzoXCzrbe547M2Z3M16/T26/b5d/p7M7n7rvf6HKvvuf096jY
4p3S3s/p76HI0ZXH06PO1/3+/tXq8Xq8zMXl7Mbk7LnY35HO23y+y7je59Xr8drt8d7v9IbH1HKz
woTI1nW4x5nR3cHk6tLq8JHN25rR3YnK2KPW4JrQ3aza47Xd5o7N2onL2J7T3oTBzoXBzrPc5pzS
35PO25/N1p3T35XI05nK1ZDN23Cuu3qyv8vk6sfm7c3o7q/b5Kva44/E0a/a5Mnm7X6+zfP5+8bl
7K/U3JvM1aTW4Mje47Hb5ZTP3KPV4Ha2xI3E0Nnm6cjl7K7T29Dp75LG0o/F0sHc4rjf6HzE1JbI
06fP2Nfs8bLV3afX4r7g6aTV4Xa2xajN1WmntsHj67KpkJXP3cDi6Xm2xZ/U4IPAzcPd4q7a5JfQ
3K3a443E0YzI1YvE0e7x8ZGEYP///wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH/C05FVFNDQVBFMi4wAwEB
AAAh+QQBAACbACwAAAAAEAAQAAAI8AA3CRQIYFPBgwYHCtxgAk+AQgHkBDAUwJKdAgMVVBCkR40i
Py4m1LiyIJPAGRSI7IDhQ8AUSlCilGBhclOGGHEicWjQIhAXQAvCIKophQCTMmQanTCDoEuTIyNq
KhjSB0SDPCEcQOAD6cKLmkpsEBggQEUaBFYYGamjw2QRGgR+DGKQQAIENCkcicFk8oGQAUssZDkD
R8uWKmtwaDJJZ8ADNx1yvPFSCQsPGTf4bprTxgMJSYQeTTKA4c+hMYvZOOkhgK6DL3suoQiS6A7f
CEieGAACRgOVFQcOfEiiabFCEZiSK19eU+CiTNCjSy8QEAA7')
	#endregion
	$ToolStripMenuItem_Notepad.Name = 'ToolStripMenuItem_Notepad'
	$ToolStripMenuItem_Notepad.Size = '290, 22'
	$ToolStripMenuItem_Notepad.Text = 'Notepad'
	$ToolStripMenuItem_Notepad.add_Click($ToolStripMenuItem_Notepad_Click)
	#
	# ToolStripMenuItem_localhost
	#
	[void]$ToolStripMenuItem_localhost.DropDownItems.Add($ToolStripMenuItem_netstatsListening)
	[void]$ToolStripMenuItem_localhost.DropDownItems.Add($toolstripseparator1)
	[void]$ToolStripMenuItem_localhost.DropDownItems.Add($ToolStripMenuItem_compmgmt)
	[void]$ToolStripMenuItem_localhost.DropDownItems.Add($ToolStripMenuItem_services)
	[void]$ToolStripMenuItem_localhost.DropDownItems.Add($toolstripseparator3)
	[void]$ToolStripMenuItem_localhost.DropDownItems.Add($ToolStripMenuItem_systemproperties)
	[void]$ToolStripMenuItem_localhost.DropDownItems.Add($ToolStripMenuItem_devicemanager)
	[void]$ToolStripMenuItem_localhost.DropDownItems.Add($ToolStripMenuItem_taskManager)
	[void]$ToolStripMenuItem_localhost.DropDownItems.Add($ToolStripMenuItem_otherLocalTools)
	#region Binary Data
	$ToolStripMenuItem_localhost.Image = [System.Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACx
jwv8YQUAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAAAlwSFlz
AAALDAAACwwBP0AiyAAAAodJREFUOE+lk11Ik1EYx4+ZqZmiqYSoiSZGoFREiJIXLYS6yAxGF0lK
aEXlZfRhlGGS9q2uyfZu02l+lKGw+RkilaU1P7eZy8SiiIggIrrRoPp19nohlkHQxY/zcuD5nec8
5/8KQPwP/1XsPXiRoOP+AEsx6nrDiMQxPsPQ6DSOsWkGhyYZdroXt+8tjkuqQwT1IaKdiMj3xGvm
KKsBxQY6idID1j44ctbNqOsFwm6353Z1dWGz2dTTNyTXIgLbEWufIaKmCdn0mZM3f1DXKYvbJXI1
dEPBGRdO9xSira0Nt9tNcXGxKkjZUoNY2YKIeYCIdUnesSNvjovKT0oscF5y2gTa405crpeIlpYW
JiYm5DSEKkjTWPENb0CEt8prSMmaUWLT3pJf9JXC0lmOXPhGXtF3duWM45yQgsbGRlWg/RioCjIy
DYTF1eATakZE3JN0E5DwFM3+V2gLP5B99BOZeV/I2D0wPwOvwOPxoNfrVcHG1EqiEhX8I6oRoVbZ
iZSs6SIpY5ht2inStTMk73zNZk0vI+OTiPr6+kWCqPhrrI6pYEXYDTkLPSJYSkLuEJrYQ0LqAOvS
HaxOcZC01cbQ8HOExWJRBUajUe3AP6Qcv1Vl+PhfwsfvMssCqvBdacYvvJngOLsUdeMT2UH0+iae
PBtbECiKogq8xf/Ko8eOBYFOp1syhUsls639IfbOfh72DyK8rXuvUH7lKr29vRhNZhnx+YSeKy1F
k7WHfXmH2Z6VzaniktnffzxhMBj+Krhltv7cm3OIgmMnyDqYT8PdVs8fAqvVmms2m9VnNJlMVOiV
5mrj7SCltpFKQw3XdUaqTbWUV1SjN9dRJffk9wGltmm5DJ/4BZ3IpG+IT6wAAAAAAElFTkSuQmCC')
	#endregion
	$ToolStripMenuItem_localhost.Name = 'ToolStripMenuItem_localhost'
	$ToolStripMenuItem_localhost.Size = '90, 22'
	$ToolStripMenuItem_localhost.Text = 'LocalHost'
	#
	# ToolStripMenuItem_compmgmt
	#
	$ToolStripMenuItem_compmgmt.Name = 'ToolStripMenuItem_compmgmt'
	$ToolStripMenuItem_compmgmt.Size = '278, 22'
	$ToolStripMenuItem_compmgmt.Text = 'MMC - Computer Management'
	$ToolStripMenuItem_compmgmt.add_Click($ToolStripMenuItem_compmgmt_Click)
	#
	# ToolStripMenuItem_taskManager
	#
	$ToolStripMenuItem_taskManager.Name = 'ToolStripMenuItem_taskManager'
	$ToolStripMenuItem_taskManager.Size = '278, 22'
	$ToolStripMenuItem_taskManager.Text = 'Task Manager'
	$ToolStripMenuItem_taskManager.add_Click($ToolStripMenuItem_taskManager_Click)
	#
	# ToolStripMenuItem_services
	#
	$ToolStripMenuItem_services.Name = 'ToolStripMenuItem_services'
	$ToolStripMenuItem_services.Size = '278, 22'
	$ToolStripMenuItem_services.Text = 'MMC - Services'
	$ToolStripMenuItem_services.add_Click($ToolStripMenuItem_services_Click)
	#
	# ToolStripMenuItem_shutdownGui
	#
	#region Binary Data
	$ToolStripMenuItem_shutdownGui.Image = [System.Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACx
jwv8YQUAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAA0tJREFU
OE9tk2tI01EYxteauAzD7nQzInBd1jLa8jrddKO5dEtNSXOpgZe+hGEXLbtgV9OoIEK8VB+CIuiD
hBgkWQSBqdnmv92nbrOwrFZu/11a29PZgkDzgZfDObzn9573nOcwGLOkKZAzR3JEUkqe0qIrUXbp
y/KfavdJb+mKsxWm2sMRs/NnzIeliTuonDSNrvYIDJcvwdjUBMvt27A9eAB72x0YK/eb9GV54jkh
Q8LtipEihXuotBQDxcUYrqqC/dEjfOrqgqmlBWOtrZh4/BjW5gs+7V6RagZkMJnHUe+V0q8zMxEK
882bGCwpgctshttqhb6xEVN9fRhra4P94UNYrzX+MlQWJf2DvBdyu1+LRXgRH48JkhDSu8JCuEwm
uMfHYTh1KrzmNBgw3tGBj0+ewFCe3x8GDCXz1rzLEv3u3bgR6oqKcCJtNGIkNzc8ekZHYT52DG4C
C+lrby9sd+/CdqsZI4oMPmM4gVP0ViLGqw0b8PXZMwSDQZjLy2FUKuEhAC8BWGtqYGtoQMDng0un
Q39yMgbkWVCn8WoZ7xM21Q1JJeiPi4OH9Oz//BmjEgnsBOD98AFejQbWjAxYBAJ4yNz/4wcGOBwM
ikRQJ226wVAnbq6h9sih4XLhoSgEnE5MymSYIuEoKAjHFAFMpqfDb7fDPzkJiscDtXs3NAlxVxlU
Kk9qzM2Gic/HNHnvkNzXr4POzoZboYCHBJ2TA/rMmb/309MDy65dMOUpQSVtKWHoMgRsozLTMSEW
4zupFpyeRpD0Grh3D4HqagTIxQaIB4I0jaDXi5+HDuETOb4lP8unFwuWh19Cm8o9+6VMBadcDn9d
HeBwhKvNkMuF3xcvhk/2rfQgdMJtd/75YEwmjDRI+W/c1ZUIEBfi6FGguxvQagG9Hnj+HKivR1Cl
gq+qEpY9qfpxmTB6hht7UuIXqyWCPvdxsjnUb3Mz0N4OdHYCxJk4fx7e+hMwyBLf9gp3xs75H1oT
trN6krgVlgMK4/fG06A7WkHfb4fjyjnYSvMmXqZsrb2fymf/tzmKOY+5jMVcsIjFjFnBjly6Pnrh
qry1K1JOctYdaNgcqyqMXZkeFxO9ZnUUe+mSCFZMbCQramXEfGYI9AdHhzFu6obUdgAAAABJRU5E
rkJggg==')
	#endregion
	$ToolStripMenuItem_shutdownGui.Name = 'ToolStripMenuItem_shutdownGui'
	$ToolStripMenuItem_shutdownGui.Size = '290, 22'
	$ToolStripMenuItem_shutdownGui.Text = 'Shutdown Gui'
	$ToolStripMenuItem_shutdownGui.add_Click($ToolStripMenuItem_shutdownGui_Click)
	#
    #region ToolStripMenuItem_SSMS
	#
	#Binary Data
	$ToolStripMenuItem_SSMS.Image = [System.Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAAXNSR0IArs4c6QAAAARnQU1BAACx
jwv8YQUAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAAlhJREFU
aEPVWe2SgzAI9NF9NN+sd6SlgwQSzILeZSZ/Oo2yfCxZ3DZg7fv+QjfweuwoGU7rOI7lTc/4tYL2
vSvL+EcAZBp/O4Bs4x8D0JJ/YVkFf2sNoBHQAD7G31fEmQDIeGKwfxkBNv6xGljlfjaYznM6lUQA
7a7eeen5MgAZee4RlPR8CQDUeDKcvEzPsdKslIUyjNc5rkFIAKksxMYv9KbvEZkSswikshDqeZ3X
0jgrArqQYRaSALaNrrfxzZ7WqcEd1sp5CzB0l+4BUCHGtgeAjdQpWcJCJgASGsQoTXD4YDwAsxrI
6jMtchUA2NMjFkpTcy4A8n5RBDKMZ8q2I5BUA1YEsowvBWDVQDZdlwKwagBtllbhN7quoFGOgKQw
NAJWTzEAtBlNeM/6gKyBTACnexT6YKuzVtQAR6C7R2UCkFdpDQJ9Dxdtp+YSuyI8Jx3ZMlNz4bz3
aoRfjvD8iKlC96gzI10buqIpQsDZCctqbhVAlvEzLaELudMSKwDQBiU9H9HTQzV3FQDq+XQ1hwC4
ouTov14TtHoIjyCnag4HEFNyJJI8AJ4cLWEh8x6VpOa0HLV6xKmI950GUv3mwvKaDPP+O4U+MhSQ
oxE1J9noOxAg49+rqeE2WaPfCIC33AgUqjnpyC4CbLwG4E2jTQCFak5nQTiFRteHLoVAAB4LTWtg
ogPM2dOfisDKdKwCAEdAqjmLQul/yWPJuJLTukHfcaw0Gub/ivf1UAz57CQBRGoA9jwDzrwLjdRc
2Tc1r7ld/X3WLM3GtZo2xjlYzV2YhHSv/wGeD3wz9WdSYQAAAABJRU5ErkJggg==')
	$ToolStripMenuItem_SSMS.Name = 'ToolStripMenuItem_SSMS'
	$ToolStripMenuItem_SSMS.Size = '290, 22'
	$ToolStripMenuItem_SSMS.Text = 'SSMS'
	$ToolStripMenuItem_SSMS.add_Click($ToolStripMenuItem_SSMS_Click)
	#
	# ToolStripMenuItem_PrintersControl
	#
	#region Binary Data
	$ToolStripMenuItem_PrintersControl.Image = [System.Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACx
jwv8YQUAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAAnZJREFU
OE+Nk+9LU1EYx++78O9wvhH/g6DBzKy0BAXRF8Iu0zcG4gsXbLDBWgVDJwSOlb4UMrQIogUyZOXu
fugmolttiLW00lku9W7u7u7Xt+eccCms6MIHLud8n895ngNHACCccdXyTn9rPOztmghXCXQ5w0rX
xIrS6QhUL9+Vps5nz/5rxWzhxkOpeCgr+JkrIJP9zaFcQGJPhuXVLgyPtvJX7ry+dF50QdDpCOZP
TlWsfSkTJYQ/q1jeLqBQqmBtr4z7b3ahM/me/lXQ4QgqTLBOgvWvZazuFCF9VJE6yFEnCg6OTtFm
XS7VFdhstoYOR0A9zqmI0WmxfTqVd1GE98MpPPEsjmm0a/f8ql6vb7hwB1RsILJ0WTgiQWK/ivck
2CRRdKfEx1jaytNeEdftEvr7+7M9PT0GJhGosG16ehrRaBS3x0PIkCCZriJBxL5VsEGjhKgLP42S
IcHNByH4/X6MjY2hvb29jQk26UM6nYbFYvkvWFaSJPT29m4zgVoul8GIRCKQZfmfBINBnmWMjo5W
BavVClVVOQsLC0ilUlxUD7Y3Oztby4uiCMFsNiORSHDcbjeSySR8Pl9dWGZycrKW12q1EIxGI7xe
L8fpdCIej2NxcbEusVgMdru9lm9uboZAc8Dj8XBcLhfoTjgmkwkjIyNgbXZ3d6O1tRU6nY6vneWb
mpogDA8PV+bm5vgiK5x//hJLbwN1eTb/Ai0tLTw7MzODxsZGCAaD4cnAwMBmX18fRFcIeUXF4YmK
H8TBcQF7GQU733P4lJaRLxQhToWg0WhY8QZhvvCYRFe4MvR4FUPuPwzS/6B7hcP2xKlw5fxb+AW7
EgTI9bZhkwAAAABJRU5ErkJggg==')
	#endregion
	$ToolStripMenuItem_PrintersControl.Name = 'ToolStripMenuItem_PrintersControl'
	$ToolStripMenuItem_PrintersControl.Size = '290, 22'
	$ToolStripMenuItem_PrintersControl.Text = 'Printers'
	$ToolStripMenuItem_PrintersControl.add_Click($ToolStripMenuItem_PrintersControl_Click)
	#
	# ToolStripMenuItem_netstatsListening
	#
	$ToolStripMenuItem_netstatsListening.Name = 'ToolStripMenuItem_netstatsListening'
	$ToolStripMenuItem_netstatsListening.Size = '278, 22'
	$ToolStripMenuItem_netstatsListening.Text = 'Netstats | Listening ports'
	$ToolStripMenuItem_netstatsListening.add_Click($ToolStripMenuItem_netstatsListening_Click)
	#
	# ToolStripMenuItem_otherLocalTools
	#
	[void]$ToolStripMenuItem_otherLocalTools.DropDownItems.Add($ToolStripMenuItem_addRemovePrograms)
	[void]$ToolStripMenuItem_otherLocalTools.DropDownItems.Add($ToolStripMenuItem_diskManagement)
	[void]$ToolStripMenuItem_otherLocalTools.DropDownItems.Add($ToolStripMenuItem_networkConnections)
	[void]$ToolStripMenuItem_otherLocalTools.DropDownItems.Add($ToolStripMenuItem_scheduledTasks)
	$ToolStripMenuItem_otherLocalTools.Name = 'ToolStripMenuItem_otherLocalTools'
	$ToolStripMenuItem_otherLocalTools.Size = '278, 22'
	$ToolStripMenuItem_otherLocalTools.Text = 'Other Windows Apps'
	#
	# ToolStripMenuItem_addRemovePrograms
	#
	$ToolStripMenuItem_addRemovePrograms.Name = 'ToolStripMenuItem_addRemovePrograms'
	$ToolStripMenuItem_addRemovePrograms.Size = '311, 22'
	$ToolStripMenuItem_addRemovePrograms.Text = 'Add/Remove Programs'
	$ToolStripMenuItem_addRemovePrograms.add_Click($ToolStripMenuItem_addRemovePrograms_Click)
	#
	# ToolStripMenuItem_devicemanager
	#
	$ToolStripMenuItem_devicemanager.Name = 'ToolStripMenuItem_devicemanager'
	$ToolStripMenuItem_devicemanager.Size = '278, 22'
	$ToolStripMenuItem_devicemanager.Text = 'Device Manager'
	$ToolStripMenuItem_devicemanager.add_Click($ToolStripMenuItem_devicemanager_Click)
	#
	#
	# toolstripseparator1
	#
	$toolstripseparator1.Name = 'toolstripseparator1'
	$toolstripseparator1.Size = '275, 6'
	#
	# toolstripseparator3
	#
	$toolstripseparator3.Name = 'toolstripseparator3'
	$toolstripseparator3.Size = '275, 6'
	#
	# ToolStripMenuItem_systemproperties
	#
	$ToolStripMenuItem_systemproperties.Name = 'ToolStripMenuItem_systemproperties'
	$ToolStripMenuItem_systemproperties.Size = '278, 22'
	$ToolStripMenuItem_systemproperties.Text = 'System Properties'
	$ToolStripMenuItem_systemproperties.add_Click($ToolStripMenuItem_systemproperties_Click)
	#
	# toolstripseparator4
	#
	$toolstripseparator4.Name = 'toolstripseparator4'
	$toolstripseparator4.Size = '287, 6'
	#
	# toolstripseparator5
	#
	$toolstripseparator5.Name = 'toolstripseparator5'
	$toolstripseparator5.Size = '287, 6'
	#
	# ToolStripMenuItem_networkConnections
	#
	$ToolStripMenuItem_networkConnections.Name = 'ToolStripMenuItem_networkConnections'
	$ToolStripMenuItem_networkConnections.Size = '311, 22'
	$ToolStripMenuItem_networkConnections.Text = 'Network Connections'
	$ToolStripMenuItem_networkConnections.add_Click($ToolStripMenuItem_networkConnections_Click)
	#
	# ToolStripMenuItem_diskManagement
	#
	$ToolStripMenuItem_diskManagement.Name = 'ToolStripMenuItem_diskManagement'
	$ToolStripMenuItem_diskManagement.Size = '311, 22'
	$ToolStripMenuItem_diskManagement.Text = 'Disk Management'
	$ToolStripMenuItem_diskManagement.add_Click($ToolStripMenuItem_diskManagement_Click)
	#
	# ToolStripMenuItem_scheduledTasks
	#
	$ToolStripMenuItem_scheduledTasks.Name = 'ToolStripMenuItem_scheduledTasks'
	$ToolStripMenuItem_scheduledTasks.Size = '311, 22'
	$ToolStripMenuItem_scheduledTasks.Text = 'Scheduled Tasks'
	$ToolStripMenuItem_scheduledTasks.add_Click($ToolStripMenuItem_scheduledTasks_Click)
	#
	# errorprovider1
	#
	$errorprovider1.ContainerControl = $form_MainForm
	#
	# tooltipinfo
	#
	# ToolStripMenuItem_scripts
	#
	
	[void]$ToolStripMenuItem_scripts.DropDownItems.Add($ToolStripMenuItem_SET_Backup_Path)
	[void]$ToolStripMenuItem_scripts.DropDownItems.Add($ToolStripMenuItem_SET_Allow_Batch)
	[void]$ToolStripMenuItem_scripts.DropDownItems.Add($ToolStripMenuItem_SET_HungerRush_ShortCuts)
	[void]$ToolStripMenuItem_scripts.DropDownItems.Add($ToolStripMenuItem_SET_Allow_Close_Day)

	[void]$ToolStripMenuItem_scripts.DropDownItems.Add($ToolStripMenuItem_Printers)
	[void]$ToolStripMenuItem_Printers.DropDownItems.Add($ToolStripMenuItem_CREATE_Kitchen_Printers)
	[void]$ToolStripMenuItem_Printers.DropDownItems.Add($ToolStripMenuItem_REMOVE_ALL_Printers)
	[void]$ToolStripMenuItem_Printers.DropDownItems.Add($ToolStripMenuItem_CREATE_Station_Printer)
	[void]$ToolStripMenuItem_Printers.DropDownItems.Add($ToolStripMenuItem_Test_All_Local_Printers)


	#region Binary Data
	$ToolStripMenuItem_scripts.Image = [System.Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACx
jwv8YQUAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAAn9JREFU
OE9jYMABJMT5GNjYWLSyU23qpzd7RJsq8rC7mkrjUo4qLinBx8DIyKifHG9x/O7Jov8vtkR8mppl
5He815GwAarKogwsLEymaYmW5x+dL/3//1Ty//crA/7OKHZPf7E6Cb8BlmYKDOzsLNY5aTZXnl0A
aj6e8P/P1vD/2ydEbpFV1BVwd7DGbcD///MYeLnZnUty7G6+vFjy///h2P//d0T+/3+99v+9/RmP
JpTa+Pz//59BUpQb0xARYSGgs9mcc+IdHz46Wvb//4GY//+3QzT/vwl0yfms//c3RT2eUGzlCzJE
QgTTEDZtDcUNF3YU/r99pOT/10NF//9fqwYaUPz//7nM//9Pp4Hxva2xj3savMCGiIrxobiERUZa
fNGeFZn/v96s+P/7Vt3//1cL/v8/mwHXDDboZsn/W+cq7leVuRtP7QtBGMDExAziaNhbah85tR6o
6Ure//9n0oExkAoxAOgFkOb/r1r/f3/V/n/J9LDS/5+7UcOCmZkFbIitucbhE8vigbYDDQBpvpD9
//9tYLi8bvv//3Pv/6cXyj50Vbt6bFkQhRmYUEPUbUzVDhxfCjTkMtAldyv+/3/b8f//twn/X9+s
+baoP6AEqJPZQEsCe5QCUyBIQsfNRu/e61PAWPjS9///ryn/399v/LliWmgjUI7N1lQOd3pQlJNi
YOPgDG8LN/38Z5r3///Pev5/etX1Z/386D5pYS4uLwcVgsmZS19dfu+9fpf//zt0/39dm/Bv2/qs
2cba4nwRAfoENYMUsMpKis5aXe70+8Ukp597WvyXegbZiKQl2ROlGZgLmUAKJQw0FSPzIx3DQn2d
RHNivXBqBgD70EG6KrB0jQAAAABJRU5ErkJggg==')
	#endregion
	$ToolStripMenuItem_scripts.Name = 'ToolStripMenuItem_scripts'
	$ToolStripMenuItem_scripts.Size = '74, 22'
	$ToolStripMenuItem_scripts.Text = 'Scripts'
	#
	$ToolStripMenuItem_Printers.Name = 'ToolStripMenuItem_otherLocalTools'
	$ToolStripMenuItem_Printers.Size = '278, 22'
	$ToolStripMenuItem_Printers.Text = 'Printers'
	# ToolStripMenuItem_SET_Backup_Path
	#
	$ToolStripMenuItem_SET_Backup_Path.Name = 'ToolStripMenuItem_SET_Backup_Path'
	$ToolStripMenuItem_SET_Backup_Path.Size = '152, 22'
	$ToolStripMenuItem_SET_Backup_Path.Text = 'Set Backup Paths'
	$ToolStripMenuItem_SET_Backup_Path.add_Click($ToolStripMenuItem_SET_Backup_Path_Click)
	#endregion

	# ToolStripMenuItem_SET_HungerRush_ShortCuts
	#
	$ToolStripMenuItem_SET_HungerRush_ShortCuts.Name = 'ToolStripMenuItem_SET_HungerRush_ShortCuts'
	$ToolStripMenuItem_SET_HungerRush_ShortCuts.Size = '152, 22'
	$ToolStripMenuItem_SET_HungerRush_ShortCuts.Text = 'Create HR ShortCuts'
	$ToolStripMenuItem_SET_HungerRush_ShortCuts.add_Click($ToolStripMenuItem_SET_HungerRush_ShortCuts_Click)
    #endregion

	# ToolStripMenuItem_SET_Allow_Close_Day
	#
	$ToolStripMenuItem_SET_Allow_Close_Day.Name = 'ToolStripMenuItem_SET_Allow_Close_Day'
	$ToolStripMenuItem_SET_Allow_Close_Day.Size = '152, 22'
	$ToolStripMenuItem_SET_Allow_Close_Day.Text = 'Set Close Day Only on Station 1'
	$ToolStripMenuItem_SET_Allow_Close_Day.add_Click($ToolStripMenuItem_SET_Allow_Close_Day_Click)
	#endregion


	# ToolStripMenuItem_Test_All_Local_Printers
	#
	$ToolStripMenuItem_Test_All_Local_Printers.Name = 'ToolStripMenuItem_Test_All_Local_Printers'
	$ToolStripMenuItem_Test_All_Local_Printers.Size = '152, 22'
	$ToolStripMenuItem_Test_All_Local_Printers.Text = 'Test ALL Local Printers'
	$ToolStripMenuItem_Test_All_Local_Printers.add_Click($ToolStripMenuItem_Test_All_Local_Printers_Click)
	#endregion

	# $ToolStripMenuItem_CREATE_Kitchen_Printers
	#
	$ToolStripMenuItem_CREATE_Kitchen_Printers.Name = 'ToolStripMenuItem_CREATE_Kitchen_Printers'
	$ToolStripMenuItem_CREATE_Kitchen_Printers.Size = '152, 22'
	$ToolStripMenuItem_CREATE_Kitchen_Printers.Text = 'Create Kitchen Printers'
	$ToolStripMenuItem_CREATE_Kitchen_Printers.add_Click($ToolStripMenuItem_CREATE_Kitchen_Printers_Click)
	#
	# $ToolStripMenuItem_REMOVE_ALL_PRINTERS
	#
	$ToolStripMenuItem_REMOVE_ALL_Printers.Name = 'ToolStripMenuItem_REMOVE_ALL_Printers'
	$ToolStripMenuItem_REMOVE_ALL_Printers.Size = '152, 22'
	$ToolStripMenuItem_REMOVE_ALL_Printers.Text = 'REMOVES ALL Printers'
	$ToolStripMenuItem_REMOVE_ALL_Printers.add_Click($ToolStripMenuItem_REMOVE_ALL_Printers_Click)

	# $ToolStripMenuItem_REMOVE_ALL_Printers
	#
	$ToolStripMenuItem_CREATE_Station_Printer.Name = 'ToolStripMenuItem_CREATE_Station_Printer'
	$ToolStripMenuItem_CREATE_Station_Printer.Size = '152, 22'
	$ToolStripMenuItem_CREATE_Station_Printer.Text = 'Create Station Printer'
	$ToolStripMenuItem_CREATE_Station_Printer.add_Click($ToolStripMenuItem_CREATE_Station_Printer_Click)

	# $ToolStripMenuItem_SET_Allow_Batch
	#
	$ToolStripMenuItem_SET_Allow_Batch.Name = 'ToolStripMenuItem_SET_Allow_Batch'
	$ToolStripMenuItem_SET_Allow_Batch.Size = '152, 22'
	$ToolStripMenuItem_SET_Allow_Batch.Text = 'SET Allow Batch on Station 1 Only'
	$ToolStripMenuItem_SET_Allow_Batch.add_Click($ToolStripMenuItem_SET_Allow_Batch_Click)

	# imagelistAnimation
	#
	$Formatter_binaryFomatter = New-Object System.Runtime.Serialization.Formatters.Binary.BinaryFormatter
	#region Binary Data
	$System_IO_MemoryStream = New-Object System.IO.MemoryStream (,[byte[]][System.Convert]::FromBase64String('AAEAAAD/////AQAAAAAAAAAMAgAAAFdTeXN0ZW0uV2luZG93cy5Gb3JtcywgVmVyc2lvbj00LjAu
MC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAA
ACZTeXN0ZW0uV2luZG93cy5Gb3Jtcy5JbWFnZUxpc3RTdHJlYW1lcgEAAAAERGF0YQcCAgAAAAkD
AAAADwMAAAB2CgAAAk1TRnQBSQFMAgEBCAEAAcgBAAHIAQABEAEAARABAAT/ASEBAAj/AUIBTQE2
BwABNgMAASgDAAFAAwABMAMAAQEBAAEgBgABMP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/
AP8AugADwgH/AzAB/wMwAf8DwgH/MAADwgH/A1AB/wOCAf8DwgH/sAADMAH/AwAB/wMAAf8DMAH/
MAADggH/AzAB/wMwAf8DUAH/gAADwgH/AzAB/wMwAf8DwgH/IAADMAH/AwAB/wMAAf8DMAH/A8IB
/wNQAf8DggH/A8IB/xAAA8IB/wMwAf8DMAH/A8IB/wNQAf8DMAH/AzAB/wNQAf8EAAOSAf8DkgH/
A8IB/3AAAzAB/wMAAf8DAAH/AzAB/yAAA8IB/wMwAf8DMAH/A8IB/wOCAf8DMAH/AzAB/wOCAf8Q
AAMwAf8DAAH/AwAB/wMwAf8DwgH/A1AB/wOCAf8DwgH/A5IB/wOCAf8DggH/A5IB/3AAAzAB/wMA
Af8DAAH/AzAB/zAAA1AB/wMwAf8DMAH/A1AB/xAAAzAB/wMAAf8DAAH/AzAB/xAAA5IB/wOSAf8D
kgH/A8IB/3AAA8IB/wMwAf8DMAH/A8IB/zAAA8IB/wNQAf8DggH/A8IB/xAAA8IB/wMwAf8DMAH/
A8IB/xAAA8IB/wOSAf8DkgH/A8IB/zgAA8IB/wMwAf8DMAH/A8IB/zAAA8IB/wOCAf8DUAH/A8IB
/zAAA8IB/wPCAf8DkgH/A8IB/zQAA8IB/wPCAf80AAMwAf8DAAH/AwAB/wMwAf8wAANQAf8DMAH/
AzAB/wNQAf8wAAOSAf8DggH/A4IB/wOSAf8wAAPCAf8DwgH/A8IB/wPCAf8wAAMwAf8DAAH/AwAB
/wMwAf8wAAOCAf8DMAH/AzAB/wOCAf8wAAPCAf8DggH/A5IB/wOSAf8wAAPCAf8DwgH/A8IB/wPC
Af8wAAPCAf8DMAH/AzAB/wPCAf8wAAPCAf8DggH/A1AB/wPCAf8wAAPCAf8DkgH/A5IB/wPCAf80
AAPCAf8DwgH/EAADwgH/A8IB/xQAA8IB/wOCAf8DUAH/A8IB/zAAA8IB/wOSAf8DkgH/A8IB/zQA
A8IB/wPCAf9UAAPCAf8DwgH/A8IB/wPCAf8QAANQAf8DMAH/AzAB/wNQAf8wAAOSAf8DggH/A5IB
/wOSAf8wAAPCAf8DwgH/A8IB/wPCAf9QAAPCAf8DwgH/A8IB/wPCAf8DwgH/A8IB/wOSAf8DwgH/
A4IB/wMwAf8DMAH/A4IB/yQAA8IB/wPCAf8EAAPCAf8DggH/A5IB/wOSAf8wAAPCAf8DwgH/A8IB
/wPCAf9UAAPCAf8DwgH/BAADkgH/A4IB/wOCAf8DkgH/A8IB/wOCAf8DUAH/A8IB/yAAA8IB/wPC
Af8DwgH/A8IB/wPCAf8DkgH/A5IB/wPCAf80AAPCAf8DwgH/ZAADkgH/A5IB/wOSAf8DkgH/MAAD
wgH/A8IB/wPCAf8DwgH/sAADwgH/A5IB/wOSAf8DwgH/NAADwgH/A8IB/7QAA8IB/wPCAf8DkgH/
A8IB/zQAA8IB/wPCAf+0AAOSAf8DggH/A4IB/wOSAf8wAAPCAf8DwgH/A8IB/wPCAf+gAAPCAf8D
UAH/A4IB/wPCAf8DkgH/A5IB/wOSAf8DwgH/BAADwgH/A8IB/xQAA8IB/wPCAf8DkgH/A8IB/wPC
Af8DwgH/A8IB/wPCAf8kAAPCAf8DwgH/dAADggH/AzAB/wMwAf8DggH/A8IB/wOSAf8DkgH/A8IB
/wPCAf8DwgH/A8IB/wPCAf8QAAOSAf8DggH/A4IB/wOSAf8EAAPCAf8DwgH/JAADwgH/A8IB/wPC
Af8DwgH/cAADUAH/AzAB/wMwAf8DggH/EAADwgH/A8IB/wPCAf8DwgH/EAADkgH/A5IB/wOSAf8D
kgH/MAADwgH/A8IB/wPCAf8DwgH/cAADwgH/A1AB/wNQAf8DwgH/FAADwgH/A8IB/xQAA8IB/wOS
Af8DkgH/A8IB/zQAA8IB/wPCAf9sAAPCAf8DMAH/AzAB/wPCAf8wAAPCAf8DUAH/A4IB/wPCAf8w
AAPCAf8DwgH/A5IB/wPCAf80AAPCAf8DwgH/NAADMAH/AwAB/wMAAf8DMAH/MAADggH/AzAB/wMw
Af8DUAH/MAADkgH/A4IB/wOCAf8DkgH/MAADwgH/A8IB/wPCAf8DwgH/MAADMAH/AwAB/wMAAf8D
MAH/MAADUAH/AzAB/wMwAf8DggH/MAADkgH/A5IB/wOSAf8DkgH/MAADwgH/A8IB/wPCAf8DwgH/
MAADwgH/AzAB/wMwAf8DwgH/MAADwgH/A1AB/wNQAf8DwgH/MAADwgH/A5IB/wOSAf8DwgH/NAAD
wgH/A8IB/3wAA8IB/wMwAf8DMAH/A8IB/zAAA8IB/wNQAf8DggH/A8IB/zAAA8IB/wPCAf8DkgH/
A8IB/xAAA8IB/wMwAf8DMAH/A8IB/1AAAzAB/wMAAf8DAAH/AzAB/zAAA4IB/wMwAf8DMAH/A1AB
/zAAA5IB/wOCAf8DggH/A5IB/xAAAzAB/wMAAf8DAAH/AzAB/1AAAzAB/wMAAf8DAAH/AzAB/zAA
A1AB/wMwAf8DMAH/A4IB/wOSAf8DMAH/AzAB/wPCAf8gAAOSAf8DkgH/A5IB/wOSAf8DwgH/A1AB
/wOCAf8DwgH/AzAB/wMAAf8DAAH/AzAB/1AAA8IB/wMwAf8DMAH/A8IB/zAAA8IB/wOCAf8DUAH/
A8IB/wMwAf8DAAH/AwAB/wMwAf8gAAPCAf8DkgH/A5IB/wPCAf8DggH/AzAB/wMwAf8DUAH/A8IB
/wMwAf8DMAH/A8IB/6AAAzAB/wMAAf8DAAH/AzAB/zAAA1AB/wMwAf8DMAH/A4IB/7AAA8IB/wMw
Af8DMAH/A8IB/zAAA8IB/wOCAf8DUAH/A8IB/xgAAUIBTQE+BwABPgMAASgDAAFAAwABMAMAAQEB
AAEBBQABgAEBFgAD/4EABP8B/AE/AfwBPwT/AfwBPwH8AT8D/wHDAfwBAwHAASMD/wHDAfwBAwHA
AQMD/wHDAf8DwwP/AcMB/wPDAf8B8AH/AfAB/wHwAf8B+QH/AfAB/wHwAf8B8AH/AfAB/wHwAf8B
8AH/AfAB/wHwAf8B8AH/AfAB/wHwAf8B+QHnAcMB/wHDAf8B5wL/AsMB/wHDAf8BwwL/AcABAwH+
AUMB/wHDAv8B5AEDAfwBAwH/AecC/wH8AT8B/AE/BP8B/AE/Af4BfwT/AfwBPwH+AX8E/wH8AT8B
/AE/BP8BwAEnAcABPwHnA/8BwAEDAcIBfwHDA/8DwwH/AcMD/wHDAecBwwH/AecD/wEPAf8BDwH/
AQ8B/wGfAf8BDwH/AQ8B/wEPAf8BDwH/AQ8B/wEPAf8BDwH/AQ8B/wEPAf8BDwH/AQ8B/wGfA/8B
wwH/AcMB/wLDAv8BwwH/AcMB/wLDAv8BwwH/AcABPwHAAQMC/wHDAf8BwAE/AcABAwT/AfwBPwH8
AT8E/wH8AT8B/AE/Cw=='))
	#endregion
	$imagelistAnimation.ImageStream = $Formatter_binaryFomatter.Deserialize($System_IO_MemoryStream)
	$Formatter_binaryFomatter = $null
	$System_IO_MemoryStream = $null
	$imagelistAnimation.TransparentColor = 'Transparent'
	#
	# timerCheckJob
	#
	$timerCheckJob.add_Tick($timerCheckJob_Tick2)
	#endregion Generated Form Code
	
	#region NotifyIcon                  ###########

	# Create the NotifyIcon object
	$notifyIcon = New-Object System.Windows.Forms.NotifyIcon

	$base64IconData = '/9j/4AAQSkZJRgABAgEBLAEsAAD/7QAsUGhvdG9zaG9wIDMuMAA4QklNA+0AAAAAABABLAAAAAEAAQEsA
AAAAQAB/+Fnemh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8APD94cGFja2V0IGJlZ2luPSLvu78iIG
lkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4KPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczp
tZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNS42LWMxNDggNzkuMTY0MDUwLCAyMDE5LzEwLzAx
LTE4OjAzOjE2ICAgICAgICAiPgogICA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnL
zE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPgogICAgICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD
0iIgogICAgICAgICAgICB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iCiA
gICAgICAgICAgIHhtbG5zOnhtcD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wLyIKICAgICAgICAg
ICAgeG1sbnM6eG1wR0ltZz0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL2cvaW1nLyIKICAgICAgI
CAgICAgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iCiAgICAgICAgIC
AgIHhtbG5zOnN0UmVmPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VSZWY
jIgogICAgICAgICAgICB4bWxuczpzdEV2dD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBl
L1Jlc291cmNlRXZlbnQjIgogICAgICAgICAgICB4bWxuczppbGx1c3RyYXRvcj0iaHR0cDovL25zLmFkb
2JlLmNvbS9pbGx1c3RyYXRvci8xLjAvIgogICAgICAgICAgICB4bWxuczpwZGY9Imh0dHA6Ly9ucy5hZG
9iZS5jb20vcGRmLzEuMy8iCiAgICAgICAgICAgIHhtbG5zOnBkZng9Imh0dHA6Ly9ucy5hZG9iZS5jb20
vcGRmeC8xLjMvIj4KICAgICAgICAgPGRjOmZvcm1hdD5pbWFnZS9qcGVnPC9kYzpmb3JtYXQ+CiAgICAg
ICAgIDxkYzp0aXRsZT4KICAgICAgICAgICAgPHJkZjpBbHQ+CiAgICAgICAgICAgICAgIDxyZGY6bGkge
G1sOmxhbmc9IngtZGVmYXVsdCI+SHVuZ2VyUnVzaF9JY29uX1JHQjwvcmRmOmxpPgogICAgICAgICAgIC
A8L3JkZjpBbHQ+CiAgICAgICAgIDwvZGM6dGl0bGU+CiAgICAgICAgIDx4bXA6Q3JlYXRvclRvb2w+QWR
vYmUgSWxsdXN0cmF0b3IgMjQuMCAoTWFjaW50b3NoKTwveG1wOkNyZWF0b3JUb29sPgogICAgICAgICA8
eG1wOkNyZWF0ZURhdGU+MjAyMC0wMi0wNlQxNDoxNDo1MC0wODowMDwveG1wOkNyZWF0ZURhdGU+CiAgI
CAgICAgIDx4bXA6TW9kaWZ5RGF0ZT4yMDIwLTAyLTA2VDIyOjE0OjU1WjwveG1wOk1vZGlmeURhdGU+Ci
AgICAgICAgIDx4bXA6TWV0YWRhdGFEYXRlPjIwMjAtMDItMDZUMTQ6MTQ6NTAtMDg6MDA8L3htcDpNZXR
hZGF0YURhdGU+CiAgICAgICAgIDx4bXA6VGh1bWJuYWlscz4KICAgICAgICAgICAgPHJkZjpBbHQ+CiAg
ICAgICAgICAgICAgIDxyZGY6bGkgcmRmOnBhcnNlVHlwZT0iUmVzb3VyY2UiPgogICAgICAgICAgICAgI
CAgICA8eG1wR0ltZzp3aWR0aD4yNTY8L3htcEdJbWc6d2lkdGg+CiAgICAgICAgICAgICAgICAgIDx4bX
BHSW1nOmhlaWdodD4yNTY8L3htcEdJbWc6aGVpZ2h0PgogICAgICAgICAgICAgICAgICA8eG1wR0ltZzp
mb3JtYXQ+SlBFRzwveG1wR0ltZzpmb3JtYXQ+CiAgICAgICAgICAgICAgICAgIDx4bXBHSW1nOmltYWdl
Pi85ai80QUFRU2taSlJnQUJBZ0VCTEFFc0FBRC83UUFzVUdodmRHOXphRzl3SURNdU1BQTRRa2xOQSswQ
UFBQUFBQkFCTEFBQUFBRUEmI3hBO0FRRXNBQUFBQVFBQi8rSU1XRWxEUTE5UVVrOUdTVXhGQUFFQkFBQU
1TRXhwYm04Q0VBQUFiVzUwY2xKSFFpQllXVm9nQjg0QUFnQUomI3hBO0FBWUFNUUFBWVdOemNFMVRSbFF
BQUFBQVNVVkRJSE5TUjBJQUFBQUFBQUFBQUFBQUFBQUFBUGJXQUFFQUFBQUEweTFJVUNBZ0FBQUEmI3hB
O0FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBU
lkzQnlkQUFBQVZBQUFBQXomI3hBO1pHVnpZd0FBQVlRQUFBQnNkM1J3ZEFBQUFmQUFBQUFVWW10d2RBQU
FBZ1FBQUFBVWNsaFpXZ0FBQWhnQUFBQVVaMWhaV2dBQUFpd0EmI3hBO0FBQVVZbGhaV2dBQUFrQUFBQUF
VWkcxdVpBQUFBbFFBQUFCd1pHMWtaQUFBQXNRQUFBQ0lkblZsWkFBQUEwd0FBQUNHZG1sbGR3QUEmI3hB
O0E5UUFBQUFrYkhWdGFRQUFBL2dBQUFBVWJXVmhjd0FBQkF3QUFBQWtkR1ZqYUFBQUJEQUFBQUFNY2xSU
1F3QUFCRHdBQUFnTVoxUlMmI3hBO1F3QUFCRHdBQUFnTVlsUlNRd0FBQkR3QUFBZ01kR1Y0ZEFBQUFBQk
RiM0I1Y21sbmFIUWdLR01wSURFNU9UZ2dTR1YzYkdWMGRDMVEmI3hBO1lXTnJZWEprSUVOdmJYQmhibmt
BQUdSbGMyTUFBQUFBQUFBQUVuTlNSMElnU1VWRE5qRTVOall0TWk0eEFBQUFBQUFBQUFBQUFBQVMmI3hB
O2MxSkhRaUJKUlVNMk1UazJOaTB5TGpFQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQ
UFBQUFBQUFBQUFBQUFBQUEmI3hBO0FBQUFBQUFBQUFBQUFGaFpXaUFBQUFBQUFBRHpVUUFCQUFBQUFSYk
1XRmxhSUFBQUFBQUFBQUFBQUFBQUFBQUFBQUJZV1ZvZ0FBQUEmI3hBO0FBQUFiNklBQURqMUFBQURrRmh
aV2lBQUFBQUFBQUJpbVFBQXQ0VUFBQmphV0ZsYUlBQUFBQUFBQUNTZ0FBQVBoQUFBdHM5a1pYTmomI3hB
O0FBQUFBQUFBQUJaSlJVTWdhSFIwY0RvdkwzZDNkeTVwWldNdVkyZ0FBQUFBQUFBQUFBQUFBQlpKUlVNZ
2FIUjBjRG92TDNkM2R5NXAmI3hBO1pXTXVZMmdBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU
FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBWkdWell3QUEmI3hBO0FBQUFBQUF1U1VWRElEWXhPVFk
yTFRJdU1TQkVaV1poZFd4MElGSkhRaUJqYjJ4dmRYSWdjM0JoWTJVZ0xTQnpVa2RDQUFBQUFBQUEmI3hB
O0FBQUFBQUF1U1VWRElEWXhPVFkyTFRJdU1TQkVaV1poZFd4MElGSkhRaUJqYjJ4dmRYSWdjM0JoWTJVZ
0xTQnpVa2RDQUFBQUFBQUEmI3hBO0FBQUFBQUFBQUFBQUFBQUFBQUFBQUdSbGMyTUFBQUFBQUFBQUxGSm
xabVZ5Wlc1alpTQldhV1YzYVc1bklFTnZibVJwZEdsdmJpQnAmI3hBO2JpQkpSVU0yTVRrMk5pMHlMakV
BQUFBQUFBQUFBQUFBQUN4U1pXWmxjbVZ1WTJVZ1ZtbGxkMmx1WnlCRGIyNWthWFJwYjI0Z2FXNGcmI3hB
O1NVVkROakU1TmpZdE1pNHhBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQjJhV1YzQUFBQ
UFBQVRwUDRBRkY4dUFCRFAmI3hBO0ZBQUQ3Y3dBQkJNTEFBTmNuZ0FBQUFGWVdWb2dBQUFBQUFCTUNWWU
FVQUFBQUZjZjUyMWxZWE1BQUFBQUFBQUFBUUFBQUFBQUFBQUEmI3hBO0FBQUFBQUFBQUFBQUFBS1BBQUF
BQW5OcFp5QUFBQUFBUTFKVUlHTjFjbllBQUFBQUFBQUVBQUFBQUFVQUNnQVBBQlFBR1FBZUFDTUEmI3hB
O0tBQXRBRElBTndBN0FFQUFSUUJLQUU4QVZBQlpBRjRBWXdCb0FHMEFjZ0IzQUh3QWdRQ0dBSXNBa0FDV
kFKb0Fud0NrQUtrQXJnQ3kmI3hBO0FMY0F2QURCQU1ZQXl3RFFBTlVBMndEZ0FPVUE2d0R3QVBZQSt3RU
JBUWNCRFFFVEFSa0JId0VsQVNzQk1nRTRBVDRCUlFGTUFWSUImI3hBO1dRRmdBV2NCYmdGMUFYd0Jnd0d
MQVpJQm1nR2hBYWtCc1FHNUFjRUJ5UUhSQWRrQjRRSHBBZklCK2dJREFnd0NGQUlkQWlZQ0x3STQmI3hB
O0FrRUNTd0pVQWwwQ1p3SnhBbm9DaEFLT0FwZ0NvZ0tzQXJZQ3dRTExBdFVDNEFMckF2VURBQU1MQXhZR
ElRTXRBemdEUXdOUEExb0QmI3hBO1pnTnlBMzREaWdPV0E2SURyZ082QThjRDB3UGdBK3dEK1FRR0JCTU
VJQVF0QkRzRVNBUlZCR01FY1FSK0JJd0VtZ1NvQkxZRXhBVFQmI3hBO0JPRUU4QVQrQlEwRkhBVXJCVG9
GU1FWWUJXY0Zkd1dHQlpZRnBnVzFCY1VGMVFYbEJmWUdCZ1lXQmljR053WklCbGtHYWdaN0Jvd0cmI3hB
O25RYXZCc0FHMFFiakJ2VUhCd2NaQnlzSFBRZFBCMkVIZEFlR0I1a0hyQWUvQjlJSDVRZjRDQXNJSHdne
UNFWUlXZ2h1Q0lJSWxnaXEmI3hBO0NMNEkwZ2puQ1BzSkVBa2xDVG9KVHdsa0NYa0pqd21rQ2JvSnp3bm
xDZnNLRVFvbkNqMEtWQXBxQ29FS21BcXVDc1VLM0FyekN3c0wmI3hBO0lnczVDMUVMYVF1QUM1Z0xzQXZ
JQytFTCtRd1NEQ29NUXd4Y0RIVU1qZ3luRE1BTTJRenpEUTBOSmcxQURWb05kQTJPRGFrTnd3M2UmI3hB
O0RmZ09FdzR1RGtrT1pBNS9EcHNPdGc3U0R1NFBDUThsRDBFUFhnOTZENVlQc3cvUEQrd1FDUkFtRUVNU
VlSQitFSnNRdVJEWEVQVVImI3hBO0V4RXhFVThSYlJHTUVhb1J5UkhvRWdjU0poSkZFbVFTaEJLakVzTV
M0eE1ERXlNVFF4TmpFNE1UcEJQRkUrVVVCaFFuRkVrVWFoU0wmI3hBO0ZLMFV6aFR3RlJJVk5CVldGWGd
WbXhXOUZlQVdBeFltRmtrV2JCYVBGcklXMWhiNkZ4MFhRUmRsRjRrWHJoZlNGL2NZR3hoQUdHVVkmI3hB
O2loaXZHTlVZK2hrZ0dVVVpheG1SR2JjWjNSb0VHaW9hVVJwM0dwNGF4UnJzR3hRYk94dGpHNG9ic2h2Y
UhBSWNLaHhTSEhzY294ek0mI3hBO0hQVWRIaDFISFhBZG1SM0RIZXdlRmg1QUhtb2VsQjYrSHVrZkV4OC
tIMmtmbEIrL0grb2dGU0JCSUd3Z21DREVJUEFoSENGSUlYVWgmI3hBO29TSE9JZnNpSnlKVklvSWlyeUx
kSXdvak9DTm1JNVFqd2lQd0pCOGtUU1I4SktzazJpVUpKVGdsYUNXWEpjY2w5eVluSmxjbWh5YTMmI3hB
O0p1Z25HQ2RKSjNvbnF5ZmNLQTBvUHloeEtLSW8xQ2tHS1RncGF5bWRLZEFxQWlvMUttZ3FteXJQS3dJc
k5pdHBLNTByMFN3RkxEa3MmI3hBO2JpeWlMTmN0REMxQkxYWXRxeTNoTGhZdVRDNkNMcmN1N2k4a0wxb3
ZrUy9ITC80d05UQnNNS1F3MnpFU01Vb3hnakc2TWZJeUtqSmomI3hBO01wc3kxRE1OTTBZemZ6TzRNL0U
wS3pSbE5KNDAyRFVUTlUwMWh6WENOZjAyTnpaeU5xNDI2VGNrTjJBM25EZlhPQlE0VURpTU9NZzUmI3hB
O0JUbENPWDg1dkRuNU9qWTZkRHF5T3U4N0xUdHJPNm83NkR3blBHVThwRHpqUFNJOVlUMmhQZUErSUQ1Z
1BxQSs0RDhoUDJFL29qL2kmI3hBO1FDTkFaRUNtUU9kQktVRnFRYXhCN2tJd1FuSkN0VUwzUXpwRGZVUE
FSQU5FUjBTS1JNNUZFa1ZWUlpwRjNrWWlSbWRHcTBid1J6VkgmI3hBO2UwZkFTQVZJUzBpUlNOZEpIVWx
qU2FsSjhFbzNTbjFLeEVzTVMxTkxta3ZpVENwTWNreTZUUUpOU2syVFRkeE9KVTV1VHJkUEFFOUomI3hB
O1Q1TlAzVkFuVUhGUXUxRUdVVkJSbTFIbVVqRlNmRkxIVXhOVFgxT3FVL1pVUWxTUFZOdFZLRlYxVmNKV
0QxWmNWcWxXOTFkRVY1SlgmI3hBOzRGZ3ZXSDFZeTFrYVdXbFp1Rm9IV2xaYXBscjFXMFZibFZ2bFhEVm
NobHpXWFNkZGVGM0pYaHBlYkY2OVh3OWZZVit6WUFWZ1YyQ3EmI3hBO1lQeGhUMkdpWWZWaVNXS2NZdkJ
qUTJPWFkrdGtRR1NVWk9sbFBXV1NaZWRtUFdhU1p1aG5QV2VUWitsb1AyaVdhT3hwUTJtYWFmRnEmI3hB
O1NHcWZhdmRyVDJ1bmEvOXNWMnl2YlFodFlHMjViaEp1YTI3RWJ4NXZlRy9SY0N0d2huRGdjVHB4bFhId
2NrdHlwbk1CYzExenVIUVUmI3hBO2RIQjB6SFVvZFlWMTRYWStkcHQyK0hkV2Q3TjRFWGh1ZU14NUtubU
plZWQ2Um5xbGV3UjdZM3ZDZkNGOGdYemhmVUY5b1g0QmZtSismI3hBO3duOGpmNFIvNVlCSGdLaUJDb0Z
yZ2MyQ01JS1NndlNEVjRPNmhCMkVnSVRqaFVlRnE0WU9obktHMTRjN2g1K0lCSWhwaU02Sk00bVomI3hB
O2lmNktaSXJLaXpDTGxvdjhqR09NeW8weGpaaU4vNDVtanM2UE5vK2VrQWFRYnBEV2tUK1JxSklSa25xU
zQ1Tk5rN2FVSUpTS2xQU1YmI3hBO1g1WEpsalNXbjVjS2wzV1g0SmhNbUxpWkpKbVFtZnlhYUpyVm0wS2
JyNXdjbkltYzk1MWtuZEtlUUo2dW54MmZpNS82b0dtZzJLRkgmI3hBO29iYWlKcUtXb3dhamRxUG1wRmF
reDZVNHBhbW1HcWFMcHYybmJxZmdxRktveEtrM3FhbXFIS3FQcXdLcmRhdnByRnlzMEsxRXJiaXUmI3hB
O0xhNmhyeGF2aTdBQXNIV3c2ckZnc2RheVM3TENzeml6cnJRbHRKeTFFN1dLdGdHMmViYnd0MmkzNExoW
nVORzVTcm5DdWp1NnRic3UmI3hBO3U2ZThJYnlidlJXOWo3NEt2b1MrLzc5NnYvWEFjTURzd1dmQjQ4Sm
Z3dHZEV01QVXhGSEV6c1ZMeGNqR1JzYkR4MEhIdjhnOXlMekomI3hBO09zbTV5ampLdDhzMnk3Yk1OY3k
xelRYTnRjNDJ6cmJQTjgrNDBEblF1dEU4MGI3U1A5TEIwMFRUeHRSSjFNdlZUdFhSMWxYVzJOZGMmI3hB
OzErRFlaTmpvMld6WjhkcDIydnZiZ053RjNJcmRFTjJXM2h6ZW90OHAzNi9nTnVDOTRVVGh6T0pUNHR2a
lkrUHI1SFBrL09XRTVnM20mI3hBO2x1Y2Y1Nm5vTXVpODZVYnAwT3BiNnVYcmNPdjc3SWJ0RWUyYzdpan
V0TzlBNzh6d1dQRGw4WEx4Ly9LTTh4bnpwL1EwOU1MMVVQWGUmI3hBOzltMzIrL2VLK0JuNHFQazQrY2Y
2Vi9ybiszZjhCL3lZL1NuOXV2NUwvdHovYmYvLy8rNEFEa0ZrYjJKbEFHVEFBQUFBQWYvYkFJUUEmI3hB
O0JnUUVCQVVFQmdVRkJna0dCUVlKQ3dnR0JnZ0xEQW9LQ3dvS0RCQU1EQXdNREF3UURBNFBFQThPREJNV
EZCUVRFeHdiR3hzY0h4OGYmI3hBO0h4OGZIeDhmSHdFSEJ3Y05EQTBZRUJBWUdoVVJGUm9mSHg4Zkh4OG
ZIeDhmSHg4Zkh4OGZIeDhmSHg4Zkh4OGZIeDhmSHg4Zkh4OGYmI3hBO0h4OGZIeDhmSHg4Zkh4OGZIeDh
mLzhBQUVRZ0JBQUVBQXdFUkFBSVJBUU1SQWYvRUFhSUFBQUFIQVFFQkFRRUFBQUFBQUFBQUFBUUYmI3hB
O0F3SUdBUUFIQ0FrS0N3RUFBZ0lEQVFFQkFRRUFBQUFBQUFBQUFRQUNBd1FGQmdjSUNRb0xFQUFDQVFNR
EFnUUNCZ2NEQkFJR0FuTUImI3hBO0FnTVJCQUFGSVJJeFFWRUdFMkVpY1lFVU1wR2hCeFd4UWlQQlV0SG
hNeFppOENSeWd2RWxRelJUa3FLeVkzUENOVVFuazZPek5oZFUmI3hBO1pIVEQwdUlJSm9NSkNoZ1poSlJ
GUnFTMFZ0TlZLQnJ5NC9QRTFPVDBaWFdGbGFXMXhkWGw5V1oyaHBhbXRzYlc1dlkzUjFkbmQ0ZVgmI3hB
O3A3ZkgxK2YzT0VoWWFIaUltS2k0eU5qbytDazVTVmxwZVltWnFibkoyZW41S2pwS1dtcDZpcHFxdXNyY
TZ2b1JBQUlDQVFJREJRVUUmI3hBO0JRWUVDQU1EYlFFQUFoRURCQ0VTTVVFRlVSTmhJZ1p4Z1pFeW9iSH
dGTUhSNFNOQ0ZWSmljdkV6SkRSRGdoYVNVeVdpWTdMQ0IzUFMmI3hBO05lSkVneGRVa3dnSkNoZ1pKalp
GR2lka2RGVTM4cU96d3lncDArUHpoSlNrdE1UVTVQUmxkWVdWcGJYRjFlWDFSbFptZG9hV3ByYkcmI3hB
OzF1YjJSMWRuZDRlWHA3ZkgxK2YzT0VoWWFIaUltS2k0eU5qbytEbEpXV2w1aVptcHVjblo2ZmtxT2twY
WFucUttcXE2eXRycSt2L2EmI3hBO0FBd0RBUUFDRVFNUkFEOEE5VTRxN0ZYWXE3RlhZcTdGWFlxN0ZYWX
E3RlV2MWp6RG9laXdldHF0OURaUm5kZldjS1dwL0t2Mm0rZ1kmI3hBO1FMYThtYUVCY2pUenpYUCtjaGZ
LZG1XVFM3YTQxU1FkSHA5WGlQOEFzbkJmL2hNbU1aZGRsN1h4ajZRWmZZd2JWZjhBbklYemxja3ImI3hB
O1lXOXJwOGY3SkNHYVFmTm5QRC9oTW1NWWNESjJ2bFBJQU1Wdi93QXovd0F3TDRuMTlkdWxyMUVEQzNIL
0FDUkVlUzRBNGs5Ym1semsmI3hBO2Z1KzVKTGpXdFl1VFc1dnJpYytNa3J2MnArMFRocG9PU1I1a29QQ3
dkaXFNdDlhMWkyTmJhK3VJRDR4eXVuYW43SkdDbVl5U0hJbE8mI3hBOzdEOHovd0F3TEVqME5kdW1wMEU
3QzRIL0FDV0VtRGdEZkRXNW84cEg3L3ZaVnBYL0FEa0w1eXRpRnY3ZTExQ1A5b2xERElma3lIaC8mI3hB
O3dtUk9NT1hqN1h5am1BV2M2SC96a0w1VHZDcWFwYlhHbHlIcTlQckVRLzJTQVA4QThKa0RqTG40dTE4W
itvR1AydlE5SDh3NkhyVUgmI3hBO3JhVmZRM3NZM2IwWERGYS96TDlwZnBHUUlwMk9QTkNZdUp0TU1EWT
dGWFlxN0ZYWXE3RlhZcTdGWFlxN0ZYWXE3RlhZcTdGWFlxN0YmI3hBO1hZcTdGV00rYnZ6RjhxK1Zveit
rcm9QZDBxbGhCU1NkdTQrR280ajNZZ1pJUkpjWFVhekhpK283OTNWNHY1cS9QdnpUcVplRFIxWFMmI3hB
O0xRN0IxcEpjTVBlUmh4WC9BR0sxOTh0R01Pa3o5cTVKYlI5SSsxNXJkM2wzZVhEM0YzUEpjWEVockpOS
3pPN0gzWmlTY202MlVpVFomI3hBOzNLbGhZdXhWMkt1eFYyS3V4VjJLdXhWMkt1eFZWdEx5N3M3aExpMG
5rdDdpTTFqbWlaa2RUN01wQkdCbEdSQnNiRjZWNVYvUHZ6VHAmI3hBO2hTRFdGWFY3UWJGMnBIY0tQYVJ
SeGIvWkxYM3lCeGgyV0R0WEpIYVhxSDJ2YVBLUDVpK1ZmTk1ZL1J0MEV1NlZld25wSE92Yy9EVTgmI3hB
O2g3cVNNcU1TSGQ2ZldZOHYwbmZ1NnNteUxsT3hWMkt1eFYyS3V4VjJLdXhWMkt1eFYyS3V4VjJLdXhWQ
zZwcXVtNlZZeTMybzNDV3QmI3hBO3BDS3lUU0dnSHNQRW5zQnVjSURDZVNNQmNqUWVFK2UvejcxRytNbG
o1WURXTm51clg3ai9BRWh4L2tEcEdQOEFodmxsc2NmZTZIVmQmI3hBO3F5bHRqMkhmMWVTU3l5elN0TEs
3U1N1U3p5T1N6TVQxSkozT1dPb0p2bXR3b2RpcnNWZGlyc1ZkaXJzVmRpcnNWZGlyc1ZkaXJzVmQmI3hB
O2lxNktXV0dWWlluYU9WQ0dTUkNWWlNPaEJHNHdKQnJrOWI4aWZuM3FOaVk3SHpPR3ZyUFpWdjBIK2tJU
DhzZEpCL3czenl1V1B1ZHYmI3hBO3BlMVpSMnlianY2dmR0TDFYVGRWc1lyN1RyaExxMG1GWTVvelVIMl
BnUjNCM0dWRU8raGtqTVhFMkVWZ1p1eFYyS3V4VjJLdXhWMksmI3hBO3V4VjJLdXhWMktzYjg3K2ZORDh
vNmQ5WnYzOVM2a0IrcVdLRWVwS3cvd0NJcU83SHA4OXNsR051TnFkVkRER3p6N256UDV5ODlhOTUmI3hB
O3N2emM2bExTQkNmcTFsR1NJWWgva3IzYnhZNzVmR0lEekdwMVU4cHVYeVk5a25HZGlyc1ZkaXJzVmRpc
nNWZGlyc1ZkaXJzVmRpcnMmI3hBO1ZkaXJzVmRpcnNWZGlySWZKdm5yWHZLZCtMblRaYXdPUjlac3BDVE
RLUDhBS1hzM2d3M3lNb2d1VHB0VlBFYmo4bjB4NUk4K2FINXUmI3hBOzA3NnpZUDZkMUdCOWJzWEk5U0p
qL3dBU1U5bUhYNTdaUktOUFQ2YlZRelJzYys1a21SY2wyS3V4VjJLdXhWMkt1eFYyS3V4VmgvNWomI3hB
O2ZtTnAzazNUbFpsRnpxdHlEOVRzNjByVFl5U0VkRUg0OUIzSWxHTnVIck5aSERIdmtlUWZNR3VhNXFtd
WFuTnFXcHp0Y1hjNXF6dDAmI3hBO0E3S282S283QVprQVU4dGx5eW5MaWtiS0J3dGJzVmRpcnNWZGlyc1
ZkaXJzVmRpcnNWZGlyc1ZkaXJzVmRpcnNWZGlyc1ZkaXJzVlImI3hBOzJoNjVxbWg2bkRxV21UdGIzY0J
xcnIwSTdxdzZNcDdnNENMYk1XV1VKY1VUUmZUL0FPWFA1amFkNXkwNW1WUmJhcmJBZlhMT3RhVjImI3hB
O0VrWlBWRCtIUTlpY2VVYWVwMGVzam1qM1NITU13eUxtT3hWMkt1eFYyS3V4VjJLc2I4K2VkOU84bzZHO
S9jMGt1cEtwWTJsYU5MSlQmI3hBOzhGWHF4N2ZPbVNqRzNHMVdwamhoWjU5SHlwcm11YW5ybXFUNm5xVX
hudTdodVRzZWdIWlZIWlZHd0daQUZQSjVjc3B5TXBjeWdjTFcmI3hBOzdGWFlxN0ZYWXE3RlhZcTdGWFl
xN0ZYWXE3RlhZcTdGWFlxN0ZYWXE3RlhZcTdGWFlxN0ZVZG9ldWFub2VxUWFucHN4Z3U3ZHVTTU8mI3hB
O2hIZFdIZFdHeEdBaTJ6RmxsQ1FsSG1IMVg1RDg3NmQ1dTBOTCsycEhkUjBTK3RLMWFLU240cTNWVDMrZ
GN4NVJwNnpTNm1PYUZqbjEmI3hBO1pKa1hKZGlyc1ZkaXJzVlF1cTZwWTZWcHR4cU45S0liUzFReVRTSH
NCMkhpVDBBN25DQXd5VEVJbVI1QjhtK2V2T1YvNXMxNlhVcmsmI3hBO2xJQldPeXRxN1JRZy9DditzZXJ
IeHpJakdnOGxxdFNjcytJL0JqMlNjWjJLdXhWMkt1eFYyS3V4VjJLdXhWMkt1eFZVanQ3aVJlVWMmI3hB
O1R1dlNxcVNQd3dKb3VrdDdpTmVVa1RvdlNyS1FQeHhXaXA0VU94VjJLdXhWMkt1eFYyS3V4VjJLdXhWM
ktzaDhpK2NyL3dBcDY5RnEmI3hBO1ZzUzhCcEhlMjFkcFlTZmlYL1dIVlQ0NUdVYkRrNlhVbkZQaUh4Zl
dXbGFwWTZycHR2cU5qS0pyUzZRU1F5RHVEMlBnUjBJN0hNY2gmI3hBOzYzSE1UaUpEa1VWZ1p1eFYyS3V
4VjgvL0FKOStlemZhaVBMRmpKL29kaXdlL1pUczl4MlQ1UmovQUliNVpkamoxZWU3VjFYRkx3eHkmI3hB
O0hQM3ZJc3RkTzdGWFlxN0ZYWXE3RlhZcTdGWFlxeVB5bitYM21uelRJUDBYYUg2cUR4a3ZwdjNjQ252O
ForMFI0S0NjaVpBT1RnMG0mI3hBO1RMOUkyNytqMkR5NS93QTQ4ZVhyVlZrMTI3bDFHZWdMUVJFd1FnOX
hVSDFHK2ZKZmxsUnlIbzduRDJSQWZXYmVnYVg1SjhvNlVvRmgmI3hBO3BGckNWNlNla3JTZlRJd1p6OSt
RTWk3Q0dseHc1UkNkQUFBQUNnSFFZRzl4QUlJSXFEMUdLcExxbmtueWpxcWtYK2tXc3hicko2U3ImI3hB
O0o5RWloWEgzNFJJdEU5TGpuemlIbi9tUC9uSGp5OWRLMG1oWGN1blQwSldDVW1lRW5zS2srb3Z6NU44c
21NaDZ1dnpka1FQMEduai8mI3hBO0FKcy9MN3pUNVdrUDZVdEQ5Vko0eDMwUDd5QmoyK01mWko4R0FPV2
lRTHBzK2t5WXZxRzNmMFk1a25HZGlyc1ZkaXJzVmRpcnNWZGkmI3hBO3JzVmV1L2tKNTdOanFKOHNYMG4
raDN6RjdCbU95WEhkUGxJUCtHK2VWWkk5WGNkbGFyaGw0WjVIbDczMEJsTDBMc1ZkaXJHZnpGODMmI3hB
O1IrVnZLdDFxVlI5YmNlaFlJZjJwNUFlT3g3TFFzZllaS0lzdUxyTlI0V015NjlQZStTcFpaWnBYbGxZd
kxJeGVSMk5Tek1ha2srNXomI3hBO0llUkp2ZGJoUTdGWFlxN0ZYWXE3RlhZcTRBa2dBVkoyQUdLdmJQeT
MvSXRaRWkxYnpaR1FHQWUzMG1wVTA2ZzNCRy8rd0greThNcGwmI3hBO2s3bmVhUHN1L1ZrK1g2M3QxdmI
yOXRDa0Z2RWtNRVlDeHhScUZSVkhRS29vQU1xZDRBQUtDL0ZMc1ZkaXJzVmRpcnNWV1hGdmIzTUwmI3hB
O3dYRVNUUVNBckpGSW9aR1U5UXltb0l4UVFDS0x4SDh5UHlMV05KZFc4cHhraFFYdU5KcVdOT3BOdVR2L
0FMQS83SHd5Mk9UdmRIck8mI3hBO3k2OVdQNWZxZUprRUVnaWhHeEJ5NTBic1ZkaXJzVmRpcnNWZGlyc1
ZYUlN5d3lwTEV4U1dOZzhicWFGV1UxQkI5amdTRFc3NjEvTHImI3hBO3pkSDVwOHEydXBWSDF0QjZGK2c
vWm5qQTViRHMxUXc5am1QSVVYcnRIcVBGeGlYWHI3MlRaRnluWXErY2Z6NzgxSFUvTks2UEE5YlQmI3hB
O1NGNHVCMGE0a0FhUS93Q3hYaXZ6cmwrTWJQTmRxNStMSndqbEg3M21HV09yZGlyc1ZkaXJzVmRpcnNWZ
GlyM3I4bHZ5dGp0SUlQTkcmI3hBO3RSY3J5VWM5TnRYRlJFakQ0Wm1CL2JZZlo4QnYxNlV6bjBkLzJib2
FBeVM1OVAxdlk4cWQwN0ZVQnJXdjZMb2RtYnpWcnlPenR4c0cmI3hBO2tOQ3g4RVVWWmo3S0NjSUZ0ZVh
OSEdMa2FEeXZYLzhBbkl6UzRYYUxROU5rdTZiQzV1VzlGUG1FVU16RDVsY3NHUHZkVGw3WWlQb0YmI3hB
Oys5aUYxL3prRDU4bWVzUzJkc3ZaWTRXYjhaSGZKZUdIRGwydG1QY0hXdjhBemtENThoZXNxMmR5dmRaS
VdYOFkzVEh3d3NlMXN3N2kmI3hBO3kvUVArY2pOTG1kWXRjMDJTMHJzYm0yYjFrK1pSZ3JLUGtXeUp4OX
ptWXUySW42eFh1ZXFhTHIraTY1Wmk4MG04anZMYzdGb3pVcWYmI3hBO0IxTkdVK3pBSEt5S2R0aXpSeUM
0bXdqOERZN0ZYam41MC9sYkhkd1QrYU5GaTQza1E1Nmxhb0tDVkZIeFRLQisybysxNGpmcjF0aFAmI3hB
O282WHRMUTJEa2p6Ni9yZUM1YzZCMkt1eFYyS3V4VjJLdXhWMkt2VC9BTWhQTlIwenpTMmp6dlMwMWRlS
0E5RnVJd1dqUCt5WGt2enAmI3hBO2xlUWJPMDdLejhPVGhQS1gzdm83S0hwVXY4dzZ4Qm91aDMycXpieD
JVTHpjVHR5S2o0Vi8yVFVHRUMydk5rRUlHUjZQamU4dTdpOHUmI3hBOzU3dTRjeVhGeEkwczBoNnM3c1d
ZL1NUbVM4WktSSnM4eXBZV0xzVmRpcnNWZGlyc1ZkaXJQZnljOGtMNW04ekNhOGo1NlRwbEpyb0UmI3hB
O2ZESTVQN3FJL3dDc1JVK3dJNzVDY3FEc096dE40dVRmNll2cURwbU85UzdGV0IvbVorYW1uK1VZUHFkc
0Z1OWRsWGxGYm43RVNucEomI3hBO0tSK0NqYyt3M3ljWVc2L1c2OFlSUTNtK2J0YzEvV05kdjN2OVd1bn
VybC8ybk95aitWRkh3cXZzQmw0RlBOWmNzcG01R3lsK0ZyZGkmI3hBO3JzVmRpcVlhSHIrc2FGZnBmNlR
kUGEzS2Z0SWRtSDhycWZoWmZZakFSYlppeXlnYmlhTDZSL0xQODFOUDgzUWZVN2tMYWE3RXZLVzMmI3hB
O0gySlZIV1NJbjhWTzQ5eHZsRW9VOUxvdGVNd283VFo1a0hZTzY0cStYL3pqOGtMNWE4ekdhemo0YVRxU
U05cUFQaGpldjcySWY2cE4mI3hBO1I3RWVHWkVKV0hsdTBkTjRXVGI2Wk1DeWJyM1lxN0ZYWXE3RlhZcT
dGVld6dTdpenU0THUzY3gzRnZJc3NNZzZxNk1HVS9RUmdaUmsmI3hBO1FiSE1Qc2p5OXJFR3RhSFk2ckR
0SGV3cE54Ry9Fc1BpWC9ZdFVaakVVOW5oeUNjQklkWG5uL09RdXVHejhwMjJsbzFKTlV1QnpIakYmI3hB
O2IwZHYrSEtaUEdOM1hkcjVheGlQODQvYytkY3ZlYmRpcnNWZGlyc1ZkaXFhZVhQSyt1ZVk3OFdPa1dyW
E0zV1Joc2thL3dBMGpuWlImI3hBOy9tTUJOTnVIQlBJYWlMZTMrVmYrY2ZOQ3MwU2Z6Rk8ybzNQVnJhSX
RGYnI3VkZKSCtkVitXVW5KM084d2RrUUc4eloreDZmcFdqNlgmI3hBO3BGbXRscGxySFoycWtrUlJLRkZ
UMUpwMUo4VGtDYmRyanh4Z0tpS0NMd00yTytmdk45djVVOHQzR3FTQVBjYlJXVUIvM1pPNFBFSDImI3hB
O0ZDemV3eVVZMlhHMWVvR0tCbDE2UGt6VWRSdmRTdnA3KytsYWU3dVhNazByZFdZL3E5aDJ6SUR5TTVtU
kpQTW9mQ3hkaXJzVmRpcnMmI3hBO1ZkaXFJMDdVYjNUYjZDL3NaV2d1N1p4SkRLdlZXSDYvY2Q4QlpRbV
lrRWN3K3MvSVBtKzM4MStXN2ZWSXdFdU40cjJBZjdyblFEa0ImI3hBOzdHb1pmWTVqeWpSZXUwbW9HV0F
sMTZzaXlMa29UVmRIMHZWN05yTFU3V084dFdJSmlsVU1Lam9SWG9SNGpDRFRESmpqTVZJV0htSG0mI3hB
O3Ivbkh6UXJ4SG44dXp0cDF6MVcybExTMjdlMVRXUlBuVnZsa3hrNzNWWit5SUhlQm8vWThROHgrVjljO
HVYNXNkWHRXdHB1c2JIZEomI3hBO0YvbWpjYk1QOHpsd051anpZSjR6VWhTVjRXcDJLdXhWMkt1eFYyS3
Zvci9uSHJYRGVlVTduUzNhc21sM0I0RHdpdUt1di9EaDhveUQmI3hBO2Q2VHNqTGVNeC9tbjcyRGY4NUM
2cWJuemxiMkNuOTNwOXFnSytFa3hMc2YrQTRaUEdObkE3WHlYbEE3Zzh1eXgxVHNWZGlyc1ZkaXImI3hB
O0pmSVhrYlV2Tit0TFpXMVlyU0tqMzEzU3F4Ui9oVm02S1A0VnlNcFU1T2wwc3MwcUhMcStwUExmbG5SL
0xtbHg2YnBVQWhnVGQyTkQmI3hBO0pJL2Q1Ry9hWS8yRGJNY20zcThPQ09PUERFSnBnYlhZcTdGWHp4L3
prTDVoYTg4ejIyalJ2V0RUSVE4cWovZjgvd0FScjhvK0ZQbWMmI3hBO3Z4alo1enRmTnhaQkgrYjk1ZVU
1WTZsMkt1eFYyS3V4VjJLdXhWMkt2VnYrY2V2TUxXZm1lNTBhUjZRYW5DWGlVLzcvQUlQaUZQbkgmI3hB
O3pyOGhsZVFiTzI3SXpjT1F4L25mZUgwUGxEMGJzVmRpcVYrWlBMT2orWTlMazAzVllCTkErNk1LQ1NOK
3p4dCt5dy9zTzJFR21yTmcmI3hBO2prand5RDViOCsrUnRTOG9hMDFsYzFsdEphdlkzZEtMTEgrTkdYb3
cvaFRNaU1yZVUxV2xsaGxSNWRHTlpKeG5ZcTdGWFlxN0ZYcVAmI3hBOy9PUFdxbTI4NVhGZ3gvZDZoYXV
BdmpKQ1E2bi9BSURubGVRYk8xN0l5VmxJN3d4WDh6NzgzMzVnYTdQV3ZHNmFBSDJ0d0lmK1plU2gmI3hB
O3ljVFd6NHMwajUvZHN4akpPSzdGWFlxN0ZWUzJ0NTdtNGl0cmRESlBPNnh4UnJ1V2R6eFZSN2tuQWtBa
zBIMXI1QThtMnZsUHk1QnAmI3hBOzBZVnJwZ0piK2NmN3NtWWZGdjhBeXI5bGZiM3pIbEt5OWZwTk1NVU
JIcjFaSmtYSlVycTZ0clMza3VicVZJTGVGUzhzMGpCVVZSMUomI3hBO1k3REZFcEFDenllUmVhditjaDd
DMW1lMjh1V2YxNWtOUHJ0eHlTRTAva2pGSFllNUs1YU1mZTZiUDJ1QnRBWDVsZ3QzK2UvNWlUa20mI3hB
O0s2Z3RRZWdodDR5Qi93QWpSSmt2RERneTdVekhyWHdZTGZYMTVmM2sxN2V6TlBkVHNYbW1jMVptUGM1T
ndKU01qWjVxR0ZpN0ZYWXEmI3hBOzdGWFlxN0ZYWXE3RlZheHZydXd2SWJ5emxhQzZ0MkVrTXlHakt3Nk
VZR1VaR0pzYzJkMm41Ny9tSkFRWmJxQzZBNmlhM2pBUC9Jb1ImI3hBOzVEd3c1OGUxTXc2MzhHZGVWZjh
Bbklld3Vwa3R2TWRuOVJaelQ2N2I4bmhGZjU0elYxSHVDMlJPUHVjN0IydUR0TVY1aDY3YTNWdGQmI3hB
OzI4ZHpheXBQYnpLSGltallNaktlaEREWTVVN21NZ1JZNUt1S1dOK2YvSnRyNXM4dVQ2ZElGVzZVR1d3b
lArNjVsSHc3L3dBcmZaYjImI3hBOzk4bEdWRnh0WHBobGdZOWVqNUt1YmVlMnVKYmE0UXh6d08wY3NiYk
ZYUThXVSs0SXpJZVFJSU5GVHdvZGlyc1ZkaXJKL3dBc0w4MlAmI3hBOzVnYUZQV25LNldBbjJ1QVlmK1p
tUm55Y3JSVDRjMFQ1L2Zza210WEJ1ZFl2cms5WjdpV1E5UDIzTGR2bmhEUmtOeUo4MEhoWU94VjImI3hB
O0t1eFY2UitRM2w1ZFQ4NmZYNVY1VytreEdmMjlaL2dpQis5bUgrcmxlUTdPeTdMdzhXV3p5aStsY29lb
mRpcjVyL09UOHg3alg5V20mI3hBOzBhd2xLNkpZeUZDRk8xeE1obzBqVTZxcDJRZlQ4cjRScDVudEhXSE
pMaEgwajdYbTJXT3NkaXJzVmRpcnNWZGlyc1ZkaXJzVmRpcnMmI3hBO1ZkaXJzVmRpcjBuOG0vekh1TkE
xYUhScitVdG9sOUlFQVk3Vzh6bWl5TFhvckhaeDlQenJuRzNaOW5hdzQ1Y0oray9ZK2xNb2VtZGkmI3hB
O3I1cS9Qbnk4dW1lZFByOFM4YmZWb2hQN2VzbndTZ2ZjckgvV3kvR2RubU8xTVBEbHNjcFBOOHNkYTdGW
FlxN0ZVWm90d2JiV0xHNUgmI3hBO1dDNGlrSFQ5aHczZjVZQ3p4bXBBK2FEd3NIWXE3RlhZcTdGWDBEL3
pqaFlMSDVjMVMvcFI3aThFSlBpc0Vhc1B4bU9VWmViMFBZOFAmI3hBO1JJOTUrNysxNjVsYnVHTmZtVHJ
rbWllUjlYMUNKdUU2dytsQXdOQ0pKMkVTc3Z1cGZsOUdTaUxMaTYzTHdZcEVmaTN5UG1TOGc3RlgmI3hB
O1lxN0ZYWXE3RlhZcTdGWFlxN0ZYWXE3RlhZcTdGWFlxN0ZYMXgrVzJ1U2EzNUgwalVKVzV6dEQ2VTdFM
UprZ1l4TXplN0ZPWDA1alMmI3hBO0ZGNi9SWmVQRkVuOFV5WEl1VThqL3dDY2o3QlpQTG1sMzlLdmIzaG
hCOEZualpqK01JeXpGemRQMnhEMFJQY2Z2L3NmUDJYdlBPeFYmI3hBOzJLdXhWMkt1eFYyS3V4VjJLdXh
WOUlmODQ5RUh5Sk1BYTB2NWdmYjkzR2NveWMzcGV5UDdvLzF2MVBUY3Jkbzg5L1BlS1YveTd1bVMmI3hB
O3ZHT2VCcGFmeW1RTHYvc21HVHg4M1hkcWcrQ2ZlSHpKbVE4dTdGWFlxOTYvSlB5TjVVMUx5Z2RSMUxUW
WIyN211SkVNazYrb0ZWS0ImI3hBO1ZVSFlaVE9SdDMvWm1seHl4OFVoWnQ2Qi93QXE0OGgvOVdDeC93Q1
JLZjB5SEVYWS9rc1A4MFBPUHp5OGorVjlMOHNXMnA2WHA4VmomI3hBO2RKZEpDeGdYZ3JKSWpraGxHeDN
VVU9UeHlKTHJPMU5MamhqRW9pamJ3ekxuUk94VjJLdXhWN24rUnZrZnl2cW5saTUxUFZOUGl2cnAmI3hB
OzdwNFZNNDVxc2FJaEFWVHRXckdweW5KSWd1OTdMMHVPY0RLUXMyOUgvd0NWY2VRLytyQlkvd0RJbFA2W
kRpTHMvd0FsaC9taDUvOEEmI3hBO25aNUc4cWFiNVFHbzZicHNObGR3M0VhQ1NCZlRESzlReXNCc2NuQ1
J0MTNhZWx4eHg4VVJSdDRMbHpvSFlxN0ZYMDMrUkVVcWZsM2EmI3hBO3M5ZU1rODdSVi9sRWhYYi9BR1N
uTWZKemVvN0tCOEVlOHZRc2c3RjVsL3prS1FQSWtJSnBXL2hBOS8zY2h5ekh6ZFgydi9kRCt0K3QmI3hB
OzgzNWU4MDdGWFlxN0ZYWXFqTmF0emJheGZXeDZ3WEVzWjZmc09WN2ZMQUdlUVZJanpRZUZnN0ZYWXE3R
lh1bi9BRGpmckNHMTFmUlcmI3hBO2FqbzZYa0tlSWNlbklmbzRKOStVNVE3N3NiSnRLUHhlMDVVN3RML0
1HaTIydDZKZTZUYzdRM3NUUk13RlNwSStGd1BGV293d2cwMTUmI3hBO3NReVFNVDFmSUd1NkxmNkpxMTF
wVitucDNWcTVSeDJJN010ZXFzTndmRE1rRzNqc3VNd2tZbm1FRGhhM1lxK2wvd0FnL3dEeVgwWC8mI3hB
O0FERlQvckdZK1RtOVAyVC9BSFB4TDBiSU95ZVpmODVDZjhvSkYvekhRLzhBRUpNc3g4M1Y5ci8zUS9yZ
nJmTitYdk5PeFYyS3V4VjkmI3hBO0lmOEFPUGYvQUNna3YvTWROL3hDUEtNbk42WHNqKzZQOWI5VDAzSz
NhUE9mejgvOGw5TC9BTXhVSDZ6azhmTjF2YTM5ejhRK2FNeUgmI3hBO21IWXFqdEMwVy8xdlZyWFNyQlB
VdXJwd2lEc0IzWnFkRlViaytHQW1tekZqTTVDSTVsOWYrWDlGdHRFMFN5MG0yM2hzb2xpVmlLRmkmI3hB
O0I4VGtlTE5Wam1NVGIyT0hFTWNCRWRFd3dOanhiL25KRFdFRnJwR2lxMVhkM3ZKazhBZzlPTS9UemY3c
3R4QjBuYk9UYU1maThMeTUmI3hBOzBMc1ZkaXJzVlJtaTI1dWRZc2JZZFo3aUtNZFAyM0M5L25nTFBHTG
tCNXAzK1o5Z2JIOHdOZGdwVGxkTk9CN1hBRTMvQURNd1E1TismI3hBO3RodzVwRHorL2RqR1NjVjJLdXh
WMktzai9MM3pVL2xmelhaNm9TZnFvUG8zcWlwNVFTYlBzT3ZIWmdQRVpHUXNPVHBNL2haQkxwMTkmI3hB
O3o2M2dtaG5oam5oY1NReXFIamtVMVZsWVZEQWpxQ014bnJ3UVJZWDRwWVQrWlg1WjZmNXdzaExHVnR0Y
XQxcGEzWkd6TDE5S1dtNVcmI3hBO3ZROVYrOEdjWlU0T3QwUXpDK1VnK2FkZjh1NnpvR29QWWF0YXZiWE
M5T1ErRjEvbVJoc3krNHk4RzNtY3VHV00xSVVVdXd0VDZYL0kmI3hBO1AveVgwWC9NVlA4QXJHWStUbTl
QMlQvYy9FdlJzZzdKNWwvemtKL3lna1gvQURIUS93REVKTXN4ODNWOXIvM1EvcmZyZk4rWHZOT3gmI3hB
O1YyS3V4VjlJZjg0OS93REtDUy84eDAzL0FCQ1BLTW5ONlhzais2UDliOVQwM0szYVBPZno4LzhBSmZTL
zh4VUg2ems4Zk4xdmEzOXomI3hBOzhRK2FNeUhtRXgwRHk3ck92NmdsaHBOcTl6Y04xNGo0VVgrWjJPeX
I3bkFUVGJpd3l5R29peStsdnkxL0xQVC9BQ2ZaR1dRcmM2MWMmI3hBO0xTNnV3TmxYcjZVVmR3dGVwNnQ
5d0ZFcFc5Tm90RU1Jdm5JczJ5RG5MSjVvWUlaSjVuRWNNU2w1SkdORlZWRlN4SjZBREZCSUFzdmsmI3hB
O2o4d3ZOVCthUE5kNXFnSitxaytqWkthampCSHNteDZjdDJJOFRtVEVVSGtOWG44WElaZE9udVk1a25HZ
Glyc1ZkaXJKL3dBc0xBMzMmI3hBOzVnYUZCU3ZHNldjajJ0d1p2K1plUm55Y3JSUTRzMFI1L2R1eXIvbk
lYU2piZWNyZS9VZnU5UXRVSmJ4a2hKUmgvd0FCd3lPTTdPWDImI3hBO3ZqcktEM2g1ZGxqcW5ZcTdGWFl
xN0ZYdGY1SC9BSm14UXJINVUxaVVJbGFhVmN1YUFGai9BSERFKy8yUHU4TXF5UjZ1NzdNMXRmdTUmI3hB
O2ZEOVQzTEtYZk94VkE2eG9XajYxYUd6MVd6aXZMYzdoSlZCb2VsVlBWVDdnMXdnMDE1TVVaaXBDdytTd
k8ya1d1amViTlYweTA1ZlYmI3hBO2JXNGRJUXhxUW5VQW52U3RNeUltdzhqcWNZaGtsRWNnWHZ2NUIvOE
Frdm92K1lxZjlZeW5KemVnN0ovdWZpWG8yUWRrOHkvNXlFLzUmI3hBO1FTTC9BSmpvZitJU1paajV1cjd
YL3VoL1cvVytiOHZlYWRpcnNWZGlyNlEvNXg3L0FPVUVsLzVqcHY4QWlFZVVaT2IwdlpIOTBmNjMmI3hB
OzZucHVWdTBlYy9uNS93Q1MrbC81aW9QMW5KNCticmUxdjduNGg0RjVKMGkxMW56WnBXbVhmTDZyZFhDS
k1GTkNVNmtBOXEwcGwwalEmI3hBO2VmMDJNVHlSaWVSTDYxMGZRdEgwVzBGbnBWbkZaMjQzS1JLQlU5S3
NlckgzSnJtT1RiMTJQRkdBcUlvSTdBMk94VjRiK2VINW14VEwmI3hBO0o1VTBlVU9sYWFyY29hZ2xUL2N
LUjcvYis3eHk3SEhxNkh0UFczKzdqOGYxUEZNdGRJN0ZYWXE3RlhZcTlSLzV4NjBvM1BuSzR2MkgmI3hB
Ozd2VDdWeUc4SkppRVVmOEFBYzhyeUhaMnZaR084cFBjR2MvODVDNkdienluYmFvaTFrMHU0SE0rRVZ4U
kcvNGNKa01aM2MvdGZGZU0mI3hBO1MvbW43M3pybDd6YnNWZGlyc1ZkaXJzVmUwZmxwK2VQMWVPTFNQTm
NqUEV0RXR0Vm9XWlFOZ3M0RzdEL0FDK3ZqNDVWTEgzTzcwWGEmI3hBO2Rlbko4LzF2Y2JhNXQ3bUNPNHR
wVW1nbFVORkxHd1pHVTlDckRZaktYZXhrQ0xISlV4UytTdnpSL3dESmc2Ny9BTXhUZnFHWk1lVHkmI3hB
O0d0L3ZwZTk3ZitRZi9rdm92K1lxZjlZeW5KemQ3MlQvQUhQeEwwYklPeVd5Unh5S1VrVU9wNnF3QkgzS
EZCRm9DYnk1NWVuTlp0THQmI3hBO0pUV3Z4d1JOdWUrNjRiTFdjRUR6aVBraDVQSlhrMlJ1VW1nNmM3QV
VxMXBBVFQ2VXg0aXgvTFl2NXNma0hSK1N2SnNiY285QjA1R0kmI3hBO3BWYlNBR24wSmp4RmZ5MkwrYkg
1QkVRK1hQTDBCckRwZHBFYTErQ0NKZHgzMlhHeXlHQ0E1Ukh5UjhjY2NhaEkxQ0tPaXFBQjl3d04mI3hB
O2dGTHNVdk9mejgvOGw5TC9BTXhVSDZ6azhmTjF2YTM5ejhROFEvSzcvd0FtRG9YL0FERkwrbzVkTGs2T
FJmMzBmZSt0Y3hucjFPNXUmI3hBO2JlMmdrdUxtVklZSWxMU3l5TUZSVkhVc3gyQXhSS1FBczhuaDM1bC
9uajlZamwwanlwSXlSTlZMblZhRldZSFlyQUR1by95K3ZoNDUmI3hBO2RISDN1aTF2YWQrbkg4LzFQRjh
0ZEk3RlhZcTdGWFlxN0ZYMFYvemoxb1pzL0tkenFqclNUVkxnOEQ0eFc5VVgvaHkrVVpEdTlKMlImI3hB
O2lyR1pmemo5ejBQekRvOEd0YUhmYVZOdEhld3ZEeU8vRXNQaGIvWXRRNUFHblk1c1luQXhQVjhiM2xwY
1dkM1BhWENHTzR0NUdpbWomI3hBO1BWWFJpckQ2Q015WGpKUklOSG1GTEN4ZGlyc1ZkaXJzVmRpcklmS3
ZuN3pUNVhsQjBxOFpiY25sSlp5L3ZJSDhhb2VoUGl0RDc1RXgmI3hBO0JjakJxc21JK2svRG85Yzh1Lzh
BT1JXanpxc1d2V0Vsbk4wTnhiZnZZaWZFb2VMcjlITEt6ajduY1llMkluNnhYdWVPZWROWXRkYTgmI3hB
OzE2cHFsb0dGdGR6dEpDSEZHNDlCVUFtblRMSWlnNmJVWkJQSVpEa1M5OS9JUC95WDBYL01WUDhBckdVN
U9iMEhaUDhBYy9FdlJzZzcmI3hBO0oyS3V4VjJLdXhWMkt1eFYyS3ZPZno4LzhsOUwvd0F4VUg2ems4Zk
4xdmEzOXo4UThDOGw2eGE2TDVxMHZWTG9NMXRhVHJKTUVGVzQmI3hBOzlDUURTdEs1ZElXSG50UGtFTWd
rZVFMMlB6Ri96a1ZvOEN0Rm9OaEplVGRCY1hQN3FJSHhDRGs3ZlR4eXNZKzkzV2J0aUkrZ1g3M2smI3hB
O2Ztcno5NXA4MFNrNnJlTTF1RHlqczR2M2NDZUZFSFVqeGFwOThzRVFIVDU5Vmt5bjFINGRHUFpKeDNZc
TdGWFlxN0ZYWXFxMmRwY1gmI3hBO2wzQmFXNkdTNHVKRmloakhWbmRncWo2U2NES01TVFE1bDlrZVh0SG
cwWFE3SFNvZDQ3S0ZJZVEyNUZSOFRmN0pxbk1ZbTNzOE9NUWcmI3hBO0lqb21HQnNmT1A1OStWVHBubWx
kWWdTbHBxNjhuSTZMY1JnTElQOEFaTHhiNTF5L0dkbm11MWNIRGs0aHlsOTd6RExIVnV4VjJLdXgmI3hB
O1YyS3V4VjJLdXhWMkt2cGY4Zy8vQUNYMFgvTVZQK3NaajVPYjAvWlA5ejhTOUd5RHNtSC9BSnBlY05UO
HArV2sxVFRvb1piaHJtT0EmI3hBO3JjSzdKeGRYSk5FYU0xK0h4eVVJMlhDMTJvbGhoeFJybTh1aS93Q2
NqL01ncjZ1bFdiK0hBeXIrdG15end3Nm9kc1pPNElsUCtjazkmI3hBO1NDZ1BvY0xOM0t6c0I5eFEvcng
4Sm1PMlpmelE1LzhBbkpQVWlwQ2FIQ3JkaTA3RWZjRUg2OGZDVTlzeS9taERTLzhBT1IvbVEwOUwmI3hB
O1NyTlBIbVpXL1V5NCtHR0I3WXlkd2VvL2xiNXcxUHpaNWFmVk5SaWhpdUZ1WklBdHVycW5GRlFnMGRwR
Fg0dkhLNXhvdTEwT29sbWgmI3hBO3hTcm16REl1YTg1L1B6L3lYMHYvQURGUWZyT1R4ODNXOXJmM1B4RD
VvekllWWRpcnNWZGlyc1ZkaXJzVmRpcnNWZW4vQUpDZVZUcWYmI3hBO21sdFluU3RwcEM4a0o2TmNTQXJ
HUDlpdkp2blRLOGgyZHAyVmc0c25FZVVmdmZSMlVQU3V4VmpQNWkrVVkvTlBsVzYwMmcrdG9QWHMmI3hB
O0hQN004WVBIYzltcVZQc2NsRTBYRjFtbjhYR1k5ZW52ZkpVc1VzTXJ4U3FVbGpZcElqQ2hWbE5DQ1BZN
WtQSWtWc3R3b2RpcnNWZGkmI3hBO3JzVmRpcnNWZGlyNlgvSVAvd0FsOUYvekZUL3JHWStUbTlQMlQvYy
9FdlJzZzdKNWwvemtKL3lna1gvTWREL3hDVExNZk4xZmEvOEEmI3hBO2REK3QrdDgzNWU4MDdGWFlxN0Z
YMGgvemozL3lna3YvQURIVGY4UWp5akp6ZWw3SS91ai9BRnYxUFRjcmRvODUvUHovQU1sOUwvekYmI3hB
O1Fmck9UeDgzVzlyZjNQeEQ1b3pJZVlkaXJzVmRpcnNWZGlyc1ZkaXE2S0tXYVZJb2xMeXlNRWpSUlVze
kdnQUh1Y0NRTDJmV3Y1ZGUmI3hBO1VZL0szbFcxMDJnK3R1UFh2M0g3VThnSExjZGxvRkhzTXg1R3k5ZG
85UDRXTVI2OWZleWJJdVU3RlhZcStmOEE4Ky9JaHNkUkhtZXgmI3hBO2ovME8rWUpmcW8yUzQ3UDhwQi9
3M3p5N0hMbzg5MnJwZUdYaURrZWZ2ZVJaYTZkMkt1eFYyS3V4VjJLdXhWMkt2cFg4Z1pZMjhncWkmI3hB
O3NHZU82bURxRHVwUEVpdjBaUms1dlRka245ejhYcEdWdXplWC93RE9ROXhBbmtxMmdad0pwYjZNeHhrL
0V3U04rUkE4QlVWeXpIemQmI3hBO1YydVI0UUhtK2NzdmViZGlyc1ZkaXI2TS93Q2NlTGlCL0pWekFyZ3
pSWDBoa2pyOFNoNDQrSkk4RFEweWpKemVrN0lJOElqemVvNVcmI3hBOzdWNXYrZjBzYStRV1JtQ3ZKZFF
oRkozWWprVFQ2TXN4ODNXZHJIOXo4WHpWbDd6THNWZGlyc1ZkaXJzVmRpcnNWZXUva0o1RU45cUomI3hB
Ozh6MzBmK2gyTEZMQldHejNIZC9sR1A4QWh2bGxXU1hSM0haV2w0cGVJZVE1ZTk5QVpTOUM3RlhZcTdGV
UxxdWwyT3E2YmNhZGZSQ2EmI3hBOzB1a01jMFo3Zzl4NEVkUWV4d2dzTWtCT0ppZVJmSnZucnliZitVOW
VsMDI1QmVBMWtzcm1tMHNKUHd0L3JEb3c4Y3lJeXNQSmFyVEgmI3hBO0ZQaFB3WTlrbkdkaXJzVmRpcnN
WZGlyc1ZYeHpUUlY5T1JrcjE0a2l0UGxnU0N2K3Uzbisvd0NUL2cyL3JpdkVWT1NhV1FneU96a2QmI3hB
O0N4Si9YaXRyY0tIWXE3RlhZcXVqbWxqSk1ic2hQVXFTUDFZRTJxZlhiei9mOG4vQnQvWEZlSXJKSnBwY
WVwSXowNmNpVFN2enhVbFomI3hBO2hRN0ZYWXE3RlhZcTdGWFlxeUh5TDVOdi9ObXZSYWJiQXBBS1NYdH
pUYUtFSDRtLzFqMFVlT1JsS2c1T2wweHl6NFI4WDFscFdsMk8mI3hBO2xhYmI2ZFl4Q0cwdFVFY01ZN0F
kejRrOVNlNXpISmV0eHdFSWlJNUJGWUdic1ZkaXJzVmRpckcvUG5ralR2TjJodllYTkk3cU9yMk4mI3hB
OzNTclJTVS9GVzZNTy93QTZaS01xY2JWYWFPYUZIbjBmS211YUhxZWg2cFBwbXBRbUM3dDI0dXA2RWRtV
TkxWWJnNWtBMjhubHhTaEkmI3hBO3hsekNCd3Ric1ZkaXJzVmRpcnNWZGlyc1ZkaXJzVmRpcnNWZGlyc1
ZkaXJzVmRpcnNWZGlyc1ZkaXJzVlIyaDZIcWV1YXBCcG1td20mI3hBO2U3dUc0b282QWQyWTlsVWJrNEN
hYk1XS1U1Q01lWmZWZmtQeVJwM2xIUTBzTGFrbDFKUjc2N3BScFpLZmdxOUZIYjUxekhsSzNyTkwmI3hB
O3BvNFlVT2ZWa21SY2wyS3V4VjJLdXhWMkt1eFZoLzVqZmx6cDNuTFRsVm1GdHF0c0Q5VHZLVnBYY3h5Q
WRVUDRkUjNCbEdWT0hyTkgmI3hBO0hOSHVrT1JmTUd1YUhxbWg2bk5wdXB3TmIzY0JveU4wSTdNcDZNcD
dFWmtBMjh0bHhTaExoa0tLQnd0YnNWZGlyc1ZkaXJzVmRpcnMmI3hBO1ZkaXJzVmRpcnNWZGlyc1ZkaXJ
zVmRpcnNWZGlyc1ZSMmg2SHFtdWFuRHB1bVFOY1hjNW9xTDBBN3N4NktvN2s0Q2FiTVdLVTVjTVImI3hB
O1pmVC9BT1hQNWM2ZDVOMDVsVmhjNnJjZ2ZYTHlsSzAzRWNZUFJCK1BVOWdNZVVyZXAwZWpqaGozeVBNc
3d5TG1PeFYyS3V4VjJLdXgmI3hBO1YyS3V4VjJLc2I4NytROUQ4M2FkOVd2MDlPNmpCK3FYeUFlcEV4Lz
RrcDdxZXZ6M3lVWlU0MnAwc00wYVBQdmZNL25MeUxyM2xPL04mI3hBO3RxVVZZSEorclhzWUpobEgrUzN
adkZUdmw4WkF2TWFuU3p4R3BmTmoyU2NaMkt1eFYyS3V4VjJLdXhWMkt1eFYyS3V4VjJLdXhWMksmI3hB
O3V4VjJLdXhWMktzaDhtK1JkZTgyWDR0dE5pcEFoSDFtOWtCRU1RL3ltN3Q0S044aktRRGs2YlN6eW1vL
045TWVTUEllaCtVZE8rclcmI3hBO0NlcGRTQWZXNzV3UFVsWWY4UlVkbEhUNTc1UktWdlQ2YlN3d3hvYy
s5a21SY2wyS3V4VjJLdXhWMkt1eFYyS3V4VjJLdXhWQzZwcFcmI3hBO202cll5Mk9vMjZYVnBNS1NReUN
vUHVQQWpzUnVNSUxDZU9NeFVoWWVFK2UveUUxR3hNbDk1WUxYMW51eldEbi9BRWhCL2tIcElQOEEmI3hB
O2h2bmxzY25lNkhWZGxTanZqM0hkMWVTU3hTd3l0RktqUnlvU3J4dUNyS1IxQkIzR1dPb0lybXR3b2Rpc
nNWZGlyc1ZkaXJzVmRpcnMmI3hBO1ZkaXJzVmRpcnNWZGlxNktLV2FWWW9rYVNWeUZTTkFXWmllZ0FHNX
dKQXZrOWI4aWZrSnFOOFk3N3pPV3NiUFpsc0VQK2tPUDhzOUkmI3hBO3gvdzN5eXVXVHVkdnBleXBTM3l
iRHU2dmR0TDByVGRLc1lySFRyZExXMGhGSTRZeFFEM1BpVDNKM09WRXUraGpqQVZFVUVWZ1p1eFYmI3hB
OzJLdXhWMkt1eFYyS3V4VjJLdXhWMkt1eFYyS3V4VmpQbTc4dXZLdm1tTS9wSzFDWGRLSmZ3VWpuWHNQa
W9lUTltQkdTRWlIRjFHangmI3hBOzVmcUcvZjFlTCthdnlFODA2WVhuMGRsMWUwRzRSYVIzQ2ozalk4Vy
8yTFY5c3RHUU9rejlsWkk3eDlRKzE1cmQyZDNaM0QyOTNCSmImI3hBOzNFWnBKREtySTZuM1ZnQ01tNjJ
VU0RSMktsaFl1eFYyS3V4VjJLdXhWMkt1eFYyS3V4VlZ0TE83dkxoTGUwZ2t1TGlRMGpoaVZuZGomI3hB
OzdLb0pPQmxHSkpvYmw2VjVWL0lUelRxWlNmV0dYU0xRN2xHcEpjTVBhTlR4WC9aTlgyeUJ5QjJXRHNyS
kxlWHBIMnZhUEtQNWRlVmYmI3hBO0swWS9SdHFIdTZVZS9ucEpPM1kvRlFjUjdLQU1xTWlYZDZmUjQ4WD
BqZnY2c215TGxPeFYyS3V4VjJLdXhWMkt1eFYyS3V4VjJLdXgmI3hBO1YyS3V4VjJLdXhWMkt1eFZMOVk
4dmFIclVIbzZyWXczc1kyWDFrREZhL3l0OXBmb09FR212SmhoTVZJVzg4MXovbkhyeW5lRm4wdTUmI3hB
O3VOTGtQUksvV0loL3NYSWYvaDhtTWhkZGw3SXhuNlNZL2F3YlZmOEFuSHJ6bGJFdFlYRnJxRWY3SURtR
1EvTlhIRC9oOG1NZ2NESjImI3hBO1JsSElnc1Z2L3dBc1B6QXNTZlgwSzZhblV3S0xnZjhBSkV5WkxqRG
lUMFdhUE9KKy93QzVKTGpSZFl0alM1c2JpQStFa1RwMnIrMEImI3hBO2h0b09PUTVnb1BDd2RpcU10OUY
xaTVOTGF4dUp6NFJ4Ty9hdjdJT0MyWXh5UElGTzdEOHNQekF2aVBRMEs2V3ZRenFMY2Y4QUpZeDQmI3hB
O09NTjhORm1seWlmdSs5bFdsZjhBT1BYbks1SWEvdUxYVDQvMmdYTTBnK1NvT0gvRDVFNUE1ZVBzaktlW
kFaem9mL09QWGxPekt2cWwmI3hBO3pjYXBJT3FWK3J4SC9Zb1Mvd0R3K1FPUXVmaTdJeGo2aVpmWTlEMG
Z5OW9laXdlanBWakRaUm5adlJRS1dwL00zMm0razVBbTNZNDgmI3hBO01JQ29pa3d3TmpzVmRpcnNWZGl
yc1ZkaXJzVmRpcnNWZi8vWjwveG1wR0ltZzppbWFnZT4KICAgICAgICAgICAgICAgPC9yZGY6bGk+CiAg
ICAgICAgICAgIDwvcmRmOkFsdD4KICAgICAgICAgPC94bXA6VGh1bWJuYWlscz4KICAgICAgICAgPHhtc
E1NOlJlbmRpdGlvbkNsYXNzPnByb29mOnBkZjwveG1wTU06UmVuZGl0aW9uQ2xhc3M+CiAgICAgICAgID
x4bXBNTTpPcmlnaW5hbERvY3VtZW50SUQ+dXVpZDo2NUU2MzkwNjg2Q0YxMURCQTZFMkQ4ODdDRUFDQjQ
wNzwveG1wTU06T3JpZ2luYWxEb2N1bWVudElEPgogICAgICAgICA8eG1wTU06RG9jdW1lbnRJRD54bXAu
ZGlkOjU4NjQ2ZDc2LWQ4OGUtNDRiNi1hYWRiLTAzNWEzYTlhZjUwZDwveG1wTU06RG9jdW1lbnRJRD4KI
CAgICAgICAgPHhtcE1NOkluc3RhbmNlSUQ+eG1wLmlpZDo1ODY0NmQ3Ni1kODhlLTQ0YjYtYWFkYi0wMz
VhM2E5YWY1MGQ8L3htcE1NOkluc3RhbmNlSUQ+CiAgICAgICAgIDx4bXBNTTpEZXJpdmVkRnJvbSByZGY
6cGFyc2VUeXBlPSJSZXNvdXJjZSI+CiAgICAgICAgICAgIDxzdFJlZjppbnN0YW5jZUlEPnhtcC5paWQ6
YTJkMWVlNDYtYWE1Ni00Zjk5LWIzNDgtNDcxMTU0ZmE5MzMyPC9zdFJlZjppbnN0YW5jZUlEPgogICAgI
CAgICAgICA8c3RSZWY6ZG9jdW1lbnRJRD54bXAuZGlkOmEyZDFlZTQ2LWFhNTYtNGY5OS1iMzQ4LTQ3MT
E1NGZhOTMzMjwvc3RSZWY6ZG9jdW1lbnRJRD4KICAgICAgICAgICAgPHN0UmVmOm9yaWdpbmFsRG9jdW1
lbnRJRD51dWlkOjY1RTYzOTA2ODZDRjExREJBNkUyRDg4N0NFQUNCNDA3PC9zdFJlZjpvcmlnaW5hbERv
Y3VtZW50SUQ+CiAgICAgICAgICAgIDxzdFJlZjpyZW5kaXRpb25DbGFzcz5wcm9vZjpwZGY8L3N0UmVmO
nJlbmRpdGlvbkNsYXNzPgogICAgICAgICA8L3htcE1NOkRlcml2ZWRGcm9tPgogICAgICAgICA8eG1wTU
06SGlzdG9yeT4KICAgICAgICAgICAgPHJkZjpTZXE+CiAgICAgICAgICAgICAgIDxyZGY6bGkgcmRmOnB
hcnNlVHlwZT0iUmVzb3VyY2UiPgogICAgICAgICAgICAgICAgICA8c3RFdnQ6YWN0aW9uPnNhdmVkPC9z
dEV2dDphY3Rpb24+CiAgICAgICAgICAgICAgICAgIDxzdEV2dDppbnN0YW5jZUlEPnhtcC5paWQ6ZjMwZ
GU3NzYtNjkxZC00MGZkLTk4ZDAtMGI0YzFmNzNlYWYyPC9zdEV2dDppbnN0YW5jZUlEPgogICAgICAgIC
AgICAgICAgICA8c3RFdnQ6d2hlbj4yMDIwLTAyLTA1VDE0OjEyOjIzLTA4OjAwPC9zdEV2dDp3aGVuPgo
gICAgICAgICAgICAgICAgICA8c3RFdnQ6c29mdHdhcmVBZ2VudD5BZG9iZSBJbGx1c3RyYXRvciAyNC4w
IChNYWNpbnRvc2gpPC9zdEV2dDpzb2Z0d2FyZUFnZW50PgogICAgICAgICAgICAgICAgICA8c3RFdnQ6Y
2hhbmdlZD4vPC9zdEV2dDpjaGFuZ2VkPgogICAgICAgICAgICAgICA8L3JkZjpsaT4KICAgICAgICAgIC
AgICAgPHJkZjpsaSByZGY6cGFyc2VUeXBlPSJSZXNvdXJjZSI+CiAgICAgICAgICAgICAgICAgIDxzdEV
2dDphY3Rpb24+c2F2ZWQ8L3N0RXZ0OmFjdGlvbj4KICAgICAgICAgICAgICAgICAgPHN0RXZ0Omluc3Rh
bmNlSUQ+eG1wLmlpZDo1ODY0NmQ3Ni1kODhlLTQ0YjYtYWFkYi0wMzVhM2E5YWY1MGQ8L3N0RXZ0Omluc
3RhbmNlSUQ+CiAgICAgICAgICAgICAgICAgIDxzdEV2dDp3aGVuPjIwMjAtMDItMDZUMTQ6MTQ6NTAtMD
g6MDA8L3N0RXZ0OndoZW4+CiAgICAgICAgICAgICAgICAgIDxzdEV2dDpzb2Z0d2FyZUFnZW50PkFkb2J
lIElsbHVzdHJhdG9yIDI0LjAgKE1hY2ludG9zaCk8L3N0RXZ0OnNvZnR3YXJlQWdlbnQ+CiAgICAgICAg
ICAgICAgICAgIDxzdEV2dDpjaGFuZ2VkPi88L3N0RXZ0OmNoYW5nZWQ+CiAgICAgICAgICAgICAgIDwvc
mRmOmxpPgogICAgICAgICAgICA8L3JkZjpTZXE+CiAgICAgICAgIDwveG1wTU06SGlzdG9yeT4KICAgIC
AgICAgPGlsbHVzdHJhdG9yOlN0YXJ0dXBQcm9maWxlPldlYjwvaWxsdXN0cmF0b3I6U3RhcnR1cFByb2Z
pbGU+CiAgICAgICAgIDxpbGx1c3RyYXRvcjpDcmVhdG9yU3ViVG9vbD5BSVJvYmluPC9pbGx1c3RyYXRv
cjpDcmVhdG9yU3ViVG9vbD4KICAgICAgICAgPHBkZjpQcm9kdWNlcj5BZG9iZSBQREYgbGlicmFyeSAxN
S4wMDwvcGRmOlByb2R1Y2VyPgogICAgICAgICA8cGRmeDpDcmVhdG9yVmVyc2lvbj4yMS4wLjA8L3BkZn
g6Q3JlYXRvclZlcnNpb24+CiAgICAgIDwvcmRmOkRlc2NyaXB0aW9uPgogICA8L3JkZjpSREY+CjwveDp
4bXBtZXRhPgogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgI
CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC
AgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA
gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI
CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgIC
AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA
gICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI
CAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC
AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICA
gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI
CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC
AgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA
gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI
CAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC
AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA
gICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgI
CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC
AgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA
gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI
CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgIC
AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA
gICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI
CAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC
AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICA
gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg
ICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgCjw/eHBhY2tld
CBlbmQ9InciPz7/4gxYSUNDX1BST0ZJTEUAAQEAAAxITGlubwIQAABtbnRyUkdCIFhZWiAHzgACAAkABg
AxAABhY3NwTVNGVAAAAABJRUMgc1JHQgAAAAAAAAAAAAAAAAAA9tYAAQAAAADTLUhQICAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABFjcHJ0AAABUAAAADNkZXNjAAABhAAA
AGx3dHB0AAAB8AAAABRia3B0AAACBAAAABRyWFlaAAACGAAAABRnWFlaAAACLAAAABRiWFlaAAACQAAAA
BRkbW5kAAACVAAAAHBkbWRkAAACxAAAAIh2dWVkAAADTAAAAIZ2aWV3AAAD1AAAACRsdW1pAAAD+AAAAB
RtZWFzAAAEDAAAACR0ZWNoAAAEMAAAAAxyVFJDAAAEPAAACAxnVFJDAAAEPAAACAxiVFJDAAAEPAAACAx
0ZXh0AAAAAENvcHlyaWdodCAoYykgMTk5OCBIZXdsZXR0LVBhY2thcmQgQ29tcGFueQAAZGVzYwAAAAAA
AAASc1JHQiBJRUM2MTk2Ni0yLjEAAAAAAAAAAAAAABJzUkdCIElFQzYxOTY2LTIuMQAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWFlaIAAAAAAAAPNRAAEAAAABFsxYWV
ogAAAAAAAAAAAAAAAAAAAAAFhZWiAAAAAAAABvogAAOPUAAAOQWFlaIAAAAAAAAGKZAAC3hQAAGNpYWVo
gAAAAAAAAJKAAAA+EAAC2z2Rlc2MAAAAAAAAAFklFQyBodHRwOi8vd3d3LmllYy5jaAAAAAAAAAAAAAAA
FklFQyBodHRwOi8vd3d3LmllYy5jaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAABkZXNjAAAAAAAAAC5JRUMgNjE5NjYtMi4xIERlZmF1bHQgUkdCIGNvbG91ciBzcGFjZSAtIH
NSR0IAAAAAAAAAAAAAAC5JRUMgNjE5NjYtMi4xIERlZmF1bHQgUkdCIGNvbG91ciBzcGFjZSAtIHNSR0I
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAZGVzYwAAAAAAAAAsUmVmZXJlbmNlIFZpZXdpbmcgQ29uZGl0aW9u
IGluIElFQzYxOTY2LTIuMQAAAAAAAAAAAAAALFJlZmVyZW5jZSBWaWV3aW5nIENvbmRpdGlvbiBpbiBJR
UM2MTk2Ni0yLjEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHZpZXcAAAAAABOk/gAUXy4AEM8UAAPtzA
AEEwsAA1yeAAAAAVhZWiAAAAAAAEwJVgBQAAAAVx/nbWVhcwAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAA
AAo8AAAACc2lnIAAAAABDUlQgY3VydgAAAAAAAAQAAAAABQAKAA8AFAAZAB4AIwAoAC0AMgA3ADsAQABF
AEoATwBUAFkAXgBjAGgAbQByAHcAfACBAIYAiwCQAJUAmgCfAKQAqQCuALIAtwC8AMEAxgDLANAA1QDbA
OAA5QDrAPAA9gD7AQEBBwENARMBGQEfASUBKwEyATgBPgFFAUwBUgFZAWABZwFuAXUBfAGDAYsBkgGaAa
EBqQGxAbkBwQHJAdEB2QHhAekB8gH6AgMCDAIUAh0CJgIvAjgCQQJLAlQCXQJnAnECegKEAo4CmAKiAqw
CtgLBAssC1QLgAusC9QMAAwsDFgMhAy0DOANDA08DWgNmA3IDfgOKA5YDogOuA7oDxwPTA+AD7AP5BAYE
EwQgBC0EOwRIBFUEYwRxBH4EjASaBKgEtgTEBNME4QTwBP4FDQUcBSsFOgVJBVgFZwV3BYYFlgWmBbUFx
QXVBeUF9gYGBhYGJwY3BkgGWQZqBnsGjAadBq8GwAbRBuMG9QcHBxkHKwc9B08HYQd0B4YHmQesB78H0g
flB/gICwgfCDIIRghaCG4IggiWCKoIvgjSCOcI+wkQCSUJOglPCWQJeQmPCaQJugnPCeUJ+woRCicKPQp
UCmoKgQqYCq4KxQrcCvMLCwsiCzkLUQtpC4ALmAuwC8gL4Qv5DBIMKgxDDFwMdQyODKcMwAzZDPMNDQ0m
DUANWg10DY4NqQ3DDd4N+A4TDi4OSQ5kDn8Omw62DtIO7g8JDyUPQQ9eD3oPlg+zD88P7BAJECYQQxBhE
H4QmxC5ENcQ9RETETERTxFtEYwRqhHJEegSBxImEkUSZBKEEqMSwxLjEwMTIxNDE2MTgxOkE8UT5RQGFC
cUSRRqFIsUrRTOFPAVEhU0FVYVeBWbFb0V4BYDFiYWSRZsFo8WshbWFvoXHRdBF2UXiReuF9IX9xgbGEA
YZRiKGK8Y1Rj6GSAZRRlrGZEZtxndGgQaKhpRGncanhrFGuwbFBs7G2MbihuyG9ocAhwqHFIcexyjHMwc
9R0eHUcdcB2ZHcMd7B4WHkAeah6UHr4e6R8THz4faR+UH78f6iAVIEEgbCCYIMQg8CEcIUghdSGhIc4h+
yInIlUigiKvIt0jCiM4I2YjlCPCI/AkHyRNJHwkqyTaJQklOCVoJZclxyX3JicmVyaHJrcm6CcYJ0knei
erJ9woDSg/KHEooijUKQYpOClrKZ0p0CoCKjUqaCqbKs8rAis2K2krnSvRLAUsOSxuLKIs1y0MLUEtdi2
rLeEuFi5MLoIuty7uLyQvWi+RL8cv/jA1MGwwpDDbMRIxSjGCMbox8jIqMmMymzLUMw0zRjN/M7gz8TQr
NGU0njTYNRM1TTWHNcI1/TY3NnI2rjbpNyQ3YDecN9c4FDhQOIw4yDkFOUI5fzm8Ofk6Njp0OrI67zstO
2s7qjvoPCc8ZTykPOM9Ij1hPaE94D4gPmA+oD7gPyE/YT+iP+JAI0BkQKZA50EpQWpBrEHuQjBCckK1Qv
dDOkN9Q8BEA0RHRIpEzkUSRVVFmkXeRiJGZ0arRvBHNUd7R8BIBUhLSJFI10kdSWNJqUnwSjdKfUrESwx
LU0uaS+JMKkxyTLpNAk1KTZNN3E4lTm5Ot08AT0lPk0/dUCdQcVC7UQZRUFGbUeZSMVJ8UsdTE1NfU6pT
9lRCVI9U21UoVXVVwlYPVlxWqVb3V0RXklfgWC9YfVjLWRpZaVm4WgdaVlqmWvVbRVuVW+VcNVyGXNZdJ
114XcleGl5sXr1fD19hX7NgBWBXYKpg/GFPYaJh9WJJYpxi8GNDY5dj62RAZJRk6WU9ZZJl52Y9ZpJm6G
c9Z5Nn6Wg/aJZo7GlDaZpp8WpIap9q92tPa6dr/2xXbK9tCG1gbbluEm5rbsRvHm94b9FwK3CGcOBxOnG
VcfByS3KmcwFzXXO4dBR0cHTMdSh1hXXhdj52m3b4d1Z3s3gReG54zHkqeYl553pGeqV7BHtje8J8IXyB
fOF9QX2hfgF+Yn7CfyN/hH/lgEeAqIEKgWuBzYIwgpKC9INXg7qEHYSAhOOFR4Wrhg6GcobXhzuHn4gEi
GmIzokziZmJ/opkisqLMIuWi/yMY4zKjTGNmI3/jmaOzo82j56QBpBukNaRP5GokhGSepLjk02TtpQglI
qU9JVflcmWNJaflwqXdZfgmEyYuJkkmZCZ/JpomtWbQpuvnByciZz3nWSd0p5Anq6fHZ+Ln/qgaaDYoUe
htqImopajBqN2o+akVqTHpTilqaYapoum/adup+CoUqjEqTepqaocqo+rAqt1q+msXKzQrUStuK4trqGv
Fq+LsACwdbDqsWCx1rJLssKzOLOutCW0nLUTtYq2AbZ5tvC3aLfguFm40blKucK6O7q1uy67p7whvJu9F
b2Pvgq+hL7/v3q/9cBwwOzBZ8Hjwl/C28NYw9TEUcTOxUvFyMZGxsPHQce/yD3IvMk6ybnKOMq3yzbLts
w1zLXNNc21zjbOts83z7jQOdC60TzRvtI/0sHTRNPG1EnUy9VO1dHWVdbY11zX4Nhk2OjZbNnx2nba+9u
A3AXcit0Q3ZbeHN6i3ynfr+A24L3hROHM4lPi2+Nj4+vkc+T85YTmDeaW5x/nqegy6LzpRunQ6lvq5etw
6/vshu0R7ZzuKO6070DvzPBY8OXxcvH/8ozzGfOn9DT0wvVQ9d72bfb794r4Gfio+Tj5x/pX+uf7d/wH/
Jj9Kf26/kv+3P9t////7gAOQWRvYmUAZMAAAAAB/9sAhAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ
EBAQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgIDAwMDAwMDAwMDAQEBAQEBAQIBAQICAgECAgMDAwMDAwM
DAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwP/wAARCAF4AXgDAREAAhEBAxEB
/8QAzwABAAIDAAMBAQEAAAAAAAAAAAkKBwgLBAUGAwIBAQEAAQQDAQAAAAAAAAAAAAAABgUHCAkBAwQCE
AAABgIBAwEEBwQIBQQDAQAAAQIDBAUGBwgREhMJIRQVCjEiIxa3OHhBtjd3MjTWV5cYWBm1Nnan10JSM2
XVlhcaEQABAwIDBAUFCgcNBwUBAAABAAIDEQQhBQYxQRIHUWFxEwiBkaEiFLHB0TJCsiMzczRSYnKStHU
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
xh76yt0fzO0LryMHTWYwTXNKmFxMc7emsMga8gbC5oczocRQraweJT1ARARARARARARARARARARARARAR
ARARARARARARARARARARARARaH8tPUe4tcOmZNdsjNfjuw0xSkQtU4K2xkGcP+VBqjKs45SY1Vi0V8uik
u2kqJ5G+pspdMu06jZZVeX2MTaRfhHAf7fJVWq5gc5tCcuWuhzq673OOGrbWCkk5rs4hUNiB6ZXMqMWh2
xVieVvra8q99rtMd1bMRx11xMQ9ETAwicqVsKyhuGXRVtsd2NEs62QZJ6l8FaqjSlRoWt4vrHLrLT9nbU
fN9LL1/F8jfhqsH9feJvXurDJZ5E7+x8mdUcMLq3Dh+PcEBzT9iIqbCXbVDpPnzrWdLs7SbLsrKwkvTJ9
hPkvTJ02XJcU7IlS5chbj8mS+6s1LWtSlKUZmZmYroAaKDABY5SzS3Erp53OfM9xLnOJLnE4kknEknEk4
leIOV1oCICICICICICICICICICICICICICICICLy4E+dVTolnVzZdbZV8lmZAsIEl6HOhS4ziXY8qJLjr
bfjSWHUEpC0KSpKiIyMjHBAcKHEFdkU0tvK2eBzmTMcC1zSQ5pGIIIxBBxBGIUxfFL1teVehF1eO7SmI5
Fa4hoZiKgZvOVF2FWw2zPqqp2O1Gl2dlIIldT+NNWpqSkkIWyX1ioV7p+zuavh+il6vi+VvwUWRugfE3r
3SZjs89d/bGTNoOGZ1Lho/EuAC5x+2EtdgLdqs7cS/Ue4tcxWY1drfNfgWw1RTkTdU502xj+cMeJBKkqr
I5yZNVlMVguqlO1cqX42+hvJaM+0oje5VeWOMraxfhDEf7PLRZwcv+c2hOYzWw5Ldd1nHDV1rPSOcU28I
qWygdMTn0GLg3Yt8BTldVARARARARARARARARARARARARARARARARARARARARARYf3fv3T/HHBp+xt055
RYHisEloak20jrYXE1DSnk1GOUsZL9vkl082g1IiQmH3zQlS+0kJUou+3tp7qQRW7S5/Vu6ydgHWVHdT6
s07ozK35zqW7itLBuwvPrPdSvBGwVfI87mMa51KmlASqpvNr1ytv7kO2wLjBHttH63e88KRmzr7Cdu5RF
NRpJ6NPguPRNdxXkdPs655+xI09xTkJUpkpll+noIKSXlJJej5I/jeXDqWBXM3xR6i1H3mU6GEmV5Kagz
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
dk0xklHXR+O/YttR4lcBARARARARARARARARARARARARARARARARf/2Q=='
	$iconData = [System.Convert]::FromBase64String($base64IconData)

	# Create a new NotifyIcon object
	$notifyicon = New-Object System.Windows.Forms.NotifyIcon
	
	# Set the tooltip text for the NotifyIcon
	$notifyicon.Text = 'HungerRush InstallXpert'
	
	# Set the icon using the binary data
	$iconStream = New-Object IO.MemoryStream
	$iconStream.Write($iconData, 0, $iconData.Length)
	$iconStream.Seek(0, [System.IO.SeekOrigin]::Begin)
	$notifyicon.Icon = [System.Drawing.Icon]::FromHandle((New-Object System.Drawing.Bitmap $iconStream).GetHicon())

	# Set the Text that appears when hovering over the icon
	$notifyIcon.Text = 'My PowerShell Notify Icon'

	# Show the icon in the System Tray
	$notifyIcon.Visible = $true

	# Create context menu items
	$exitMenuItem = New-Object System.Windows.Forms.MenuItem
	$exitMenuItem.Text = 'Exit'

	$hideMenuItem = New-Object System.Windows.Forms.MenuItem
	$hideMenuItem.Text = 'Hide'

	$showMenuItem = New-Object System.Windows.Forms.MenuItem
	$showMenuItem.Text = 'Show'

	# Create a context menu for the NotifyIcon
	$contextMenu = New-Object System.Windows.Forms.ContextMenu
	$notifyIcon.ContextMenu = $contextMenu
	$notifyIcon.contextMenu.MenuItems.AddRange(@($hideMenuItem, $showMenuItem, $exitMenuItem))

	# Add a left-click event to reposition and show the form
	$notifyIcon.add_Click({
			if ($_.Button -eq [Windows.Forms.MouseButtons]::Left) {
				$form_MainForm.Left = $([System.Windows.SystemParameters]::WorkArea.Width - $form_MainForm.Width)
				$form_MainForm.Top = $([System.Windows.SystemParameters]::WorkArea.Height - $form_MainForm.Height)
				$form_MainForm.Show()
				$form_MainForm.Activate()
			}
		})

	# Add double-click event to hide the form
	$notifyIcon.add_MouseDoubleClick({
			if ($_.Button -eq [Windows.Forms.MouseButtons]::Left) {
				$form_MainForm.Hide()
			}
		})

	# When Exit is clicked, close everything and kill the PowerShell process
	$exitMenuItem.add_Click({
			$notifyIcon.Visible = $false
			$form_MainForm.Close()
			Stop-Process $pid
		})

	# When Hide is clicked, hide the form
	$hideMenuItem.add_Click({
			$form_MainForm.Hide()
		})

	# When Show is clicked, show the form
	$showMenuItem.add_Click({
			$form_MainForm.WindowState = [System.Windows.Forms.FormWindowState]::Normal
			$form_MainForm.Left = $([System.Windows.SystemParameters]::WorkArea.Width - $form_MainForm.Width)
			$form_MainForm.Top = $([System.Windows.SystemParameters]::WorkArea.Height - $form_MainForm.Height)
			$form_MainForm.Show()
			$form_MainForm.Activate()
		})
	#endregion

	#----------------------------------------------
	# Create an application context for responsiveness
	$appContext = New-Object System.Windows.Forms.ApplicationContext
	[void][System.Windows.Forms.Application]::Run($appContext)


	$Form_StateCorrection_Load =
	{
		$form_MainForm.WindowState = [System.Windows.Forms.FormWindowState]::Minimized
	}

	#Init the OnLoad event to correct the initial state of the form
	$form_MainForm.add_Load($Form_StateCorrection_Load)
	#Clean up the control events
	$form_MainForm.add_FormClosed($Form_Cleanup_FormClosed)
	#Store the control values when form is closing
	$form_MainForm.add_Closing($Form_StoreValues_Closing)
	#Show the Form
	return $form_MainForm.ShowDialog()

}
#endregion

#Start the application
Main ($CommandLine)
