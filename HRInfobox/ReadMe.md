
# Support Info Tool

## Description

This PowerShell script creates a GUI using XAML to display system information and services statuses related to the POS. 

## Features

- Displays system information such as hostname, IP address, and POS/Services current version.
- Shows status of services: RevControl, RevCloud, RevCallerID, RevPrinter, RevMonitor, RevUpdate, and TriPos.
- Displays statuses of HROO(7777) and HUB(12230) ports.
- Utilizes XAML for creating the GUI.
- Provides a tray icon for easy access and control.

## Script Breakdown

### Initialization

- Sets the execution policy to bypass.
- Adds required .NET assemblies for GUI creation.
- Defines the XAML layout for the GUI.
- Defines Variables for System Info. 
- Creates Tray Icon & Controls

### GUI Elements

1. XAML Method to Create the GUI
-Create GUI in Visual Studio, Copy & Paste the XAML Code in the snippet below: 


```powershell
#Use this variable to insert you XAML code
[xml]$XAML = @'<INSERT GUI ELEMENTS IN BETWEEN HERE>'@

```

```POWERSHELL
#This to Read the XAML

$reader=(New-Object System.Xml.XmlNodeReader $xaml)  

try{$Form=[Windows.Markup.XamlReader]::Load( $reader )}

```

2. Collect & Display the system info. 
```powershell
$oCIMOS = @()

$oCIMNIC = @()

$HUBport = 12230

$HROOport = 7777

$IPAddress = (Invoke-WebRequest -uri "http://ifconfig.me/ip").Content

$oCIMOS = Get-CimInstance win32_OperatingSystem

$oCIMNIC = Get-CimInstance Win32_NetworkAdapterConfiguration | Where { $_.IPAddress } | Select -Expand IPAddress | Where { $_ -like '1*' }


$oControlSvc = get-service RevControlSvc | Where { $_.Status } | select -expand  Status
$oCloudSvc = get-service RevCloudSvc | Where { $_.Status } | select -expand  Status
$oCallerIDSvc = get-service RevCallerId | Where { $_.Status } | select -expand  Status
$oPrintSvc = get-service RevPrtSrv | Where { $_.Status } | select -expand  Status
$oMonitorSvc = get-service RevMonitorSvc | Where { $_.Status } | select -expand  Status
$oTripos = get-service TriPosService | Where { $_.Status } | select -expand  Status
$oRevUpdateSvc = get-service RUSvc | Where { $_.Status } | select -expand  Status

  

#Displays HUB Port Status
$ohub = $HUBport | ForEach-Object {$HUBport = $_;

if (Test-NetConnection -ComputerName $IPAddress -Port $HUBport -InformationLevel Quiet -WarningAction SilentlyContinue) {"Port $HUBport is open"} else {"Port $HUBport is closed"} }  

#Display HROO Port Status
$ohroo = $HROOport | ForEach-Object {$HROOport = $_;

if (Test-NetConnection -ComputerName $IPAddress -Port $HROOport -InformationLevel Quiet -WarningAction SilentlyContinue) {"Port $HROOport is open"} else {"Port $HROOport is closed"} }

#Display POS Version
$oPOSv = (Get-Item "C:\Revention\ReventionPOS.exe").LastWriteTime.ToString("yMMdd")

#Display Revcontrol Version
$ocontrolv = (Get-Item "C:\Revention\RevControlSvc.exe").LastWriteTime.ToString("yMMdd")

#Display RevCloud Version
$ocloudv = (Get-Item "C:\Revention\RevCloudSvc\RevCloudSvc.exe").LastWriteTime.ToString("yMMdd")

#Display RevUpdate Version
$oupdatev = (Get-Item "C:\Revention\RevUpdate\RUSvc.exe").LastWriteTime.ToString("yMMdd")

#Display Hostname
$txtHostName.Text = Hostname

#Displays IP Address
$txtWindowsIP.Text = $oCIMNIC

#Displays RevControl Status
$txtRevControl.text = $oControlSvc

#Displays RevControl Status
$txtCloudSvc.text = $oCloudSvc

#Displays RevControl Status
$txtCallerID.text = $oCallerIDSvc

#Displays RevControl Status
$txtPrinterSvc.text = $oPrintSvc

#Displays RevControl Status
$txtRevMonitorSvc.text = $oMonitorSvc

#Displays RevUpdate Status
$txtRevUpdateSvc.text = $oRevUpdateSvc

#Displays RevControl Status
$txtTripos.text = $oTripos

#Displays HUB Port Status
$txthub.text = $ohub

#Display HROO Port Status
$txthroo.text = $ohroo

#Display POS Version
$txtPOSv.text = $oPOSv.Substring(1)

#Display RevControl Version
$txtcontrolv.text = $ocontrolv.Substring(1)

#Display Revcloud Version
$txtcloudv.text = $ocloudv.substring(1)

#Display RevUpdate Version
$txtupdatev.text = $oupdatev.substring(1)

```

3. Create a ListView to Insert the System info & Create the Tray Icon Image & Click Controls

```powershell
#Path of icon file
$icon = [System.Drawing.Icon]::ExtractAssociatedIcon("C:\Windows\HelpPane.exe") 
 
# Populate ListView with PS Object data and set width  
$listview.ItemsSource = $disks 
$listview.Width = $grid.width*.9  
 
# Create GridView object to add to ListView  
$gridview = New-Object System.Windows.Controls.GridView  
  
# Dynamically add columns to GridView, then bind data to columns  
foreach ($column in $columnorder) {  
    $gridcolumn = New-Object System.Windows.Controls.GridViewColumn  
    $gridcolumn.Header = $column  
    $gridcolumn.Width = $grid.width*.20  
    $gridbinding = New-Object System.Windows.Data.Binding $column  
    $gridcolumn.DisplayMemberBinding = $gridbinding  
    $gridview.AddChild($gridcolumn)  
}  
  
# Add GridView to ListView  
$listview.View = $gridview  
  
# Create notifyicon, and right-click -> Exit menu  
$notifyicon = New-Object System.Windows.Forms.NotifyIcon  
$notifyicon.Text = "System Resources"  
$notifyicon.Icon = $icon  
$notifyicon.Visible = $true  
  
$menuitem = New-Object System.Windows.Forms.MenuItem  
$menuitem.Text = "Exit"  
 
$contextmenu = New-Object System.Windows.Forms.ContextMenu  
$notifyicon.ContextMenu = $contextmenu  
$notifyicon.contextMenu.MenuItems.AddRange($menuitem)  

# Add a left click that makes the Window appear in the lower right part of the screen, above the notify icon.  
$notifyicon.add_Click({  
    if ($_.Button -eq [Windows.Forms.MouseButtons]::Left) {  
            # reposition each time, in case the resolution or monitor changes  
        $window.Left = $([System.Windows.SystemParameters]::WorkArea.Width-$window.Width)  
            $window.Top = $([System.Windows.SystemParameters]::WorkArea.Height-$window.Height)  
            $window.Show()  
            $window.Activate() 
            RefreshData 
    }  
})  
  
# Close the window if it's double clicked  
$window.Add_MouseDoubleClick({  
    RefreshData 
})  
  
#Close the window if it loses focus  
$window.Add_Deactivated({  
    $window.Hide() 
})  
  
# When Exit is clicked, close everything and kill the PowerShell process  
$menuitem.add_Click({  
   $notifyicon.Visible = $false  
   $window.close()  
   Stop-Process $pid  
})  
  
```

4. To force Powershell menu to disappear.
```powershell
# Make PowerShell Disappear  
$windowcode = '[DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);'  
$asyncwindow = Add-Type -MemberDefinition $windowcode -name Win32ShowWindowAsync -namespace Win32Functions -PassThru 
$null = $asyncwindow::ShowWindowAsync((Get-Process -PID $pid).MainWindowHandle, 0)  
  
#Force garbage collection just to start slightly lower RAM usage.  
[System.GC]::Collect()  
  
#Create an application context for it to all run within.  
#This helps with responsiveness, especially when clicking Exit.  
$appContext = New-Object System.Windows.Forms.ApplicationContext  
[void][System.Windows.Forms.Application]::Run($appContext)
```