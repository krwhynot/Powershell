#=========================================================================== 
# Created By Kyle Ramsy
#=========================================================================== 
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser
$ProgressPreference = 'SilentlyContinue'
Add-Type -AssemblyName PresentationFramework, System.Drawing, System.Windows.Forms 
[void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework') 
[xml]$XAML = @' 
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" 
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" 
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008" 
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" 
        xmlns:local="clr-namespace:WpfApp3" 
        Name="window" WindowStyle="None" Height="554" Width="260" Background="#3D476A" AllowsTransparency="True"> 
        <Window.Resources> 
        <Style TargetType="GridViewColumnHeader"> 
            <Setter Property="Background" Value="Transparent" /> 
            <Setter Property="Foreground" Value="Transparent"/> 
            <Setter Property="BorderBrush" Value="Transparent"/> 
            <Setter Property="FontWeight" Value="Bold"/> 
            <Setter Property="Opacity" Value="0.5"/> 
            <Setter Property="Template"> 
                <Setter.Value> 
                    <ControlTemplate TargetType="GridViewColumnHeader"> 
                    <Border Background="Transparent"> 
                    <ContentPresenter></ContentPresenter> 
                    </Border> 
                    </ControlTemplate> 
                </Setter.Value> 
            </Setter> 
        </Style> 
        </Window.Resources> 
    <Grid Name="grid" Height="627" HorizontalAlignment="Left" VerticalAlignment="Top"> 
        <Label Name="Title" Content="HungerRush Support Info" HorizontalAlignment="Left" VerticalAlignment="Top" Width="420" Height="40" Background="#19233D" Foreground="#0C8370" FontWeight="Bold" FontSize="17"/> 
        
        <Label Content="Hostname" HorizontalAlignment="Left" Margin="0,37,0,0" VerticalAlignment="Top" Width="125" Height="30" Background="#19233D" Foreground="White" FontSize="14"/> 
        <TextBox Name="txtHostName" Height="20" Margin="130,43,5,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" IsEnabled="True" AllowDrop="True" BorderThickness="0" HorizontalAlignment="Left" Width="290" FontSize="14"/> 

        <Label Content="IP Address" HorizontalAlignment="Left" Margin="0,64,0,0" VerticalAlignment="Top" Width="125" Height="30" Background="#19233D" Foreground="White" FontSize="14"/> 
        <TextBox Name="txtWindowsIP" HorizontalAlignment="Left" Height="20" Margin="130,70,5,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="290" IsEnabled="True" BorderThickness="0" FontSize="14"/> 
    
              
        <Label Content="POS Version" HorizontalAlignment="Left" Margin="0,118,0,0" VerticalAlignment="Top" Width="125" Height="30" Background="#19233D" Foreground="White" FontSize="14"/> 
        <TextBox Name="txtposv" HorizontalAlignment="Left" Height="20" Margin="130,124,5,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="290" IsEnabled="True" BorderThickness="0" FontSize="14"/>         
       
        <Label Content="RevCtrl Version" HorizontalAlignment="Left" Margin="0,145,0,0" VerticalAlignment="Top" Width="125" Height="30" Background="#19233D" Foreground="White" FontSize="14"/> 
        <TextBox Name="txtcontrolv" HorizontalAlignment="Left" Height="20" Margin="130,151,5,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="290" IsEnabled="True" BorderThickness="0" FontSize="14"/>         
       
        <Label Content="RevCloud Version" HorizontalAlignment="Left" Margin="0,172,0,0" VerticalAlignment="Top" Width="125" Height="30" Background="#19233D" Foreground="White" FontSize="14"/> 
        <TextBox Name="txtcloudv" HorizontalAlignment="Left" Height="20" Margin="130,178,5,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="290" IsEnabled="True" BorderThickness="0" FontSize="14"/> 
 
        <Label Content="RevUpdate Version" HorizontalAlignment="Left" Margin="0,199,0,0" VerticalAlignment="Top" Width="125" Height="30" Background="#19233D" Foreground="White" FontSize="14"/> 
        <TextBox Name="txtupdatev" HorizontalAlignment="Left" Height="20" Margin="130,205,5,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="290" IsEnabled="True" BorderThickness="0" FontSize="14"/> 

    

        <Label Content="RevControl Svc" HorizontalAlignment="Left" Margin="0,253,0,0" VerticalAlignment="Top" Width="125" Height="30" Background="#19233D" Foreground="White" FontSize="14"/> 
        <TextBox Name="txtRevControl" Height="20" Margin="130,259,5,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" IsEnabled="True" AllowDrop="True" BorderThickness="0" HorizontalAlignment="Left" Width="290" FontSize="14"/> 

        <Label Content="RevCloud Svc" HorizontalAlignment="Left" Margin="0,280,0,0" VerticalAlignment="Top" Width="125" Height="30" Background="#19233D" Foreground="White" FontSize="14"/> 
        <TextBox Name="txtCloudSvc" Height="20" Margin="130,286,5,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" IsEnabled="True" AllowDrop="True" BorderThickness="0" HorizontalAlignment="Left" Width="290" FontSize="14"/> 

        <Label Content="RevCallerID Svc" HorizontalAlignment="Left" Margin="0,307,0,0" VerticalAlignment="Top" Width="125" Height="30" Background="#19233D" Foreground="White" FontSize="14"/> 
        <TextBox Name="txtCallerID" Height="20" Margin="130,313,5,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" IsEnabled="True" AllowDrop="True" BorderThickness="0" HorizontalAlignment="Left" Width="290" FontSize="14"/> 
        
        <Label Content="RevPrinter Svc" HorizontalAlignment="Left" Margin="0,334,0,0" VerticalAlignment="Top" Width="125" Height="30" Background="#19233D" Foreground="White" FontSize="14"/> 
        <TextBox Name="txtPrinterSvc" Height="20" Margin="130,340,5,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" IsEnabled="True" AllowDrop="True" BorderThickness="0" HorizontalAlignment="Left" Width="290" FontSize="14"/> 
   
        <Label Content="RevMonitor Svc" HorizontalAlignment="Left" Margin="0,361,0,0" VerticalAlignment="Top" Width="125" Height="30" Background="#19233D" Foreground="White" FontSize="14"/> 
        <TextBox Name="txtRevMonitorSvc" Height="20" Margin="130,367,5,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" IsEnabled="True" AllowDrop="True" BorderThickness="0" HorizontalAlignment="Left" Width="290" FontSize="14"/> 
        
        <Label Content="RevUpdate Svc" HorizontalAlignment="Left" Margin="0,388,0,0" VerticalAlignment="Top" Width="125" Height="30" Background="#19233D" Foreground="White" FontSize="14"/> 
        <TextBox Name="txtRevUpdateSvc" Height="20" Margin="130,394,5,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" IsEnabled="True" AllowDrop="True" BorderThickness="0" HorizontalAlignment="Left" Width="290" FontSize="14"/> 

        <Label Content="Tripos" HorizontalAlignment="Left" Margin="0,415,0,0" VerticalAlignment="Top" Width="125" Height="30" Background="#19233D" Foreground="White" FontSize="14"/> 
        <TextBox Name="txtTripos" Height="20" Margin="130,421,5,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" IsEnabled="True" AllowDrop="True" BorderThickness="0" HorizontalAlignment="Left" Width="290" FontSize="14"/> 
   
      

        <Label Content="HUB Port" HorizontalAlignment="Left" Margin="0,469,0,0" VerticalAlignment="Top" Width="125" Height="30" Background="#19233D" Foreground="White" FontSize="14"/> 
        <TextBox Name="txthub" Height="20" Margin="130,475,5,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" IsEnabled="True" AllowDrop="True" BorderThickness="0" HorizontalAlignment="Left" Width="290" FontSize="12"/> 
   
        <Label Content="HR Online Port" HorizontalAlignment="Left" Margin="0,496,0,0" VerticalAlignment="Top" Width="125" Height="30" Background="#19233D" Foreground="White" FontSize="14"/> 
        <TextBox Name="txthroo" Height="20" Margin="130,502,5,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" IsEnabled="True" AllowDrop="True" BorderThickness="0" HorizontalAlignment="Left" Width="290" FontSize="12"/> 
   

            <ListView Name="listview" SelectionMode="Single" Foreground="White" Background="Transparent" BorderBrush="Transparent" IsHitTestVisible="False"> 
                <ListView.ItemContainerStyle> 
                    <Style> 
                        <Setter Property="Control.HorizontalContentAlignment" Value="Stretch"/> 
                        <Setter Property="Control.VerticalContentAlignment" Value="Stretch"/> 
                    </Style> 
                </ListView.ItemContainerStyle> 
            </ListView> 
    </Grid> 
</Window> 
'@ 
 
#Read XAML 
$reader=(New-Object System.Xml.XmlNodeReader $xaml)  
try{$Form=[Windows.Markup.XamlReader]::Load( $reader )} 
catch{Write-Host "Unable to load Windows.Markup.XamlReader. Some possible causes for this problem include: .NET Framework is missing PowerShell must be launched with PowerShell -sta, invalid XAML code was encountered."; } 
 
#=========================================================================== 
# Store Form Objects In PowerShell 
#=========================================================================== 
$xaml.SelectNodes("//*[@Name]") | %{Set-Variable -Name ($_.Name) -Value $Form.FindName($_.Name)} 
 
Function RefreshData{ 
#=========================================================================== 
# Stores values in Object from System Classes 
#=========================================================================== 
$oCIMOS = @() 
$oCIMNIC = @() 
$HUBport = 12230
$HROOport = 7777
$IPAddress = (Invoke-WebRequest -uri "http://ifconfig.me/ip").Content

$oCIMOS = Get-CimInstance win32_OperatingSystem 
$oCIMNIC = Get-CimInstance Win32_NetworkAdapterConfiguration | Where { $_.IPAddress } | Select -Expand IPAddress | Where { $_ -like '1*' } 

$oControlSvc = get-service RevControlSvc | Where { $_.Status } | select -expand  Status 
$oCloudSvc = get-service RevCloudSvc | Where { $_.Status } | select -expand  Status 
$oCallerIDSvc = get-service RevCallerId | Where { $_.Status } | select -expand  Status
$oPrintSvc = get-service RevPrtSrv | Where { $_.Status } | select -expand  Status 
$oMonitorSvc = get-service RevMonitorSvc | Where { $_.Status } | select -expand  Status 
$oTripos = get-service TriPosService | Where { $_.Status } | select -expand  Status
$oRevUpdateSvc = get-service RUSvc | Where { $_.Status } | select -expand  Status

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

#=========================================================================== 
# Links Object Values to XAML Form Fields 
#=========================================================================== 
#Formats and displays OS name 
#$aOSName = $oCIMOS.name.Split("|") 
#$txtOSName.Text = ($aOSName[0] + " " + "(" + $Win10Ver + ")")


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



}
 
#=========================================================================== 
# Build Tray Icon 
#=========================================================================== 
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

