# Prompt user
$customPCName = Read-Host "Enter PC NAME"
$deptName = Read-Host "Enter Department/Ward/Physical Location"

# Set save path
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$csvPath = Join-Path $scriptPath "System_Report.csv"

# Get Windows version info (like winver)
$reg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$displayVersion = $reg.DisplayVersion
$build = $reg.CurrentBuild
$ubr = $reg.UBR
$winverLine = "Version $displayVersion, OS Build $build.$ubr"

# Helper function to extract IP and CIDR
function Parse-IPInfo {
    param ($ipObj)
    if ($ipObj -and $ipObj.IPAddress -and $ipObj.PrefixLength) {
        $ipAddress = $ipObj.IPAddress
        $subnetMask = "/$($ipObj.PrefixLength)"
        return @{ IP = $ipAddress; CIDR = $subnetMask }
    }
    return @{ IP = ""; CIDR = "" }
}

# Initialize variables
$ethernetIP = ""; $ethernetMAC = ""; $ethernetSubnet = ""; $ethernetGateway = ""
$wifiIP = ""; $wifiMAC = ""; $wifiSubnet = ""; $wifiGateway = ""

# Get Ethernet Info
$ethernetAdapters = Get-NetAdapter | Where-Object {
    $_.Status -eq "Up" -and
    $_.InterfaceDescription -notmatch "Virtual|vEthernet|Wi-Fi|Loopback|TAP|Hyper-V"
}

foreach ($adapter in $ethernetAdapters) {
    $ipInfo = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike "169.*" -and $_.IPAddress -ne "127.0.0.1" } |
        Select-Object -First 1

    $gwInfo = Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if ($ipInfo) {
        $parsed = Parse-IPInfo -ipObj $ipInfo
        $ethernetIP = $parsed.IP
        $ethernetSubnet = $parsed.CIDR
        $ethernetMAC = $adapter.MacAddress
        $ethernetGateway = if ($gwInfo) { $gwInfo.NextHop } else { "" }
        break
    }
}

# Get Wi-Fi Info
$wifiAdapters = Get-NetAdapter | Where-Object {
    $_.Status -eq "Up" -and $_.InterfaceDescription -match "Wi-Fi|Wireless"
}

foreach ($adapter in $wifiAdapters) {
    $ipInfo = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike "169.*" -and $_.IPAddress -ne "127.0.0.1" } |
        Select-Object -First 1

    $gwInfo = Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if ($ipInfo) {
        $parsed = Parse-IPInfo -ipObj $ipInfo
        $wifiIP = $parsed.IP
        $wifiSubnet = $parsed.CIDR
        $wifiMAC = $adapter.MacAddress
        $wifiGateway = if ($gwInfo) { $gwInfo.NextHop } else { "" }
        break
    }
}

# System info
$os  = Get-CimInstance Win32_OperatingSystem
$sys = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS

# Office version
function Get-OfficeVersion {
    $office = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" `
        -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match "Microsoft Office" -or $_.DisplayName -match "Microsoft 365" } |
        Select-Object -First 1

    if ($office) {
        return $office.DisplayName
    }

    $office = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" `
        -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match "Microsoft Office" -or $_.DisplayName -match "Microsoft 365" } |
        Select-Object -First 1

    if ($office) {
        return $office.DisplayName
    }

    return "Not Found"
}

# Connected printers
function Get-ConnectedPhysicalPrinters {
    $excluded = @("OneNote", "XPS", "Microsoft", "Fax", "Redirected", "IPP")
    $printerDevices = Get-CimInstance Win32_PnPEntity | Where-Object {
        $_.ClassGuid -eq "{4d36e979-e325-11ce-bfc1-08002be10318}" -and $_.Status -eq "OK"
    }

    $realPrinters = @()

    foreach ($device in $printerDevices) {
        $name = $device.Name
        if ($excluded -notcontains ($name.Split(" ")[0])) {
            $serial = ""

            if ($device.PNPDeviceID -match "USB\\.*\\(?<serial>.*)$") {
                $serial = $matches['serial']
            }

            $realPrinters += "$name (Serial: $serial)"
        }
    }

    return $realPrinters -join "; "
}

# Extra info
$biosVer = $bios.SMBIOSBIOSVersion
$domain = if ($sys.PartOfDomain) { $sys.Domain } else { "Workgroup" }
$ramGB = [math]::Round($sys.TotalPhysicalMemory / 1GB, 2)
$cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
$gpu = (Get-CimInstance Win32_VideoController | Select-Object -First 1).Name
$storage = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object -First 1).Size
$storageGB = if ($storage) { [math]::Round($storage / 1GB, 2) } else { "Unknown" }

# Final report
$data = [PSCustomObject]@{
    'PC Name'                  = $customPCName
    'Department/Ward/Physical Location' = $deptName
    'Hostname'                 = $env:COMPUTERNAME
    'Windows Version Info'     = $winverLine
    'OS Name'                  = $os.Caption
    'Ethernet IP'              = $ethernetIP
    'Ethernet Subnet Mask'     = $ethernetSubnet
    'Ethernet Default Gateway' = $ethernetGateway
    'Ethernet MAC'             = $ethernetMAC
    'Wi-Fi IP'                 = $wifiIP
    'Wi-Fi Subnet Mask'        = $wifiSubnet
    'Wi-Fi Default Gateway'    = $wifiGateway
    'Wi-Fi MAC'                = $wifiMAC
    'Manufacturer'             = $sys.Manufacturer
    'Model'                    = $sys.Model
    'Serial Number'            = $bios.SerialNumber
    'BIOS Version'             = $biosVer
    'Domain/Workgroup'         = $domain
    'RAM (GB)'                 = $ramGB
    'Storage C: (GB)'          = $storageGB
    'Processor'                = $cpu
    'Graphics Card'            = $gpu
    'Office Version'           = Get-OfficeVersion
    'Connected Printers'       = Get-ConnectedPhysicalPrinters
}

# Append to CSV
$writeHeader = -not (Test-Path $csvPath) -or (Get-Content $csvPath).Length -eq 0

$data | Select-Object 'PC Name', 'Department/Ward/Physical Location', 'Hostname','Windows Version Info','OS Name',
    'Ethernet IP','Ethernet Subnet Mask','Ethernet Default Gateway','Ethernet MAC',
    'Wi-Fi IP','Wi-Fi Subnet Mask','Wi-Fi Default Gateway','Wi-Fi MAC',
    'Manufacturer','Model','Serial Number','BIOS Version','Domain/Workgroup',
    'RAM (GB)','Storage C: (GB)','Processor','Graphics Card',
    'Office Version','Connected Printers' |
    Export-Csv -Path $csvPath -Append:(!$writeHeader) -NoTypeInformation -Encoding UTF8

# Open CSV
Start-Process $csvPath
