####################################################
#                                                  #
#  Please reach out to NEXTGEN for any additions,  #
#  bug fixes, corrections or otherwise. Script is  #
#  provided with no guarantees, use with caution.  #
#  It is not advised to use this outside of the    #             
#                   CyberLAB                       # 
#                                                  #
#        hayden.loader@nextgen.group               #
#                                                  #
####################################################

param (
    [int]$option,
    [string]$action,
    [int]$sizeInMB
)

$CL_build_intro = @'

 ██████ ██    ██ ██████  ███████ ██████  ██       █████  ██████      ████████  ██████   ██████  ██      ███████ 
██       ██  ██  ██   ██ ██      ██   ██ ██      ██   ██ ██   ██        ██    ██    ██ ██    ██ ██      ██      
██        ████   ██████  █████   ██████  ██      ███████ ██████         ██    ██    ██ ██    ██ ██      ███████ 
██         ██    ██   ██ ██      ██   ██ ██      ██   ██ ██   ██        ██    ██    ██ ██    ██ ██           ██ 
 ██████    ██    ██████  ███████ ██   ██ ███████ ██   ██ ██████         ██     ██████   ██████  ███████ ███████ 
                                                                                                                                                                                                                            
                                        Written by Hd0s
                                        
'@

function Show-Menu {
    Clear-Host
    Write-Host "================================================================================="
    Write-Host "                                 CyberLAB Toolbox"
    Write-Host "                             (This script is an alpha)"
    Write-Host "                                       V0.4"
    Write-Host "                                     20240613"
    Write-Host ""
    Write-Host "                      Contact: hayden.loader@nextgen.group"
    Write-Host "================================================================================="
    Write-Host "1. Download this script to the local machine"
    Write-Host "2. Building a domain controller"
    Write-Host "3. Domain joining an endpoint"
    Write-Host "4. Expand the current partition when you've increased the drive in CloudShare"
    Write-Host "5. Virtual USB functions"
    Write-Host "6. Change computer name"
    Write-Host "7. Change password for logged-in user"
    Write-Host "8. Show system info"
    Write-Host "9. Show disk usage"
    Write-Host "10. Display network information"
    Write-Host "11. Check networking function"
    Write-Host "12. Nmap scan your current network"
    Write-Host "13. Open CloudShare support website in the browser"
    Write-Host "14. Exit"
    Write-Host "================================================================================="
}

function Example1 {
    Write-Host "This is a test for downloading this script to the local machine."
}

function Example2 {
    # Function to install required modules
function Install-RequiredModules {
    Write-Host "DEBUG: Entering Install-RequiredModules function..."
    Write-Host "Installing required modules..."
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -WarningAction SilentlyContinue
    if (-Not (Get-WindowsFeature AD-Domain-Services).Installed) {
        Write-Host "Failed to install AD-Domain-Services. Exiting..."
        exit 1
    }
    Write-Host "DEBUG: Exiting Install-RequiredModules function..."
}

# Function to configure Active Directory Domain Services
function Configure-ADDS {
    param (
        [string]$domainName,
        [string]$safeModeAdminPassword
    )
    Write-Host "DEBUG: Entering Configure-ADDS function..."
    Write-Host "Configuring Active Directory Domain Services..."
    Install-ADDSForest -DomainName $domainName -SafeModeAdministratorPassword (ConvertTo-SecureString $safeModeAdminPassword -AsPlainText -Force) -Force -NoRebootOnCompletion -WarningAction SilentlyContinue
    if ($?) {
        Write-Host "======================================================================="
        Write-Host "**Active Directory Domain Services configured successfully."
        Write-Host "DEBUG: AD DS configuration successful. Rebooting server momentarily..."
        Write-Host "**After you reboot your VM, you must log in with the domain administrator user."
        Write-Host "**CloudShare will not automatically log in untill you configure the domain."
        Write-Host "**Use the time that VM is restarting to do so."
        Write-Host "**Check this URL for instructions: https://support.cloudshare.com/hc/en-us/articles/200700935-Add-Virtual-Machines-to-an-Active-Directory-Domain#:~:text=the%20CloudShare%20portal.-,2,-.%20Configure%20the%20domain"
        Write-Host "**You may also need to configure automatic login"
        Write-Host " "
        Write-Host " "
        Write-Host -fore red "======================================================================="
        Write-Host -fore red "You must re-run this script in order for DNS to be correctly configured"
        Write-Host -fore red "Re-run the script and select the option to Build the domain controller"
        Write-Host -fore red "======================================================================="
        Pause
        Restart-Computer
    } else {
        Write-Host "Failed to configure Active Directory Domain Services. Exiting..."
        exit 1
    }
    Write-Host "DEBUG: Exiting Configure-ADDS function..."
}

# Function to check if required modules are installed
function Check-RequiredModules {
    Write-Host "DEBUG: Entering Check-RequiredModules function..."
    $result = (Get-WindowsFeature AD-Domain-Services -WarningAction SilentlyContinue).Installed
    Write-Host "DEBUG: AD-Domain-Services installed: $result"
    Write-Host "DEBUG: Exiting Check-RequiredModules function..."
    return $result
}

# Function to check if AD DS is already configured
function Is-ADDSConfigured {
    Write-Host "DEBUG: Entering Is-ADDSConfigured function..."
    try {
        Get-ADDomain | Out-Null
        Write-Host "DEBUG: AD DS is already configured."
        return $true
    } catch {
        Write-Host "DEBUG: AD DS is not configured."
        return $false
    }
    Write-Host "DEBUG: Exiting Is-ADDSConfigured function..."
}

# Function to set up DNS
function Configure-DNS {
    param (
        [string]$domainName
    )
    Write-Host "DEBUG: Entering Configure-DNS function..."
    Write-Host "Configuring DNS..."
    Add-DnsServerPrimaryZone -Name $domainName -ReplicationScope "Forest" -WarningAction SilentlyContinue
    Add-DnsServerPrimaryZone -Name "0.0.10.in-addr.arpa" -ReplicationScope "Forest" -WarningAction SilentlyContinue
    Write-Host "DNS configured successfully."
    Write-Host "DEBUG: Exiting Configure-DNS function..."
}

# Specific function to set up the domain controller
function Setup-DomainController {
    Write-Host "DEBUG: Entering Setup-DomainController function..."
    if (-Not (Check-RequiredModules)) {
        Write-Host "DEBUG: Required modules not found. Installing..."
        Install-RequiredModules
    } else {
        Write-Host "DEBUG: Required modules already installed."
    }

    if (-Not (Is-ADDSConfigured)) {
        $domainName = Read-Host "Enter the domain name (e.g., example.com)"
        $safeModeAdminPassword = Read-Host "Enter the Safe Mode Administrator password"
        Write-Host "DEBUG: Configuring AD DS with domain name: $domainName"
        Configure-ADDS -domainName $domainName -safeModeAdminPassword $safeModeAdminPassword
    } else {
        Write-Host "DEBUG: AD DS is already configured. Continuing to DNS setup..."
    }

    if (-Not (Get-DnsServerZone)) {
        $domainName = (Get-ADDomain).DNSRoot
        Write-Host "DEBUG: Configuring DNS with domain name: $domainName"
        Configure-DNS -domainName $domainName
    } else {
        Write-Host "DEBUG: DNS is already configured."
    }

    Write-Host "Domain controller setup complete."
    Write-Host "DEBUG: Exiting Setup-DomainController function..."
}

# Run the specific function
Setup-DomainController

}

function Example3 {
    # Function to set DNS Server Address
    function Set-DnsServerAddress {
        param (
            [string]$adapterName,
            [string]$dnsAddress
        )
        Get-NetAdapter -Name $adapterName | Set-DnsClientServerAddress -ServerAddresses $dnsAddress
    }

    # Function to test credentials
    function Test-Credentials {
        param (
            [string]$domainControllerIP,
            [PSCredential]$credential
        )
        try {
            $connection = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainControllerIP", $credential.UserName, $credential.GetNetworkCredential().Password)
            $connection.RefreshCache()
            return $true
        } catch {
            return $false
        }
    }

    # Function to test if the IP address is reachable
    function Test-IP {
        param (
            [string]$ipAddress
        )
        try {
            $ping = Test-Connection -ComputerName $ipAddress -Count 1 -Quiet
            return $ping
        } catch {
            return $false
        }
    }

    # Get Domain Name from user
    $domainName = Read-Host "Enter the domain name (e.g., coolcoy.com)"

    # Loop until a valid domain controller IP is provided
    $ipValid = $false
    while (-not $ipValid) {
        $domainControllerIP = Read-Host "Enter the IP address of the domain controller"
        $ipValid = Test-IP -ipAddress $domainControllerIP

        if (-not $ipValid) {
            Write-Host -ForegroundColor Red "Invalid or unreachable IP address. Please try again."
        }
    }

    # Get all network adapters
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

    # Loop until a valid adapter index is selected
    $adapterValid = $false
    while (-not $adapterValid) {
        # List all available network adapters and prompt the user to select one
        Write-Host "Available network adapters:"
        $adapters | ForEach-Object { Write-Host "$($_.InterfaceIndex): $($_.Name)" }
        $adapterIndex = Read-Host "Enter the interface index of the adapter to use"
        $adapterName = ($adapters | Where-Object { $_.InterfaceIndex -eq $adapterIndex }).Name
        
        if ($adapterName) {
            $adapterValid = $true
        } else {
            Write-Host -ForegroundColor Red "Invalid adapter index. Please try again."
        }
    }

    # Set primary DNS server address
    Set-DnsServerAddress -adapterName $adapterName -dnsAddress $domainControllerIP
    Write-Host "Primary DNS server address set to $domainControllerIP for adapter $adapterName."

    # Check domain join status and join if not already joined
    Write-Host "VM name and DNS information selected. Checking domain join status."
    Start-Sleep -Seconds 2

    if ((Get-WmiObject win32_computersystem).PartOfDomain -eq $true) {
        Write-Host -ForegroundColor Green "I am domain joined!"
    } else {
        Write-Host -ForegroundColor Red "Not yet domain joined!"
        $username = "$domainName\Administrator"

        # Loop to prompt for credentials until valid
        $credentialsValid = $false
        while (-not $credentialsValid) {
            $credential = Get-Credential -UserName $username -Message "Enter credentials for $username"
            $credentialsValid = Test-Credentials -domainControllerIP $domainControllerIP -credential $credential
            
            if (-not $credentialsValid) {
                Write-Host -ForegroundColor Red "Invalid credentials. Please try again."
                Pause
            }
        }

        # Join the domain if credentials are valid
        Add-Computer -ComputerName $env:computername -DomainName $domainName -Credential $credential
        Write-Host "Rebooting now!"
        Pause
        Restart-Computer -Force
        
    }

    Write-Host "Great work! All set!"
    Pause
}



function Example4 {
    Write-Host "This is a test for expanding the current partition when you've increased the drive in CloudShare."
}

function Example5 {
    param (
        [string]$action,
        [int]$sizeInMB
    )

    # Function to create a virtual USB storage drive
    function Create-VirtualUSB {
        param (
            [int]$sizeInMB
        )

        $drivePath = "C:\VirtualUSB.vhdx"
        $sizeInBytes = $sizeInMB * 1MB

        # Create the virtual disk
        Write-Host "Creating virtual USB drive of size $sizeInMB MB at $drivePath"
        try {
            New-VHD -Path $drivePath -Dynamic -SizeBytes $sizeInBytes -Confirm:$false | Out-Null
        } catch {
            Write-Host "Failed to create the virtual hard disk. Error: $_"
            return
        }

        # Attach the virtual disk
        Write-Host "Attaching the virtual USB drive"
        try {
            Mount-VHD -Path $drivePath -PassThru | Initialize-Disk -PassThru -PartitionStyle MBR | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "VirtualUSB" -Confirm:$false
            Write-Host "Virtual USB drive created and attached successfully."
        } catch {
            Write-Host "Failed to attach the virtual USB drive. Error: $_"
            return
        }
    }

    # Function to disconnect and remove the virtual USB storage drive
    function Remove-VirtualUSB {
        $drivePath = "C:\VirtualUSB.vhdx"
        if (Test-Path $drivePath) {
            $vhd = Get-VHD -Path $drivePath
            if ($vhd.Attached) {
                Write-Host "The virtual USB drive is currently attached with drive letters:"
                $vhd | Get-Disk | Get-Partition | Format-Table -Property DriveLetter, Size, PartitionNumber

                $confirmation = Read-Host "Do you want to detach and remove this virtual USB drive? (yes/no)"
                if ($confirmation -eq 'yes') {
                    Write-Host "Detaching the virtual USB drive"
                    Dismount-VHD -Path $drivePath -Confirm:$false
                    Write-Host "Deleting the virtual USB drive file"
                    Remove-Item -Path $drivePath -Confirm:$false
                    Write-Host "Virtual USB drive detached and removed successfully."
                } else {
                    Write-Host "Operation cancelled by the user."
                }
            } else {
                Write-Host "The virtual USB drive is not attached. Deleting the file."
                Remove-Item -Path $drivePath -Confirm:$false
                Write-Host "Virtual USB drive file removed successfully."
            }
        } else {
            Write-Host "No virtual USB drive found at $drivePath"
        }
    }

    # Prompt for action and size if not provided
    if (-not $action) {
        $action = Read-Host "Enter the action (create/disconnect)"
    }

    if ($action -eq 'create') {
        if (-not $sizeInMB) {
            $sizeInMB = Read-Host "Enter the size of the virtual USB storage (in MB)"
        }
        if ($sizeInMB -match '^\d+$') {
            Create-VirtualUSB -sizeInMB $sizeInMB
        } else {
            Write-Host "Invalid size entered. Please enter a valid number."
        }
    } elseif ($action -eq 'disconnect') {
        Remove-VirtualUSB
    } else {
        Write-Host "Invalid action. Use 'create' to create a virtual USB or 'disconnect' to disconnect and remove it."
    }
}

function Example6 {
    Write-Host "This is a test for changing the computer name."
}

function Example7 {
    Write-Host "This is a test for changing the password for the logged-in user."
}

function Example8 {
    Get-ComputerInfo
}

function Example9 {
    Get-PSDrive -PSProvider FileSystem | Select-Object Name, Used, Free, @{Name="Used(GB)";Expression={"{0:N2}" -f ($_.Used / 1GB)}}, @{Name="Free(GB)";Expression={"{0:N2}" -f ($_.Free / 1GB)}}, @{Name="Total(GB)";Expression={"{0:N2}" -f ($_.Used / 1GB + $_.Free / 1GB)}}
}

function Example10 {
    Write-Host "This is a test for displaying network information."
}

function Example11 {
    Write-Host "This is a test for checking networking function."
}

function Example12 {
    Write-Host "This is a test for an Nmap scan of your current network."
}

function Example13 {
    # Print the message
    Write-Host "Opening the CloudShare Support Portal. Feel free to raise tickets if you would like, but please keep lab-support@nextgen.group on CC. Please take a look through the FAQs before raising a ticket. Feel free to reach out to NEXTGEN before raising a ticket through CloudShare."

    # Open the URL in the default web browser
    Start-Process "https://support.cloudshare.com/"
}

function ExecuteOption {
    param (
        [int]$choice,
        [string]$action,
        [int]$sizeInMB
    )

    switch ($choice) {
        1 { Example1 }
        2 { Example2 }
        3 { Example3 }
        4 { Example4 }
        5 { Example5 -action $action -sizeInMB $sizeInMB }
        6 { Example6 }
        7 { Example7 }
        8 { Example8 }
        9 { Example9 }
        10 { Example10 }
        11 { Example11 }
        12 { Example12 }
        13 { Example13 }
        14 { Write-Host "Exiting..." }
        default { Write-Host "Invalid choice. Please select a number between 1 and 14." }
    }
}

function Check-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
    return $currentPrincipal.IsInRole($adminRole)
}

function Check-ExecutionPolicy {
    $executionPolicy = Get-ExecutionPolicy
    return $executionPolicy -ne 'Restricted' -and $executionPolicy -ne 'Undefined'
}

function Main {
    Write-Host $CL_build_intro  # Ensure this is inside Main function
    Start-Sleep -Seconds 1
#    Write-Host "Entering Main function..."  # Debug statement

    if (-not (Check-Admin)) {
        Write-Host "This script must be run as an administrator. Exiting..."
        exit 1
    }

    if (-not (Check-ExecutionPolicy)) {
        Write-Host "Script execution is not enabled. Please set the execution policy to allow script execution. Exiting..."
        exit 1
    }

    if ($option -ne $null -and $option -ne 0) {
#        Write-Host "Running with option: $option"  # Debug statement
        ExecuteOption -choice $option -action $action -sizeInMB $sizeInMB
        Write-Host "`nPress any key to exit..."
        Read-Host
        exit
    } else {
#        Write-Host "Running in interactive mode..."  # Debug statement
        while ($true) {
            Show-Menu
            $choice = Read-Host "Enter your choice (1-14)"
            ExecuteOption -choice $choice

            if ($choice -eq 14) {
                break
            }

            Pause
        }
    }
}

Main
