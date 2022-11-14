<#
    .NOTES
    ===========================================================================
    Created by:    Alex Ackerman
    GitHub:        https://github.com/darkhonor
    Twitter:       @darkhonor
    ===========================================================================
    .DESCRIPTION
        This script will gather key hardware and configuration information about
        ESXi hosts that are part of the provided vCenter's inventory.  Information
        gathered includes:

        - Name (as registered on the vCenter)
        - Version of ESXi
        - ESXi Build Number (Patch Level)
        - Manufacturer of the Host
        - Model Number for the Hardware
        - Processor Type for the CPU
        - If EVC is enabled, what is the highest supported version
        - Number of CPU Cores available (including all installed processors)
        - Total Memory in GB
        - Total Memory *currently* being Used in GB
        - Current Management IP Address for the ESXi Host
        - Assigned License Key

    .PARAMETER Server
        The hostname or IP Address for the vCenter Server
    
    .PARAMETER outFile
        The name of the CSV file to save the information to

    .EXAMPLE
        VMware-VMHost-Inventory.ps1 -Server vc01.lab.local

    .EXAMPLE
        VMware-VMHost-Inventory.ps1 -Server vc01.lab.local -outFile "C:\Temp\inventory.csv"
#>
#Requires -Version 5.0
#Requires -Modules VMware.VimAutomation.Core, @{ModuleName="VMware.VimAutomation.Core";ModuleVersion="6.3.0.0"}
[CmdletBinding()]
Param (
    # vCenter Server name is mandatory
    [Parameter(Mandatory=$true)]
    [string] $Server,
    # Name of the CSV File to Output results
    [string] $outFile = "host-inventory.csv"
)
Import-Module VMware.VimAutomation.Core

# Gather the credentials of an Administrative user
$creds = Get-Credential -Message "Enter vCenter Credentials"

# Connect to the vCenter Server with the credentials provided
Write-Host -ForegroundColor White "Connecting to vCenter Server:"
Connect-VIServer -Server $Server -Credential $creds -WarningAction SilentlyContinue

# Gather the required facts about each of the assigned hosts
<#
 # Gather facts about each of the hosts:
 #  - Name (as registered on the vCenter)
 #  - Version of ESXi
 #  - ESXi Build Number (Patch Level)
 #  - Manufacturer of the Host
 #  - Model Number for the Hardware
 #  - Processor Type for the CPU
 #  - If EVC is enabled, what is the highest supported version
 #  - Number of CPU Cores available (including all installed processors)
 #  - Total Memory in GB
 #  - Total Memory *currently* being Used in GB
 #  - Current Management IP Address for the ESXi Host
 #  - Assigned License Key
#>
Write-Host -ForegroundColor White -NoNewline "Gathering ESXi Host Data: "
$inquiry = Get-VMHost | Select-Object -Property Name, Version, Build, Manufacturer,
        Model, ProcessorType, MaxEVCMode, NumCpu, MemoryTotalGB, MemoryUsageGB,
        @{N="Mgt IP Address";E={($_.ExtensionData.Config.Network.Vnic | 
            ? {$_.Device -eq "vmk0"}).Spec.Ip.IpAddress}}, LicenseKey
Write-Host -ForegroundColor Green "Done"

# Save the information to a CSV file on the local file system
Write-Host -ForegroundColor White -NoNewline "Saving to $outFile : "
$inquiry | ConvertTo-Csv | Out-File -FilePath $outFile
Write-Host -ForegroundColor Green "Done"

# Disconnect from the vCenter Server
Write-Host -ForegroundColor White -NoNewline "Disconnecting from vCenter Server: "
Disconnect-VIServer -Server $Server -Confirm:$false
Write-Host -ForegroundColor Green "Done"