<#
    gather-vm-specs.ps1
    Author: Alex Ackerman
    Last Modified: 8 Dec 2022

    From the provided ESXi Host or vCenter, gather the full list of virtual machines with their 
    allocated specifications.
#>
[CmdletBinding()]
Param (
    # vCenter Server name is mandatory
    [Parameter(Mandatory=$true)]
    [string] $VIServer,
    # Name of the CSV File to Output results
    [string] $outFile = "vm-inventory.csv"
)
Import-Module VMware.VimAutomation.Core

# Script Variables
$creds = Get-Credential -Message "Enter login details for user with rights to inventory the VMware Service"

# Login to the vCenter Server
Connect-VIServer -Server $VIServer  -Credential $creds

Write-Host -ForegroundColor White -NoNewline "Gathering Virtual Machine Data: "
$inquiry = Get-VM | Select-Object -Property Name, NumCpu, MemoryGB, ProvisionedSpaceGB, ResourcePool, PowerState, Notes
Write-Host -ForegroundColor Green "Done"

# Save the information to a CSV file on the local file system
Write-Host -ForegroundColor White -NoNewline "Saving to $outFile : "
$inquiry | ConvertTo-Csv | Out-File -FilePath $outFile
Write-Host -ForegroundColor Green "Done"

# Disconnect from the vCenter Server
Write-Host -ForegroundColor White -NoNewline "Disconnecting from vCenter Server: "
Disconnect-VIServer -Server $Server -Confirm:$false
Write-Host -ForegroundColor Green "Done"
