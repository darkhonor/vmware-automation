#
# Simple script to renew the Machine SSL certificate using the embedded VMCA certificate
#
# Author: Alex Ackerman
# Last Update: 14 Sept 2022
#
[CmdletBinding()]
Param (
    # vCenter Server name is mandatory
    [Parameter(Mandatory=$true)]
    [string] $VIServer,
    # Certificate duration will default to the standard 2 years if not provided
    [int] $duration = 730
)
Import-Module VMware.VimAutomation.Core
Import-Module VMware.Sdk.vSphere.vCenter.CertManagement

# Script Variables
$creds = Get-Credential -Message "Enter login for user with Certificate Management Role"

# Login to the vCenter Server
Connect-VIServer -Server $VIServer  -Credential $creds

# Configure the Certificate Request
$certificateRequestBody = Initialize-CertificateManagementVcenterTlsRenewRequestBody -Duration $duration

# Renew the certificate
Invoke-RenewTls -CertificateManagementVcenterTlsRenewRequestBody $certificateRequestBody

Disconnect-VIServer -Confirm $false

