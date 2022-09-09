#
# Simple script to renew the Machine SSL certificate using the embedded VMCA certificate
# Author: Alex Ackerman
# Last Update: 10 Sept 2022
#

Import-Module VMware.VimAutomation.Core
Import-Module VMware.Sdk.vSphere.vCenter.CertManagement

# Script Variables
$VIServer = "vcenter.domain.local"
$creds = Get-Credential -Message "Enter login for user with Certificate Management Role"
$duration = 730 # Default value: 2 years

# Login to the vCenter Server
Connect-VIServer -Server $VIServer  -Credential $creds

# Configure the Certificate Request
$certificateRequestBody = Initialize-CertificateManagementVcenterTlsRenewRequestBody -Duration $duration

# Renew the certificate
Invoke-RenewTls -CertificateManagementVcenterTlsRenewRequestBody $certificateRequestBody

Disconnect-VIServer -Confirm $false

