# 
# Script to apply STIG settings to a VMware Horizon Server
# 
# STIG Verion: v1r1
#

Import-Module VMware.VimAutomation.HorizonView

$HorizonCS = "local.connserver.net"
# Prompt the user for Horizon Console Admin Credentials (domain\username)
$credential = Get-Credential -Message "Enter Horizon Admin Credentials"

# Adjust the following for your environment
# STIG requires both, but may not be set in your envionment
$pkiEnabled  = $false
$twoFactorEnabled = $false

# Specify if UAG is performing authentication
$uagAuth = $true

# Specify Event Database Connection Details
$configureDb = $true
$dbType = "SQLSERVER"
$dbPort = 1433
$dbName = "HorizonEvents"
#TODO: Need to add full Events DB configuration


# Function: Get-MapEntry
# Description: Creates a new VMware.Hv.MapEntry object with the specified Key and Value
# Source: https://github.com/vmware/PowerCLI-Example-Scripts/tree/master/Modules/VMware.Hv.Helper
function Get-MapEntry {
    param(
      [Parameter(Mandatory = $true)]
      $Key,
  
      [Parameter(Mandatory = $true)]
      $Value
    )
  
    $update = New-Object VMware.Hv.MapEntry
    $update.key = $key
    $update.value = $value
    return $update
}

# Connect to the Horizon Server with the provided credentials
Connect-HVServer -Server $HorizonCS -Credential $credential

$viewAPI = $global:DefaultHVServers.ExtensionData

$HvServers = $viewAPI.ConnectionServer.ConnectionServer_List()

$updates = @()

# STIG V-246888: The Horizon Connection Server must require DoD PKI for administrative logins.
#   This setting is dependent on value of "pkiEnabled" boolean above.  STIG setting is REQUIRED
if ($pkiEnabled) {
  # PKI Support is Enabled on the Servers per STIG
  $update = Get-MapEntry -key 'authentication.smartCardSupportForAdmin' -Value "REQUIRED"
} else {
  # PKI Support is not Enabled on the Servers
  $update = Get-MapEntry -key 'authentication.smartCardSupportForAdmin' -Value "OFF"
}
for ($i = 0; $i -lt $HvServers.count; $i++) {
  $viewAPI.ConnectionServer.ConnectionServer_Update($HvServers[$i].Id, $update)
}

# STIG V-246894: The Horizon Connection Server must time out administrative sessions after 15 minutes or less.
$updates += Get-MapEntry -key 'generalData.consoleSessionTimeoutMinutes' -Value 15

# STIG V-246898: The Horizon Connection Server must reauthenticate users after a network interruption.
$updates += Get-MapEntry -key 'securityData.reauthSecureTunnelAfterInterruption' -Value $true

# STIG V-246899: The Horizon Connection Server must disconnect users after a maximum of ten hours
$updates += Get-MapEntry -key 'generalData.clientMaxSessionTimePolicy' -Value "TIMEOUT_AFTER"
$updates += Get-MapEntry -key 'generalData.clientMaxSessionTimeMinutes' -Value 600

# STIG V-246900: The Horizon Connection Server must disconnect applications after two hours of idle time.
$updates += Get-MapEntry -key 'generalData.clientIdleSessionTimeoutPolicy' -Value "TIMEOUT_AFTER"
$updates += Get-MapEntry -key 'generalData.clientIdleSessionTimeoutMinutes' -Value 120

# STIG V-246901: The Horizon Connection Server must discard SSO credentials after 15 minutes.
$updates += Get-MapEntry -Key 'generalData.desktopSSOTimeoutPolicy' -Value "DISABLE_AFTER"
$updates += Get-MapEntry -Key 'generalData.desktopSSOTimeoutMinutes' -Value 15

# STIG V-246902: The Horizon Connection Server must not accept pass-through client credentials.
$newGssAPISettings = Get-MapEntry -Key 'general.enableLoginAsCurrentUser' -Value $false
for ($i = 0; $i -lt $HvServers.count; $i++) {
  $gssId = $HvServers[$i].Authentication.GssAPIConfig.GssAPIAuthenticator
  $viewAPI.GssAPIAuthenticator.GssAPIAuthenticator_Update($gssId, $newGssAPISettings)
}

# STIG V-246903: The Horizon Connection Server must require DoD PKI for client logins.
#   This setting is dependent on value of "pkiEnabled" boolean above.  STIG setting is REQUIRED
#   If the Connection Server is paired with a Unified Access Gateway (UAG) that is performing 
#   authentication, this requirement is not applicable
if ($pkiEnabled -and !($uagAuth)) {
  # PKI Support is Enabled on the Servers per STIG
  $update = Get-MapEntry -key 'authentication.smartCardSupport' -Value "REQUIRED"
} else {
  # PKI Support is not Enabled on the Servers
  $update = Get-MapEntry -key 'authentication.smartCardSupport' -Value "OFF"
}
for ($i = 0; $i -lt $HvServers.count; $i++) {
  $viewAPI.ConnectionServer.ConnectionServer_Update($HvServers[$i].Id, $update)
}

# STIG V-246913: The Horizon Connection Server must require CAC reauthentication after user idle timeouts.
#   This setting will be set to the 'twoFactorEnabled' environment variable above
$updates += Get-MapEntry -Key 'generalData.enableMultiFactorReAuth' -Value $twoFactorEnabled

# Save the new settings to the View Server
$viewAPI.GlobalSettings.GlobalSettings_Update($updates)

# Display the current Settings after the Script has run
$globalSettings = $viewAPI.GlobalSettings.GlobalSettings_Get()
$globalSettings.GeneralData

# When complete, disconnect from the server
Disconnect-HVServer
