<#
 # Script to conduct an audit of an ESXi Host to ensure compliance with 
 # current STIG guidelines. This audit will work on vSphere ESXi 6.7 and 7.0.  
 # It has not been tested on 8.0 as of this time.
 # 
 # Script is STIG Compliant: VMware vSphere 6.7 ESXi V1R2
 # 
 # Author: Alex Ackerman
 # Date Modified: 26 Oct 2022
 #>
[CmdletBinding()]
Param (
    # ESXi Server to audit
    [Parameter(Mandatory = $true)]
    [string] $Server,
    [Parameter(Mandatory = $false)]
    [bool] $fix = $false
)
Import-Module VMware.VimAutomation.Core

# Import the General VMware Helper Module
$ScriptPath = $MyInvocation.MyCommand.Path
$ScriptDir = Split-Path -Parent $ScriptPath
$HelperModule = $ScriptDir + "\VMware-Helper.psm1"

if (!(Test-path $HelperModule)) {
    Write-host "Error: PowerShell Module $HelperModule not found." -foregroundcolor red -backgroundcolor black
    Exit
}
Import-Module $HelperModule -Force

# Login to the ESXi Host
$creds = Get-Credential -Message "Enter ESXi Root Credentials"
Connect-VIServer -Server $Server -Credential $creds

# Need to grab the VMHost variable.  It's used by functions throughout...
$VmHost = Get-VMHost -Name $Server

Write-Host -ForegroundColor Yellow "Starting DISA STIG Audit of ESXi Host..."
$TotalChecks = 0
$TotalPass = 0

# V-239258: Access to the ESXi host must be limited by enabling Lockdown Mode.

# V-239259: The ESXi host must verify the DCUI.Access list.
$result = Assert-AdvancedSetting -StigId "V-239259" -VmHost $VmHost -Name "DCUI.Access" -ExpectedOutput "root"
$TotalChecks++
if ($result) {
    $TotalPass++
}

# V-239260: The ESXi host must verify the exception users list for Lockdown Mode.

# V-239261: Remote logging for ESXi hosts must be configured.
$result = Assert-SettingExists -StigId "V-239261" -VmHost $VmHost -Name "Syslog.global.logHost"
$TotalChecks++
if ($result) {
    $TotalPass++
}

# V-239262: The ESXi host must enforce the limit of three consecutive invalid logon attempts by a user.
$result = Assert-AdvancedSetting -StigId "V-239262" -VmHost $VmHost -Name "Security.AccountLockFailures" -ExpectedOutput 3
$TotalChecks++
if ($result) {
    $TotalPass++
}

# V-239263: The ESXi host must enforce the unlock timeout of 15 minutes after a user account is locked out.
$result = Assert-AdvancedSetting -StigId "V-239263" -VmHost $VmHost -Name "Security.AccountUnlockTime" -ExpectedOutput 900
$TotalChecks++
if ($result) {
    $TotalPass++
}

# V-239264: The ESXi host must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system via the DCUI.
$result = Assert-AdvancedSetting -StigId "V-239264" -VmHost $VmHost -Name "Annotations.WelcomeMessage" -ExpectedOutput "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests- -not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
$TotalChecks++
if ($result) {
    $TotalPass++
}

# V-239265: The ESXi host must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system via SSH.
$result = Assert-AdvancedSetting -StigId "V-239265" -VmHost $VmHost -Name "Config.Etc.issue" -ExpectedOutput "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. -At any time, the USG may inspect and seize data stored on this IS. -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
$TotalChecks++
if ($result) {
    $TotalPass++
}

# V-239266: The ESXi host SSH daemon must be configured with the DoD logon banner.
# Must ssh to system to check

# V-239267: The ESXi host SSH daemon must use DoD-approved encryption to protect the confidentiality of remote access sessions.
$TotalChecks++
$esxcli = Get-EsxCli -V2
if ($true -ne $esxcli.system.security.fips140.ssh.get.invoke()) {
    Write-Host -ForegroundColor Red "V-239267 : FAIL"
} else {
    Write-Host -ForegroundColor Green "V-239267 : PASS"
    $TotalPass++
}

# V-239268: The ESXi host SSH daemon must ignore .rhosts files.

# V-239269: The ESXi host SSH daemon must not allow host-based authentication.

# V-239270: The ESXi host SSH daemon must not permit root logins.

# V-239271: The ESXi host SSH daemon must not allow authentication using an empty password.

# V-239272: The ESXi host SSH daemon must not permit user environment settings.

# V-239273: The ESXi host SSH daemon must not permit GSSAPI authentication.

# V-239274: The ESXi host SSH daemon must not permit Kerberos authentication.

# V-239275: The ESXi host SSH daemon must perform strict mode checking of home directory configuration files.

# V-239276: The ESXi host SSH daemon must not allow compression or must only allow compression after successful authentication.

# V-239277: The ESXi host SSH daemon must be configured to not allow gateway ports.

# V-239278: The ESXi host SSH daemon must be configured to not allow X11 forwarding.

# V-239279: The ESXi host SSH daemon must not accept environment variables from the client.

# V-239280: The ESXi host SSH daemon must not permit tunnels.

# V-239281: The ESXi host SSH daemon must set a timeout count on idle sessions.

# V-239282: The ESXi host SSH daemon must set a timeout interval on idle sessions.

# V-239283: The ESXi host SSH daemon must limit connections to a single session.

# V-239284: The ESXi host must remove keys from the SSH authorized_keys file.

# V-239285: The ESXi host must produce audit records containing information to establish what type of events occurred.
$result = Assert-AdvancedSetting -StigId "V-239285" -VmHost $VmHost -Name "Config.HostAgent.log.level" -ExpectedOutput "info"
$TotalChecks++
if ($result) {
    $TotalPass++
}

# V-239286: The ESXi host must enforce password complexity by requiring that at least one uppercase character be used.
$result = Assert-AdvancedSetting -StigId "V-239286" -VmHost $VmHost -Name "Security.PasswordQualityControl" -ExpectedOutput "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"
$TotalChecks++
if ($result) {
    $TotalPass++
}

# V-239287: The ESXi host must prohibit the reuse of passwords within five iterations.
$result = Assert-AdvancedSetting -StigId "V-239287" -VmHost $VmHost -Name "Security.PasswordHistory" -ExpectedOutput 5
$TotalChecks++
if ($result) {
    $TotalPass++
}

# V-239288: The password hashes stored on the ESXi host must have been generated using a FIPS 140-2 approved cryptographic hashing algorithm.

# V-239289: The ESXi host must disable the Managed Object Browser (MOB).
$result = Assert-AdvancedSetting -StigId "V-239289" -VmHost $VmHost -Name "Config.HostAgent.plugins.solo.enableMob" -ExpectedOutput $false
$TotalChecks++
if ($result) {
    $TotalPass++
}

# This is needed for the next 2 checks
$HostServices = Get-VMHostService -VMHost $VmHost

# V-239290: The ESXi host must be configured to disable nonessential capabilities by disabling SSH.
$TotalChecks++
$SSHService = $HostServices | Where-Object { $_.Key -eq "TSM-SSH" }
if ($true -eq $SSHService.Running -or "on" -eq $SSHService.Policy ) {
    Write-Host -ForegroundColor Red "V-239290 : FAIL"
} else {
    Write-Host -ForegroundColor Green "V-239290 : PASS"
    $TotalPass++
}

# V-239291: The ESXi host must disable ESXi Shell unless needed for diagnostics or troubleshooting.
$TotalChecks++
$ESXIService = $HostServices | Where-Object { $_.Key -eq "TSM" }
if ($true -eq $ESXIService.Running -or "on" -eq $ESXIService.Policy ) {
    Write-Host -ForegroundColor Red "V-239291 : FAIL"
} else {
    Write-Host -ForegroundColor Green "V-239291 : PASS"
    $TotalPass++
}

# V-239292: The ESXi host must use Active Directory for local user authentication.
$TotalChecks++
$HostAuthSvc = Get-VMHostAuthentication -VMHost $VmHost
if ($null -eq $HostAuthSvc.DomainMembershipStatus -or "Ok" -ne $HostAuthSvc.DomainMembershipStatus) {
    Write-Host -ForegroundColor Red "V-239292 : FAIL"
} else {
    Write-Host -ForegroundColor Green "V-239292 : PASS (" $HostAuthSvc.Domain ")"
    $TotalPass++
}

# V-239293: ESXi hosts using Host Profiles and/or Auto Deploy must use the vSphere Authentication Proxy to protect passwords when adding themselves to Active Directory.


# V-239294: Active Directory ESX Admin group membership must not be used when adding ESXi hosts to Active Directory.
$result = Assert-AdvancedSetting -StigId "V-239294" -VmHost $VmHost -Name "Config.HostAgent.plugins.hostsvc.esxAdminsGroup" -ExpectedOutput "ESX Admins" -NotExpected:$true
$TotalChecks++
if ($result) {
    $TotalPass++
}

# V-239295: The ESXi host must use multifactor authentication for local DCUI access to privileged accounts.

# V-239296: The ESXi host must set a timeout to automatically disable idle shell sessions after two minutes.
$result = Assert-AdvancedSetting -StigId "V-239296" -VmHost $VmHost -Name "UserVars.ESXiShellInteractiveTimeOut" -ExpectedOutput 120
$TotalChecks++
if ($result) {
    $TotalPass++
}

# V-239297: The ESXi host must terminate shell services after 10 minutes.
$result = Assert-AdvancedSetting -StigId "V-239297" -VmHost $VmHost -Name "UserVars.ESXiShellTimeOut" -ExpectedOutput 600
$TotalChecks++
if ($result) {
    $TotalPass++
}

# V-239298: The ESXi host must log out of the console UI after two minutes.
$result = Assert-AdvancedSetting -StigId "V-239298" -VmHost $VmHost -Name "UserVars.DcuiTimeOut" -ExpectedOutput 120
$TotalChecks++
if ($result) {
    $TotalPass++
}

# V-239299: The ESXi host must enable kernel core dumps.

# V-239300: The ESXi host must enable a persistent log location for all locally stored logs.
#$esxcli = Get-EsxCli -V2
$TotalChecks++
$LogLocSetting = $esxcli.system.syslog.config.get.Invoke() | Select LocalLogOutput,LocalLogOutputIsPersistent
if ($true -ne $LogLocSetting.LocalLogOutputIsPersistent) {
    Write-Host -ForegroundColor Red "V-239300 : FAIL"
} else {
    Write-Host -ForegroundColor Green "V-239300 : PASS (" $LogLocSetting.LocalLogOutput ")"
    $TotalPass++
}

Write-Host -ForegroundColor Yellow "Audit of ESXi Host Complete"
Get-ComplianceScore -TotalChecks $TotalChecks -TotalPassed $TotalPass

Disconnect-VIServer -Server $Server -Confirm:$false
