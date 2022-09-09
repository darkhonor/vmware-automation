<# 
 # VMware VM STIG Lockdown Script
 # Author: Alex Ackerman
 # Last Update: 3 Feb 2020
 # 
 # Applies the DISA STIG setting values to a Virtual Machine hosted in a vCenter instance.
 #
 # Requires the VMware PowerCLI modules to be installed:
 #
 #   Install-Module -Name VMware.PowerCLI -AllowClobber
 #>
# Script Variables
$VIServer = "vcenter.domain.local"
$VMName = "someVM"
$3DEnabled = $false

# Connect to the vCenter
Connect-VIServer -Server $VIServer  

# Execute Lockdown Commands
Get-VM $VMName | New-AdvancedSetting -Name isolation.tools.copy.disable -Value true -Force -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name isolation.tools.dnd.disable -Value true -Force -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name isolation.tools.setGUIOptions.enable -Value false -Force -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name isolation.tools.paste.disable -Value true -Force -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name isolation.tools.diskShrink.disable -Value true -Force -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name isolation.tools.diskWiper.disable -Value true -Force -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name isolation.tools.hgfsServerSet.disable -Value true -Force -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name isolation.tools.ghi.autologon.disable -Value true -Force -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name isolation.tools.ghi.launchmenu.change -Value true -Force -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name isolation.tools.memSchedFakeSampleStats.disable -Value true -Force -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name isolation.tools.ghi.protocolhandler.info.disable -Value true -Force -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name isolation.ghi.host.shellAction.disable -Value true -Force -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name isolation.tools.ghi.trayicon.disable -Value true -Force -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name isolation.tools.unity.disable -Value true -Force -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name isolation.tools.unityInterlockOperation.disable -Value true -Force -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name isolation.tools.unity.push.update.disable -Value true -Force -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name isolation.tools.unity.taskbar.disable -Value true -Force -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name isolation.tools.unityActive.disable -Value true -Force -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name isolation.tools.unity.windowContents.disable -Value true -Force -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name isolation.tools.vmxDnDVersionGet.disable -Value true -Force -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name isolation.tools.guestDnDVersionSet.disable -Value true -Force -Confirm:$false
Get-VM $VMName | Get-CDDrive | Set-CDDrive -NoMedia -Confirm:$false
Get-VM $VMName | Get-USBDevice | Remove-USBDevice -Confirm:$false
Get-VM $VMName | Get-AdvancedSetting -Name RemoteDisplay.maxConnections | Set-AdvancedSetting -Value 1 -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name RemoteDisplay.vnc.enabled -Value false -Force -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name tools.setinfo.sizeLimit -Value 1048576 -Force -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name isolation.device.connectable.disable -Value true -Force -Confirm:$false
Get-VM $VMName | New-AdvancedSetting -Name tools.guestlib.enableHostInfo -Value false -Force -Confirm:$false
Get-VM $VMName | Get-AdvancedSetting -Name sched.mem.pshare.salt | Remove-AdvancedSetting -Confirm:$false
Get-VM $VMName | Get-AdvancedSetting -Name tools.guest.desktop.autolock | Set-AdvancedSetting -Value true -Confirm:$false
# Only on Non-3D enabled VMs
if (!$3DEnabled) 
{
    Get-VM $VMName | New-AdvancedSetting -Name mks.enable3d -Value false -Force -Confirm:$false
} 
# End 3D hardening

# Disconnect from the vCenter Server
Disconnect-VIServer -Confirm:$false