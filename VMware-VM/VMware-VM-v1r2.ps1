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
$ViConnection = Connect-VIServer -Server $VIServer 

$VmBase = Get-VM -Name $VMName -Server $ViConnection

function STIGLockdown {
    param([VIObject[]]$Vm)

    # Execute Lockdown Commands
    # STIG V-239332: Copy operations must be disabled on the virtual machine
    New-AdvancedSetting -Entity $Vm -Name isolation.tools.copy.disable -Value true -Force -Confirm:$false

    # STIG V-239333: Drag and drop operations must be disabled on the virtual machine.
    New-AdvancedSetting -Entity $Vm -Name isolation.tools.dnd.disable -Value true -Force -Confirm:$false

    # STIG V-239334: Paste operations must be disabled on the virtual machine.
    New-AdvancedSetting -Entity $Vm -Name isolation.tools.paste.disable -Value true -Force -Confirm:$false

    # STIG V-239335: Virtual disk shrinking must be disabled on the virtual machine.
    New-AdvancedSetting -Entity $Vm -Name isolation.tools.diskShrink.disable -Value true -Force -Confirm:$false

    # STIG V-239336: Virtual disk erasure must be disabled on the virtual machine.
    New-AdvancedSetting -Entity $Vm -Name isolation.tools.diskWiper.disable -Value true -Force -Confirm:$false

    # STIG V-239338: HGFS file transfers must be disabled on the virtual machine.
    New-AdvancedSetting -Entity $Vm -Name isolation.tools.hgfsServerSet.disable -Value true -Force -Confirm:$false

    # STIG V-239339: Unauthorized floppy devices must be disconnected on the virtual machine.
    Get-FloppyDrive -VM $Vm | Remove-FloppyDrive -Confirm:$false

    # STIG V-239340: Unauthorized CD/DVD devices must be disconnected on the virtual machine.
    Get-CDDrive -VM $Vm | Set-CDDrive -NoMedia -Confirm:$false

    # STIG V-239343: Unauthorized USB devices must be disconnected on the virtual machine.
    Get-USBDevice -VM $Vm | Remove-USBDevice -Confirm:$false

    # STIG V-239344: Console connection sharing must be limited on the virtual machine.
    New-AdvancedSetting -Entity $Vm -Name RemoteDisplay.maxConnections -Value 1 -Confirm:$false

    # STIG V-239345: Console access through the VNC protocol must be disabled on the virtual machine.
    New-AdvancedSetting -Entity $Vm -Name RemoteDisplay.vnc.enabled -Value false -Force -Confirm:$false

    # STIG V-239346: Informational messages from the virtual machine to the VMX file must be limited on the virtual machine.
    New-AdvancedSetting -Entity $Vm -Name tools.setinfo.sizeLimit -Value 1048576 -Force -Confirm:$false

    # STIG V-239347: Unauthorized removal, connection and modification of devices must be prevented on the virtual machine.
    New-AdvancedSetting -Entity $Vm -Name isolation.device.connectable.disable -Value true -Force -Confirm:$false

    # STIG V-239348: The virtual machine must not be able to obtain host information from the hypervisor.
    New-AdvancedSetting -Entity $Vm -Name tools.guestlib.enableHostInfo -Value false -Force -Confirm:$false

    # STIG V-239349: Shared salt values must be disabled on the virtual machine.
    Get-AdvancedSetting -Entity $Vm -Name sched.mem.pshare.salt | Remove-AdvancedSetting -Confirm:$false

    # STIG V-239353: The virtual machine guest operating system must be locked when the last console connection is closed.
    New-AdvancedSetting -Entity $Vm -Name tools.guest.desktop.autolock -Value true -Confirm:$false

    # STIG V-239354: 3D features on the virtual machine must be disabled when not required.
    if (!$3DEnabled) {
        New-AdvancedSetting -Entity $Vm -Name mks.enable3d -Value false -Force -Confirm:$false
    } 
}

STIGLockdown($VmBase)

# Disconnect from the vCenter Server
Disconnect-VIServer -Server $ViConnection -Confirm:$false