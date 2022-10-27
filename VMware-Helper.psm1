##
# VMware-Helper.psm1
# 
# This is a series of PowerShell Functions that are developed to assist the management of Virtual Machines
#
# Author: Alex Ackerman
# Last Modified: 26 Oct 2022
##
<#
.SYNOPSIS
Parse the provided File into a Dictionary

.DESCRIPTION
This will parse a File object into a Dictionary object

.PARAMETER file
This is the INI file containing settings that will be parsed into an Dictionary

.EXAMPLE
ImportIni($iniFile)

.NOTES
This function was copied from the UAG Deploy scripts provided by VMware
#>
function ImportIni {
    param ($file)

    $ini = @{}
    switch -regex -file $file {
        "^\s*#" {
            continue
        }
        "^\[(.+)\]$" {
            $section = $matches[1]
            $ini[$section] = @{}
        }
        "([A-Za-z0-9#_]+)=(.+)" {
            $name, $value = $matches[1..2]
            $ini[$section][$name] = $value.Trim()
        }
    }
    $ini
}

# Function: Get-Hv-MapEntry
# Description: Creates a new VMware.Hv.MapEntry object with the specified Key and Value
# Source: https://github.com/vmware/PowerCLI-Example-Scripts/tree/master/Modules/VMware.Hv.Helper
function Get-HvMapEntry {
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

<#
.SYNOPSIS
Apply the current DISA STIG settings to a Virtual Machine

.DESCRIPTION
This function will apply the required STIG Settings for a Virtual Machine entity
using the referenced DISA STIG

.PARAMETER Vm
The VirtualMachine reference to apply the STIG Settings

.EXAMPLE
STIGLockdown($myVm)

.NOTES
Reference: VMware vSphere 6.7 Virtual Machine Security Technical Implementation Guide
             Version 1, Release: 2 Benchmark Date: 08 Feb 2022
#>
function STIGLockdown {
    param([VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$Vm)

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

function Get-VMTag {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $false)]
        [string]$Category = "Operating System"
    )
  
    $tag = Get-Tag -Name $Name
    if ($null -eq $tag) {
        $tagcat = Get-TagCategory -Name $Category
        $tag = New-Tag -Category $tagcat -Name $Name
    }

    return $tag
}

function Assert-AdvancedSetting {
    Param(
        [string]$StigId,
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VMHost]$VmHost, 
        [string]$Name,
        [System.Object]$ExpectedOutput,
        [bool]$NotExpected = $false
    )
    # Place some stuff here....
    $setting = Get-AdvancedSetting -Entity $VmHost -Name $Name
    if ($NotExpected) {
        if ($ExpectedOutput -eq $setting.Value) {
            Write-Host -ForegroundColor Red "$StigId : FAIL"
            return $false
        }
        else {
            Write-Host -ForegroundColor Green "$StigId : PASS (" $setting.Value ")"
            return $true
        } 
    }
    else {
        if ($ExpectedOutput -ne $setting.Value) {
            Write-Host -ForegroundColor Red "$StigId : FAIL"
            return $false
        }
        else {
            Write-Host -ForegroundColor Green "$StigId : PASS"
            return $true
        }
    }
}

function Assert-SettingExists {
    Param(
        [string]$StigId,
        [VMware.VimAutomation.ViCore.Types.V1.Inventory.VMHost]$VmHost, 
        [string]$Name
    )
    # Place some stuff here....
    $setting = Get-AdvancedSetting -Entity $VmHost -Name $Name
    if ($null -eq $setting.Value) {
        Write-Host -ForegroundColor Red "$StigId : FAIL"
        return $false
    }
    else {
        Write-Host -ForegroundColor Green "$StigId : PASS (" $setting.Value ")"
        return $true
    }
}

function Get-ComplianceScore {
    Param(
        [int]$TotalChecks,
        [int]$TotalPassed
    )
    Write-Host -ForegroundColor White -NoNewline "Total STIG Settings Checked:" 
    Write-Host -ForegroundColor Yellow $TotalChecks
    Write-Host -ForegroundColor White -NoNewline "Total STIG Settings Passed:"
    Write-Host -ForegroundColor Green $TotalPassed
    $score = $TotalPassed / $TotalChecks
    Write-Host -ForegroundColor White -NoNewline "Compliance Score: "
    if ($score -le 0.750) {
        Write-Host -ForegroundColor Red $score.ToString("P") " (FAIL)"
    } elseif ($score -le 0.900) {
        Write-Host -ForegroundColor Yellow $score.ToString("P") " (CONDITIONAL PASS)"
    } else {
        Write-Host -ForegroundColor Green $score.ToString("P") " (PASS)"
    }
}