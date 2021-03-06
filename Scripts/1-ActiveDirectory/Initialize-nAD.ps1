#  Copyright (c) nOsliw Solutions. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

Function Initialize-nAD {
    <#
	.SYNOPSIS
        Initializes Active Directory methods and properties

    .DESCRIPTION
        Initializes Active Directory methods and properties

	.PARAMETER Force
		Force Initialize even if its alr loaded

	.PARAMETER LPP
		Log progess prefix. Default is '#'

	.EXAMPLE
		Initialize-nAD

		Result
		-----------
		...

		Description
		-----------
		The Description..

	.OUTPUTS

    .LINK

	#>

    [CmdletBinding()]
    param(
        [switch] $Force,
        [string] $LPP = "#"
    )
    BEGIN {
        Write-Verbose -Message "$LPP Entering $($MyInvocation.MyCommand)"

        if ((Get-WmiObject -Class Win32_OperatingSystem).Version -match "^5|6.0") {
            Write-Verbose -Message "$LPP# Active Directory cmdlets is not supported on current system. The OS must be W2008R2/W7 or higher"
            break
        }
        if (-not (Get-Module | Select-String -Pattern "ActiveDirectory")) {
            if (-not (Get-Module -ListAvailable | Where-Object -FilterScript {$_.Name -eq "ActiveDirectory"})) {
                $msg = "Problem`n The ActiveDirectory Windows Feature tools are not installed in current system.`n`tThe ActiveDirectory module is required.`n`nSolution`n"
                $msg += " PS C:\> Import-Module -Name ServerManager -Force`n"
                $msg += " PS C:\> Add-WindowsFeature -Name RSAT-AD-Tools -IncludeAllSubFeature`n"
                $msg += " PS C:\> Import-Module -Name ActiveDirectory -Force"
                Write-Verbose -Message "$msg"
                Break
            }
            else {
                Write-Verbose -Message "$LPP# Loading required Active Directory module"
                Import-Module -Name ActiveDirectory -Global -Force
            }
        }
    }
    PROCESS {
        try {

            Add-Member -InputObject $__nPSMS -MemberType ScriptMethod -Name "__ADIsMemberOf" -Force -Value {
                param(
                    [string] $ADGlobalGroup,
                    [string] $ADUser
                )
                $oGroup = [ADSI] "WinNT://$__userdnsdomain/$ADGlobalGroup,group"
                # Note that the IsMember doesn't work properly with Domain Local Groups or nested Domain Global Groups
                return $oGroup.IsMember("WinNT://$__userdnsdomain/$ADUser")
            }

            $__nPSMS.Settings.IsADLoaded = $True
        }
        catch [Exception] {
            Write-Error -Exception $_.Exception
        }
    }
    END {
        Write-Verbose -Message "$LPP Exiting $($MyInvocation.MyCommand)"
    }
}
