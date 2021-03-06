#  Copyright (c) nOsliw Solutions. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

Function Get-nCSServiceAccounts {
    <#
	.SYNOPSIS
        Get system service accounts from the local Administrators group

    .DESCRIPTION
        Get system service accounts from the local Administrators group

    .PARAMETER SystemName
        Describes the system names(s)
		Default is localhost

	.PARAMETER LocalGroup
        Describes the local group to verify
		Default. Administrators

	.PARAMETER LPP
		Log progess prefix. Default is '#'

    .EXAMPLE
		Get-nCSServiceAccounts

		Result
		-----------
		...

		Description
		-----------
		The Description..

	.EXAMPLE
		Get-nCSServiceAccounts -ParamName "server1" -SwitchName

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
        [Alias('DnsHostName', '__SERVER', 'IPAddress', 'Computer', 'ComputerName', 'System')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [string[]] $SystemName = @($env:COMPUTERNAME),

        [string] $LocalGroup = "Administrators",

        [string] $LPP = "#"
    )
    BEGIN {
        if (!$__nPSMS.Settings.IsCSLoaded) {Initialize-nCS}

        $Headers = @("Domain", "SystemName", "LocalGroup", "Account", "IsAccountLocal")
        $SystemName = $SystemName | Sort-Object -Unique
    }
    PROCESS {
        try {
            Get-nCSLocalGroupMembership -SystemName $SystemName -GroupName $LocalGroup -Verbose -LPP "$LPP#" `
                | Where-Object {$_.Class -eq "User" -and $_.Account -notmatch "Administrator|Guest|ScheduledUser|Support_"} `
                | ForEach-Object `
                -Process {
                Write-Verbose -Message "$LPP## Processing account=$($_.Account) on system=$($_.computer)"
                $object = New-Object -TypeName PSObject -Property @{
                    Domain         = $Env:USERDOMAIN
                    SystemName     = $_.Computer
                    Localgroup     = $LocalGroup
                    Account        = $_.Account
                    IsAccountLocal = $_.Type -match "local"
                }

                $object | Select-Object -Property $Headers
            }
        }
        catch [Exception] {
            Write-Error -Exception $_
        }
    }
    END {
        Write-Verbose -Message "$LPP Exiting $($MyInvocation.MyCommand)"
    }
} # End Get-nCSServiceAccounts