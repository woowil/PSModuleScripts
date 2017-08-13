#  Copyright (c) EVRY AS. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

Function Remove-nADUser {
    <#
	.SYNOPSIS
        Customized Active Directory user account change with spesific properties

    .DESCRIPTION
        AD User Information with extended properties for platform
        This cmdlet depends on and extends the ActiveDirectory Module, cmdlet Get-ADUser

    .PARAMETER Users
        Specifies the SamAccountName user names.
		This is the only parameter that enables to enter an PSObject array  of user from pipeline

    .PARAMETER Department
        Specifies the a SamAccountName user file list.
		File lines with ";" are ignored

	.PARAMETER HomeDirectory
        Specifies the destination Home Directory property of the users account(s).

    .PARAMETER PlaceName
        Specifies the destination State property of the users account(s).

	.PARAMETER TSProfilePath
        Specifies the destination Terminal Services Profile Path  property of the users account(s).

	.PARAMETER IsFromSAM
        Specifies if the user account(s) is from SAM Jupiter

	.PARAMETER ShowLog
        Shows the progress message log.

	.PARAMETER LPP
        Specifies the prefix used in message log. Default is '#'

    .EXAMPLE
		Get-dSAMUser | Remove-nADUser -ShowLog -Department 8888

		Result
		-----------
		...

		Description
		-----------
		The Description..

	.EXAMPLE
		Get-nADUser AS88880 | Remove-nADUser -ShowLog -Department 8888
		cls;Get-nADUser -Filter {Name -like "ATDSUM*"}  | Remove-nADUser -ShowLog

		Result
		-----------
		...

		Description
		-----------
		The Description..

	.EXAMPLE
		"AS88880","AS88881" | Remove-nADUser -ShowLog -Department 8888 -Verbose

		Result
		-----------
		...

		Description
		-----------
		The Description..

    .EXAMPLE
		Remove-nADUser -Users AS88880,AS88882 -Department 8888

		Result
		-----------
		...

		Description
		-----------
		The Description..

	.OUTPUTS

    .LINK
        Get-dSAMUser
		Get-nADUser

	#>
    [CmdletBinding()]
    param(
        [Alias("User", "InputObject")]
        [Parameter(Mandatory = $True, HelpMessage = "The user", ValueFromPipeline = $True)]
        [PSCustomObject[]] $Users = $null,
        [switch] $IsFromSAM,
        [switch] $Force,
        [switch] $ShowLog,
        [string] $LPP = "#"
    )
    BEGIN {
        if (!$__nPSMS.Settings.IsADLoaded) {Initialize-nAD -LPP $LPP}

        Write-Verbose -Message "$LPP Entering $($MyInvocation.MyCommand)"
        $len = 0
        if (-not (Test-Path -Path Variable:\Users)) {
            $isValueFromPipeline = $False
            # Write-Verbose -Message "$LPP# Processing user instances"
        }
        else {
            $isValueFromPipeline = $True
            $len = $Users.Length
            # Write-Verbose -Message "$LPP# Processing $($Users.Length) user instances"
        }
    }
    PROCESS {
        try {
            Write-Verbose -Message "$LPP# Processing $len users"
            ForEach ($User in $Users) {
                try {
                    $User = $User.__UserName
                }
                catch [Exception] {}
                Write-Verbose -Message "$LPP## Getting Active Directory user: $User"
                try {
                    $oUser = Get-ADUser -Identity $User -Properties HomeDirectory, Department
                }
                catch [Exception] {
                    Write-Verbose -Message "$LPP### Unable to find user identity: '$User' in Active Directory"
                    continue
                }
                $HomeDirectory = $oUser.HomeDirectory
                if (-not [String]::IsNullOrEmpty($HomeDirectory) -and (Test-Path -Path $HomeDirectory -PathType Container)) {
                    Write-Verbose -Message "$LPP### Remove-nADUser - Won't remove user account as HomeDirectory=$HomeDirectory exist. Solution: Run Remove-eFSUser -User $User"
                    Start-Sleep -Seconds 4
                    continue
                }
                if ($IsFromSAM) {
                    #$oUser.Description = "SAM Jupiter inmelding"
                }

                Write-Verbose -Message "$LPP### Removing user account: $User"
                Remove-ADUser -Identity $User -Verbose -Confirm:$Confirm
            }
        }
        catch [Exception] {
            Write-Error -Exception $_
        }
    }
    END {
        Write-Verbose -Message "$LPP Exiting $($MyInvocation.MyCommand)"
    }
} # End Remove-nADUser

