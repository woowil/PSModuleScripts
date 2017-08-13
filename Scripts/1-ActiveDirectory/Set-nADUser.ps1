#  Copyright (c) nOsliw Solutions. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

Function Set-nADUser {
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

    .PARAMETER State
        Specifies the destination State property of the users account(s).

	.PARAMETER TSProfilePath
        Specifies the destination Terminal Services Profile Path  property of the users account(s).

	.PARAMETER IsFromSAM
        Specifies if the user account(s) is from SAM Jupiter

	.PARAMETER LPP
        Specifies the prefix used in message log. Default is '#'

    .EXAMPLE
		Get-eFromSAMDat | Set-nADUser -ShowLog -Department 8888

		Result
		-----------
		...

		Description
		-----------
		The Description..

	.EXAMPLE
		Get-nADUser AS88880 | Set-nADUser -ShowLog -Department 8888

		Result
		-----------
		...

		Description
		-----------
		The Description..

	.EXAMPLE
		"AS88880","AS88881" | Set-nADUser -ShowLog -Department 8888 -Verbose

		Result
		-----------
		...

		Description
		-----------
		The Description..

    .EXAMPLE
		Set-nADUser -Users AS88880,AS88882 -Department 8888

		Result
		-----------
		...

		Description
		-----------
		The Description..

	.OUTPUTS
    .LINK
        Get-nADUser

	#>

    [CmdletBinding()]
    param(
        [Alias("User", "InputObject")]
        [Parameter(Mandatory = $True, HelpMessage = "The user", ValueFromPipeline = $True)]
        [PSCustomObject[]] $Users = $null,

        [Alias("Dept")]
        [string] $Department,

        #[ValidateScript({Test-Path -Path $_ -PathType Container})]
        [Alias("Home")]
        [string] $HomeDirectory,

        [Alias("Script")]
        [string] $ScriptPath,

        [Alias("State", "st", "Place")]
        [string] $State,

        [Alias("TSProf")]
        [string] $TSProfilePath,

        [switch] $IsFromSAM,
        [switch] $Force,
        [switch] $ShowLog,
        [string] $LPP = "#"
    )
    BEGIN {
        if (!$__nPSMS.Settings.IsADLoaded) {Initialize-nAD -LPP $LPP}

        Write-Verbose -Message "$LPP Entering $($MyInvocation.MyCommand)"

        if (-not (Test-Path -Path Variable:\Users)) {
            $isValueFromPipeline = $False
            Write-Verbose -Message "$LPP# Processing user instances"
        }
        else {
            $isValueFromPipeline = $True
            Write-Verbose -Message "$LPP# Processing $($Users.Length) user instances"
        }
        if (!($State -or $Department -or $HomeDirectory -or $TSProfilePath)) {
            Write-Verbose -Message "$LPP## WARNING: None of the required properties were entered. Exiting"
            break;
        }
    }
    PROCESS {
        try {
            ForEach ($User in $Users) {
                try {
                    $User = $User.__UserName
                }
                catch [Exception] {}
                Write-Verbose -Message "$LPP## Getting Active Directory object on user: $User"
                $oUser = Get-ADUser -Identity $User -Properties State, Department, HomeDirectory, Description, ProfilePath, DistinguishedName, ScriptPath
                $oUser.ProfilePath = $Null
                $str = ""
                if ($Department) {
                    $oUser.Department = $Department
                    $str = [string]::Concat($str, ",Department=$Department")
                    if (-not $__nPSMS.__IsMemberOf($Department, $User)) {
                        Write-Verbose -Message "$LPP### Adding user $__userdomain\$User to group $__userdomain\$Department"
                        Get-ADGroup -Identity $Department | Add-ADGroupMember -Members $User -ErrorAction "SilentlyContinue"
                    }
                    else {
                        Write-Verbose -Message "$LPP### Skipping already added $__userdomain\$User in group $__userdomain\$Department"
                    }
                }
                if ($HomeDirectory) {
                    $tmpOK = $False
                    if ($oUser.HomeDirectory -ne $HomeDirectory) {
                        $tmpOK = $True
                    }
                    if ($Force -or $tmpOK) {
                        $oUser.HomeDirectory = $HomeDirectory
                        $str = [string]::Concat($str, ", HomeDirectory=$HomeDirectory")
                    }
                }
                if ($ScriptPath) {
                    $tmpOK = $False
                    if ($ScriptPath -match "\.bat|\.cmd") {
                        if ($oUser.ScriptPath -ne $ScriptPath) {
                            $tmpOK = $True
                        }
                    }
                    if ($Force -or $tmpOK) {
                        $oUser.ScriptPath = $ScriptPath
                        $str = [string]::Concat($str, ", ScriptPath=$ScriptPath")
                    }
                }
                if ($TSProfilePath) {
                    $oUser2 = [ADSI]("LDAP://" + $oUser.DistinguishedName)
                    try {$tmp = $oUser2.psbase.InvokeGet("terminalservicesprofilepath")} catch {$tmp = ""}
                    $tmpOK = $False
                    if ([String]::IsNullOrEmpty($tmp) -or !(Test-Path -Path "$tmp.V2" -PathType Container)) {
                        $tmpOK = $True
                    }
                    if ($Force -or $tmpOK) {
                        Write-Verbose -Message "$LPP### Setting TSProfilePath=$TSProfilePath on user $User"
                        $oUser2.psbase.InvokeSet("terminalservicesprofilepath", $TSProfilePath)
                        $oUser2.SetInfo()
                    }
                    else {
                        Write-Verbose -Message "$LPP### Skipping already defined TSProfilePath=$TSProfilePath"
                    }
                }
                if ($State) {
                    $str = [string]::Concat($str, ", State=$State")
                    $oUser.State = $State
                }
                if ($IsFromSAM) {
                    #$oUser.Description = "SAM Jupiter inmelding"
                }
                $str = $str -replace "^, "
                if ($str -eq "") {continue}

                Write-Verbose -Message "$LPP### Setting $str on user: $User"
                Set-ADUser -Instance $oUser
            }
        }
        catch [Exception] {
            Write-Error -Exception $_.Exception
        }
    }
    END {
        Write-Verbose -Message "$LPP Exiting $($MyInvocation.MyCommand)"
    }
} # End Set-nADUser

