#  Copyright (c) EVRY AS. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

Set-StrictMode -Version Latest

Function Test-nADUser {
    <#
	.SYNOPSIS
        Test validation for Active Directory Users

    .DESCRIPTION
        Test validation for Active Directory Users

    .PARAMETER Users
        Active Directory users

    .PARAMETER ShowLog
        Explanation.

	.PARAMETER LPP
        Explanation.

    .EXAMPLE
		Test-nADUser -Users AS88880 -ShowLog

		Result
		-----------
		[20130402 09:04:27] # Entering Test-nADUser
		[20130402 09:04:27] ## Processing user: AS88880
		[20130402 09:04:28] # Exiting Test-nADUser
		True

		Description
		-----------
		The Description..

	.EXAMPLE
		Get-nADUser -User AS88880,AS88881Not | Test-nADUser

		Result
		-----------
		False

		Description
		-----------
		The Description..

	.OUTPUTS
		Test-nADUser

	.NOTES
        Name         : Test-nADUser
	    Module       : PSMS
        Author       : Woodworth Wilson
        Changed Log  : 2013-04-XX; 1.0; Woodworth.Wilson@evry.com; Initial Version
	                 : 2013-04-XY; 1.1; Woodworth.Wilson@evry.com; Added section for ..

    .LINK

#>
    [CmdletBinding()]
    param(
        [Alias("User", "InputObject")]
        [Parameter(Mandatory = $True, HelpMessage = "The user", ValueFromPipeline = $True)]
        [string[]] $Users,
        [string] $LPP = "#"
    )
    BEGIN {
        if (!$__nPSMS.Settings.IsADLoaded) {Initialize-nAD -LPP $LPP}

        Write-Verbose -Message "$LPP Entering $($MyInvocation.MyCommand)"

        $IsTest = $True
    }
    PROCESS {
        try {
            ForEach ($User in $Users) {
                try {
                    $User = $User.__UserName
                }
                catch [Exception] {}
                Write-Verbose -Message "$LPP# Processing user: $User"
                try {
                    $oUser = Get-ADUser -Identity $User -Properties *
                }
                catch [Exception] {
                    Err -Exception $_
                    $IsTest = $False
                    continue
                }
                $oUser2 = [ADSI]("LDAP://" + $oUser.DistinguishedName)
                $PlaceName = $oUser.State

                $ProfilePath = $oUser.ProfilePath
                if (-not [String]::IsNullOrEmpty($ProfilePath)) {
                    Write-Verbose -Message "$LPP## Invalid ProfilePath '$ProfilePath' for user. Should be empty"
                    $IsTest = $False
                }

                try {$TSProfilePath = $oUser2.psbase.InvokeGet("terminalservicesprofilepath")} catch {$TSProfilePath = ""}
                if ([String]::IsNullOrEmpty($TSProfilePath)) {
                    Write-Verbose -Message "$LPP## Unconfigured TSProfilePath for user. Should be \\clustershare\$User"
                    $IsTest = $False
                }
                try {
                    if ($oUser2.psbase.InvokeGet("AllowLogon") -ne 1) {
                        Write-Verbose -Message "$LPP## Invalid TSAllowLogon for user. Should be Enabled (checked)"
                        $IsTest = $False
                    }
                }
                catch {}

                $HomeDirectory = $oUser.HomeDirectory
                if ([String]::IsNullOrEmpty($HomeDirectory)) {
                    Write-Verbose -Message "$LPP## Unconfigured HomeDirectory for user. Should be \\clustershare\$User or $DFSHomePath\$PlaceName\$User"
                    $IsTest = $False
                }
                elseif ($PlaceName -notmatch "NedreSkoyenVei" -and $HomeDirectory -notmatch ("$DFSHomePath\$PlaceName" -replace "\\", "\\")) {
                    Write-Verbose -Message "$LPP## Invalid configured HomeDirectory for user. Should be $DFSHomePath\$PlaceName\$User"
                    $IsTest = $False
                }

                $Department = $oUser.Department
                if ($oUser.Department -eq $Null) {
                    $DeptDN = "N/A"
                }
                else {
                    $DeptDN = (Get-ADGroup -Identity $Department).DistinguishedName
                }
                $IsMemberOfDepartment = $oUser.MemberOf.Contains($DeptDN)
                if ([String]::IsNullOrEmpty($Department)) {
                    Write-Verbose -Message "$LPP## Unconfigured Department for user. Should be NNNN"
                    $IsTest = $False
                }
                elseif (!$IsMemberOfDepartment) {
                    Write-Verbose -Message "$LPP## Missing Department MemberOf for user. Must add member be $__userdomain\$Department"
                    $IsTest = $False
                }

                if ([String]::IsNullOrEmpty($PlaceName)) {
                    Write-Verbose -Message "$LPP## Unconfigured PlaceName for user. Should be f.ex NedreSkoyenVei"
                    $IsTest = $False
                }
                elseif (-not (Test-Path -Path "$DFSDeptApps\$PlaceName")) {
                    Write-Verbose -Message "$LPP## Invalid PlaceName '$PlaceName' for user. Must create $DFSDeptApps\$PlaceName"
                    $IsTest = $False
                }

                $ScriptPath = $oUser.ScriptPath
                if ([String]::IsNullOrEmpty($ScriptPath)) {
                    Write-Verbose -Message "$LPP## Unconfigured ScriptPath for user. Should be $ScriptPathStd"
                    $IsTest = $False
                }
                elseif ($ScriptPathStd -ne $ScriptPath) {
                    Write-Verbose -Message "$LPP## Invalid ScriptPath '$ScriptPath' for user. Should be $ScriptPathStd"
                    $IsTest = $False
                }

                $HomeDrive = $oUser.HomeDrive
                if ([String]::IsNullOrEmpty($HomeDrive)) {
                    Write-Verbose -Message "$LPP## Unconfigured HomeDrive for user. Should be $HomeDriveStd"
                    $IsTest = $False
                }
                elseif ($HomeDriveStd -ne $HomeDrive) {
                    Write-Verbose -Message "$LPP## Invalid HomeDrive '$HomeDrive' for user. Should be $HomeDriveStd"
                    $IsTest = $False
                }
            }
        }
        catch [Exception] {
            Write-Error -Exception $_.Exception
        }
    }
    END {
        Write-Verbose -Message "$LPP Exiting $($MyInvocation.MyCommand)"
        return $IsTest
    }
} # End Test-nADUser