#  Copyright (c) nOsliw Solutions. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

Function Get-nADUser {
    <#
	.SYNOPSIS
        Active Directory user information with spesific properties

    .DESCRIPTION
        AD User Information with extended properties for platform
        This cmdlet depends on and extends the ActiveDirectory Module, cmdlet Get-ADUser

    .PARAMETER Users
        Specifies SamAccountName user names

    .PARAMETER UserList
        Specifies a file of SamAccountName user names
		Note: File lines that start with ";" are ignored

	.PARAMETER UserMatch
		Specifies a regular expression string of SamAccountName user name
		Default is: .+

	.PARAMETER Groups
        Specifies the SamAccountName domain global group names

    .PARAMETER GroupList
        Specifies a file of SamAccountName domain global group names
		Note: File lines that start with ";" are ignored

	.PARAMETER OUs
		Specifies OU names container for SamAccountName names

	.PARAMETER Property
		Specifies a properties to detain
		Default is: *

	.PARAMETER ChangedAfter
		Specifies a datetime of comparing with SamAccountName object whenChanged
		Default is: 1970-01-01

	.PARAMETER ADObjectsOnly
		Filter out __* objects

	.PARAMETER ExtendedProperty
		Extra time consuming properties

	.PARAMETER LPP
		Log progess prefix. Default is '#'

    .EXAMPLE
		Get-nADUsers -Users AS88880,AS88882 -Groups 9999

		Result
		-----------
		...

		Description
		-----------
		The Description..

	.EXAMPLE
		Get-nADUser -UserList C:\temp\users.txt

		Result
		-----------
		...

		Description
		-----------
		The Description..

	.EXAMPLE
		Get-nADUser -Groups 9999

		Result
		-----------
		...

		Description
		-----------
		The Description..

    .EXAMPLE
		Get-nADUser -GroupList C:\temp\groups.txt

		Result
		-----------
		...

		Description
		-----------
		The Description..

	.EXAMPLE
		Get-nADUsers -Users username1,username2

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
        [string[]] $Users = @(),
        [string] $UserList,
        [string] $UserMatch = ".+",
        [string[]] $Groups,
        [string] $GroupList,
        [string[]] $OUs,
        [string[]] $Property = "*",
        #[string] $SearchBase = "OU=Customers,OU=SKALA,DC=mistral,DC=mistralnett,DC=com",
        [datetime] $ChangedAfter = (Get-Date -Year 1970 -Month 1 -Day 1),
        [switch] $ADObjectsOnly,
        [switch] $ExtendedProperty,

        [string] $LPP = "#"

    )
    BEGIN {
        if (!$__nPSMS.Settings.IsADLoaded) {Initialize-nAD -LPP $LPP}

        Write-Verbose -Message "$LPP Entering $($MyInvocation.MyCommand)"

        if ($GroupList) {
            Write-Verbose -Message "$LPP# Collecting users from group list=$GroupList"
            if (-not $Groups) {$Groups = @() }
            $Tmp = Get-Content -Path $GroupList -ReadCount 0
            $Groups += ($tmp | Select-String -Pattern ";.*" -AllMatches -notmatch)
        }
        if ($Groups -and $Groups.Count -gt 0) {
            forEach ($g in $Groups) {
                Write-Verbose -Message "$LPP# Collecting users from group=$g"
                Get-ADGroupMember -Identity $g |
                    Where-Object -FilterScript {
                    $_.objectClass -eq "user" -and `
                        $_.SamAccountName -match $UserMatch} |
                    ForEach-Object -Process { $Users += $_.SamAccountName }
            }
        }
        if ($OUs -and $OUs.Count -gt 0) {
            forEach ($ou in $OUs) {
                Write-Verbose -Message "$LPP# Collecting users from OU=$ou"
                Get-ADUser -Filter * -SearchBase $ou -ResultSetSize $null -SearchScope SubTree -ErrorAction SilentlyContinue |
                    Where-Object -FilterScript {$_.SamAccountName -match $UserMatch} | # -and $_.whenChanged -ge $ChangedAfter} |
                    ForEach-Object -Process { $Users += $_.SamAccountName}
            }
        }
        if ($UserList) {
            Write-Verbose -Message "$LPP# Collecting users from user list=$UserList"
            $tmp = Get-Content -Path $UserList -ReadCount 0
            $Users += ($tmp | Select-String -Pattern ";.*" -AllMatches -notmatch)
        }

        $len = ($Users | Measure-Object).Count
        $i = 1; $Found = 0
        if ($len -gt 0) {
            $Users = $Users -match "[^ \t]+" # removes empty cells
            $Users = $Users.Trim() | Sort-Object -Unique
            $len = $Users.Count
        }
        $TextInfo = (Get-Culture).TextInfo
        Write-Verbose -Message "$LPP# Using ChangedAfter=$ChangedAfter"

    }
    PROCESS {
        try {
            ForEach ($user in $Users) {
                if ($i -lt 2) { Write-Verbose -Message "$LPP# Processing $len users"}
                try {
                    $oUser = Get-ADUser -Identity $User -Properties * #-ErrorAction SilentlyContinue
                    if ($oUser.whenChanged -lt $ChangedAfter) {continue}
                    $Found++
                }
                catch [Exception] {
                    Write-Verbose -Message "$LPP## $($_.Exception.Message.Trim())"
                    continue
                }

                if ($ADObjectsOnly) {
                    Write-Output -InputObject ($oUser | Select-Object -Property $Property)
                    continue
                }

                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__Changed" -Value $oUser.whenChanged -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__City" -Value $oUser.City -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__Company" -Value $oUser.Company -Force
                $Country = $TextInfo.ToTitleCase(($oUser.co + "").ToLower())
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__Country" -Value $Country -Force # Capitalize
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__Created" -Value $oUser.whenCreated -Force

                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__Deleted" -Value $oUser.Deleted -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__Department" -Value $oUser.Department -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__DepartmentCode" -Value ($oUser.departmentNumber -join " ") -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__DepartmentNumber" -Value ($oUser.departmentNumber -join " ") -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__DepartmentText" -Value $oUser.Department -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__Description" -Value $oUser.Description -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__DisplayName" -Value $oUser.DisplayName -Force
                #Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__DirectReports" -Value $oUser.directReports -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__DistinguishedName" -Value $oUser.DistinguishedName -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__Division" -Value $oUser.Division -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__Domain" -Value $__userdomain -Force

                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__EmailAddress" -Value $oUser.mail -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__EmployeeType" -Value $oUser.employeeType -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__Enabled" -Value $oUser.Enabled -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__ExchangeId" -Value $oUser.mailNickname -Force

                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__FaxWork" -Value $oUser.Fax -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__FirstName" -Value $oUser.GivenName -Force

                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__GivenName" -Value $oUser.GivenName -Force

                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__HomeDirectory" -Value $oUser.HomeDirectory -Force
                if ($ExtendedProperty) {
                    $res = $False
                    if ($oUser.HomeDirectory -ne $Null) {
                        try { $res = Test-Path -Path $oUser.HomeDirectory -PathType Container -ErrorAction 0 }
                        catch {
                            Write-Verbose -Message "HomeDirectory access error for $__identity on path=$($oUser.HomeDirectory)"
                        }
                    }
                    Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__HomeDirExist" -Value $res -Force
                    $res = $Null
                    if ($oUser.__HomeDirExist) {
                        $res = (Get-Item -Path $oUser.HomeDirectory)
                        try {$res = ($res.GetAccessControl.Invoke()).Access}
                        catch {
                            Write-Verbose -Message "NTFS ACL Security access error for $__identity on path=$($oUser.HomeDirectory)"
                        }
                    }
                    Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__HomeDirAccess" -Value $res -Force
                }
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__HomeDrive" -Value $oUser.HomeDrive -Force

                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__IsAccountLocked"  -Value $oUser.LockedOut -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__IsAccountDisabled" -Value (-not $oUser.Enabled) -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__IsLockedOut" -Value $oUser.LockedOut -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__LastLogonDate" -Value $__nPSMS.__GetInt64Time($oUser.lastLogon) -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__LastName" -Value $oUser.sn -Force

                $ManagerDN = $oUser.Manager
                $ManagerUserID = $null
                $ManagerNumber = $null
                $ManagerName = $null
                if (![string]::IsNullOrEmpty($ManagerDN)) {
                    $tmp = [adsi]"LDAP://$ManagerDN"
                    $ManagerUserID = ($tmp.sAMAccountName).toString()
                    $ManagerNumber = ($tmp.telephoneNumber).toString()
                    $ManagerName = ($tmp.Name).toString()
                }
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__ManagerName" -Value $ManagerName -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__ManagerNumber" -Value $ManagerNumber -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__ManagerUserID" -Value $ManagerUserID -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__ManagerDN" -Value $ManagerDN -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__MobilePhone" -Value $oUser.mobile -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__Modified" -Value $oUser.Modified -Force

                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__Name" -Value ($oUser.GivenName + " " + $oUser.sn) -Force

                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__Office" -Value $oUser.Office -Force
                $physicalDeliveryOfficeName = $TextInfo.ToTitleCase(($oUser.physicalDeliveryOfficeName + "").ToLower())
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__OfficeName" -Value $physicalDeliveryOfficeName -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__OfficePhone" -Value $oUser.OfficePhone -Force

                #Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__PasswordExpired" -Value $__nPSMS.__GetInt64Time($oUser.accountExpires) -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__PasswordExpired" -Value $oUser.PasswordExpired -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__PasswordLastSet" -Value $__nPSMS.__GetInt64Time($oUser.pwdLastSet) -Force

                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__ProfilePath" -Value $oUser.ProfilePath -Force
                if ($ExtendedProperty) {
                    $res = $False
                    if ($oUser.ProfilePath -ne $Null) { $res = Test-Path -Path $oUser.ProfilePath -PathType Container -ErrorAction 0}
                    Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__ProfilePathExist" -Value $res -Force
                }
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__PostalCode" -Value $oUser.PostalCode -Force
                $PostPlace = $oUser.StreetAddress + ", " + $oUser.PostalCode + " " + $oUser.City
                $PostPlace = $PostPlace.Trim() -replace "[ \t]+", " " -replace "^[, \t]+"
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__PostPlace" -Value $PostPlace -Force

                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__RoomNumber" -Value ($oUser.roomNumber -join " ") -Force

                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__SamAccountName" -Value $oUser.SamAccountName -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__ScriptPath" -Value $oUser.ScriptPath -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__State" -Value $oUser.st -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__StreetAddress" -Value $oUser.StreetAddress -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__Surname" -Value $oUser.sn -Force

                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__TelephoneNumber" -Value $oUser.telephoneNumber -Force
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__Title" -Value $oUser.title -Force
                try {
                    $TSAllowLogon = $False
                    $oUser2 = [ADSI]("LDAP://" + $oUser.DistinguishedName)
                    if ($oUser2.psbase.InvokeGet("AllowLogon") -eq 1) {
                        $TSAllowLogon = $True
                    }
                }
                catch {}
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__TSAllowLogon" -Value $TSAllowLogon -Force

                try {$TSProfilePath = $oUser2.psbase.InvokeGet("terminalservicesprofilepath")} catch {$TSProfilePath = ""}
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__TSProfilePath" -Value $TSProfilePath -Force
                $tmp = $oUser.__TSProfilePath
                if ($ExtendedProperty) {
                    $res = $False
                    if ( (-not [String]::IsNullOrEmpty($tmp)) -and (Test-Path -Path $tmp -IsValid)) {
                        $res = Test-Path -Path $tmp -PathType Container -ErrorAction 0
                    }
                    Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__TSProfilePathExist" -Value $res -Force
                }
                try {$TSHomeDrive = $oUser2.psbase.InvokeGet("terminalServicesHomeDrive")} catch {$TSHomeDrive = ""}
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__TSHomeDrive" -Value $TSHomeDrive -Force

                try {$TSHomeDir = $oUser2.psbase.InvokeGet("terminalServicesHomeDirectory")} catch {$TSHomeDir = ""}
                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__TSHomeDirectory" -Value $TSHomeDir -Force

                Add-Member -InputObject $oUser -MemberType NoteProperty -Name "__UserID" -Value $oUser.SamAccountName -Force

                $oUser | Select-Object -Property $Property
            }
        }
        catch [Exception] {
            Write-Error -Exception $_
        }
    }
    END {
        Write-Verbose -Message "$LPP Exiting $($MyInvocation.MyCommand)"
    }
} # End Get-nADUser