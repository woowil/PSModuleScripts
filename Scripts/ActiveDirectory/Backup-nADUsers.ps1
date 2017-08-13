#  Copyright (c) EVRY AS. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

Function Backup-nADUsers {
    <#
	.SYNOPSIS
       Backup Active Directory users to central location as a CSV semi-colon file

    .DESCRIPTION
        Run a LDAP query using filter "(&(objectCategory=person)(objectCategory=User)(samaccountname=*))"
		Create a semi-colon, UTF8 encoding output file of object fields:
		Columns: Domain;UserName;FirstName;LastName;Department;State;homeDirectory;Email;TSProfilePath;distinguishedName
		Output: "$__dfsopdata\Input\Lists\$__customerid\skalaadusers-$__customerid.csv"

    .PARAMETER sAMAccountName
       Describes the a wildcard for users to search.
	   Default is "*"

	.PARAMETER LPP
        Describes the Log Progess Prefix charactor.
		Default is "#"

    .EXAMPLE
		Backup-nADUsers -ShowLog

		Result
		-----------
		...

		Description
		-----------
		The Description..

	.EXAMPLE
		Backup-nADUsers -ShowLog -sAMAccountName "*AB*"

		Result
		-----------
		...

		Description
		-----------
		The Description..



	.OUTPUTS
		dsquery * -filter "(&(objectCategory=person)(objectCategory=User)(samaccountname=*))" -attr cn distinguishedName mail homeDirectory sn givenName

	.NOTES
        Name         : Backup-nADUsers
	    Module       : PSMS
        Author       : Woodworth Wilson
        Changed Log  : 2014-03-13; 1.0; Woodworth.Wilson@evry.com; Initial Version
	                 : 2014-04-13; 1.1; Woodworth.Wilson@evry.com; Added section for ..
					 : 2014-06-03; 1.2; Woodworth.Wilson@evry.com; Rearanges/renamed column names, Fixed Encoding output to UTF8


	.LINK
        Backup-nADUsers

	#>
    param(
        [string] $sAMAccountName = "*",
        [Parameter (Mandatory = $true)]
        [ValidateScript( {$_ -match ".+.csv$"})]
        [string] $OutputCSV,
        [string] $LPP = "#"
    )
    BEGIN {
        Write-Verbose -Message "$LPP Entering $($MyInvocation.MyCommand)"
        # http://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx

        $Filter = "(&(objectCategory=Person)(objectClass=User)(samaccountname=$sAMAccountName))"
        #$Filter = "(&(objectCategory=person)(objectClass=User))"

        $objDomain = New-Object System.DirectoryServices.DirectoryEntry
        $objSearch = New-Object System.DirectoryServices.DirectorySearcher
        $objSearch.PageSize = 15000
        $objSearch.Filter = $Filter
        $objSearch.SearchRoot = $objDomain
        $objSearch.SearchScope = "subtree"
        $objSearch.PropertiesToLoad.Add("distinguishedName") | Out-Null
        $objSearch.PropertiesToLoad.Add("sAMAccountName") | Out-Null
        $objSearch.PropertiesToLoad.Add("sn") | Out-Null
        $objSearch.PropertiesToLoad.Add("mail") | Out-Null
        $objSearch.PropertiesToLoad.Add("givenName") | Out-Null
        $objSearch.PropertiesToLoad.Add("st") | Out-Null
        $objSearch.PropertiesToLoad.Add("department") | Out-Null
        $objSearch.PropertiesToLoad.Add("homeDirectory") | Out-Null

        Write-Verbose -Message "$LPP# Finding users using LDAP filter: $Filter"
        $objects = $objSearch.FindAll()
        $len = ($objects | Measure-Object).Count; $i = 0
        $Heading = "Domain;UserName;FirstName;LastName;Department;State;homeDirectory;Email;TSProfilePath;distinguishedName;Description"
        $Heading > $OutputCSV # | Out-File $__eCsvFile -Force -Encoding "UTF8" #iso-8859-1
        $match = "Guest|Administrator|krbtgt"
        Write-Verbose -Message "$LPP# Processing $len users from current domain"
    }
    PROCESS {
        try {
            forEach ($object in $objects) {
                $oUser = $object.Properties
                $distinguishedName = $oUser.distinguishedname
                if ($distinguishedName -match $match) {
                    continue
                }
                $user = [ADSI] "LDAP://$distinguishedName"

                try { $TSProfilePath = $user.psbase.invokeGet("TerminalServicesProfilePath")} catch { $TSProfilePath = "N/A"}
                $UserName = $oUser.samaccountname
                $LastName = "N/A"
                $FirstName = "N/A"
                $homeDirectory = "N/A"
                $State = "N/A"
                $Department = "N/A"
                $Email = "N/A"
                $Description = "N/A"
                try {$LastName = $oUser.sn} catch {}
                try {$FirstName = $oUser.givenname} catch {}
                try {$homeDirectory = $oUser.homedirectory} catch {}
                try {$Department = $oUser.department} catch {}
                try {$State = $oUser.st} catch {}
                try {$Email = $oUser.mail} catch {}
                try {$Description = $oUser.description} catch {}
                "$__userdomain;$UserName;$FirstName;$LastName;$Department;$State;$homeDirectory;$Email;$TSProfilePath;$distinguishedName" >> $OutputCSV #| Out-File -Append $OutputCSV
                $i++
            }
        }
        catch [Exception] {
            Write-Error -Exception $_.Exception
        }
        finally {
            if ($i -gt 0) {
                Write-Verbose -Message "$LPP# Finalizing backup of $i($len)) users to output: $OutputCSV"
                # This solves the Encoding issue
                [System.Io.File]::ReadAllText($OutputCSV) | Out-File -FilePath $OutputCSV -Encoding UTF8
            }
        }
    }
    END {
        Write-Verbose -Message "$LPP Exiting $($MyInvocation.MyCommand)"
    }
} # End Backup-nADUsers