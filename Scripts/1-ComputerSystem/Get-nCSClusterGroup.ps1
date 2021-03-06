#  Copyright (c) nOsliw Solutions. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

Function Get-nCSClusterGroup {
    <#
	.SYNOPSIS
        Retrieves Cluster resource status (online/offline) in the Application Services environment

    .DESCRIPTION
        Retrieves the Cluster resource status (online/offline) in the Application Services environment
		Return an array object of the inbuilt Get-ClusterGroup
		Loads the FailoverClusters module if not imported

    .PARAMETER IncludeCoreGroup
		Describes the core groups 'Cluster Group' and 'Available Storage' should be included

	.PARAMETER LPP
		Log progess prefix. Default is '#'

    .EXAMPLE
		Get-nCSClusterGroup -DBTableInsert | Format-Table -AutoSize

		Result
		-----------


		Description
		-----------
		The Description..


	.OUTPUTS
		Get-nCSClusterGroup

	.LINK

#>
    [CmdletBinding()]
    param(
        [Alias('Cluster')]
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [string[]] $ClusterName,
        [switch] $IncludeCoreGroup,
        [string] $LPP = "#"
    )
    BEGIN {
        if (!$__nPSMS.Settings.IsCSLoaded) {Initialize-nCS}
        Write-Verbose -Message "$LPP Entering $($MyInvocation.MyCommand)"

        $ClusterName = $ClusterName | Sort-Object -Unique
        $len = $ClusterName.Length

        if ($__nPSMS.__IsWin32()) {
            Write-Verbose -Message "$LPP# The session is current running in x86 (Win32). Please restart the cmdlet must from required x64-bit process."
            break
        }
        elseif ((Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue) -eq $null ) {
            Write-Verbose -Message "$LPP# Importing FailoverClusters module. Please wait..."
            Import-Module -Name FailoverClusters
        }
        #Do not change to arraylist. Reason. $groups is not a hash object and causes problem in Finally section
        $Headers = @("DateTimeStamp", "Environment", "Cluster", "IsCoreGroup", "OwnerNode", "State", "Name", "Description", "PersistentState", "FailoverThreshold", "FailoverPeriod", "AutoFailbackType", "FailbackWindowStart", "FailbackWindowEnd", "Priority", "DefaultOwner", "AntiAffinityClassNames", "Id")
        $DateTimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    PROCESS {
        try {
            forEach ($cluster in $ClusterName) {
                if ([String]::IsNullOrEmpty($cluster)) { continue }
                $c = "$i($len)"; $i++
                Write-Verbose -Message "$LPP# $c Processing cluster=$cluster"

                if (-not (Get-Cluster -Name $cluster -ErrorAction SilentlyContinue)) {
                    Write-Verbose -Message "$LPP## The cluster $cluster is either invalid or unable to connect"
                    continue
                }
                if (!$IncludeCoreGroup) {
                    $object = Get-ClusterGroup -Cluster $cluster | Select-Object -Property * | Where-Object -FilterScript {!$_.IsCoreGroup}
                }
                else {
                    $object = Get-ClusterGroup -Cluster $cluster | Select-Object -Property *
                }
                $object | Add-Member -Name Environment -Value $CustomerID -MemberType NoteProperty | Out-Null
                $object | Add-Member -Name DateTimeStamp -Value $DateTimeStamp -MemberType NoteProperty | Out-Null

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
} # End Get-nCSClusterGroup