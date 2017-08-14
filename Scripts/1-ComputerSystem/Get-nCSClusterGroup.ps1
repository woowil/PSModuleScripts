#  Copyright (c) nOsliw Solutions. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

Function Get-nCSClusterGroup
{
	<#
	.SYNOPSIS
        Retrieves Cluster resource status (online/offline) in the Application Services environment

    .DESCRIPTION
        Retrieves the Cluster resource status (online/offline) in the Application Services environment
		Return an array object of the inbuilt Get-ClusterGroup
		Loads the FailoverClusters module if not imported
		Outputs a CSV file

    .PARAMETER OutFileCSV
        Describes the CSV output file. 
		Default is $__eCsvFileRandomDFS
		
	.PARAMETER IncludeCoreGroup
		Describes the core groups 'Cluster Group' and 'Available Storage' should be included
	
	.PARAMETER LPP
		Log progess prefix. Default is '#'
		
    .EXAMPLE
		Get-nCSClusterGroup -CustomerID ERF -DBTableInsert | Format-Table -AutoSize

		Result
		-----------
			[20130420 17:58:11] # Entering Get-nCSClusterGroup
			[20130420 17:58:11] ## Making a SQL connection to source:ERFDB002, database:EVRY8DMgmtDB
			[20130420 17:58:11] ## Starting Application Services cluster resource on 4 clusters
			[20130420 17:58:11] ### 1(4) Runing cluster: ERFCL11
			[20130420 17:58:11] #### Getting cluster group info on cluster
			[20130420 17:58:11] #### Inserting 5 rows into SQL Cluster table 'AS_ClusterStatus'
			[20130420 17:58:11] ### 2(4) Runing cluster: ERFCL12
			[20130420 17:58:11] #### Getting cluster group info on cluster
			[20130420 17:58:12] #### Inserting 4 rows into SQL Cluster table 'AS_ClusterStatus'
			[20130420 17:58:12] ### 3(4) Runing cluster: ERFCL13
			[20130420 17:58:12] #### Getting cluster group info on cluster
			[20130420 17:58:13] #### Inserting 6 rows into SQL Cluster table 'AS_ClusterStatus'
			[20130420 17:58:13] ### 4(4) Runing cluster: ERFCL32
			[20130420 17:58:13] #### Getting cluster group info on cluster
			[20130420 17:58:14] #### Inserting 7 rows into SQL Cluster table 'AS_ClusterStatus'
			[20130420 17:58:15] ## Exporting cluster resources to output file: \\ERF01.net\OpData\AS\EvryAO\2-ReportServices\Cluster\ClusterStatus.csv
			[20130420 17:58:15] # Exiting Get-nCSClusterGroup

			Cluster IsCoreGroup OwnerNode     State Name                       Description PersistentState FailoverThreshold FailoverPeriod AutoFailbackType
			------- ----------- ---------     ----- ----                       ----------- --------------- ----------------- -------------- ----------------
			ERFCL11       False erfcl11cn001 Online ERFCL11                                              1        4294967295              6                0
			ERFCL11       False erfcl11cn003 Online ERFCL11DB002(ERF11INST02)                            1        4294967295              6                0
			ERFCL11       False erfcl11cn001 Online ERFCL11DTC                                           1        4294967295              6                0
			ERFCL11       False erfcl11cn002 Online SHAREPOINT                                           1        4294967295              6                0
			ERFCL11       False erfcl11cn001 Online SQL Server (ERF_APPL_PROD)                           1        4294967295              6                1
			ERFCL12       False erfcl12cn002 Online ERFCL12                                              1        4294967295              6                0
			ERFCL12       False erfcl12cn001 Online ERFCL12AP001                                         1        4294967295              6                0
			ERFCL12       False erfcl12cn002 Online ERFCL12AP002                                         1        4294967295              6                0
			ERFCL12       False erfcl12cn001 Online ERFCL12DTC                                           1        4294967295              6                0
			ERFCL13       False erfcl13cn001 Online ERFCL13                                              1        4294967295              6                0
			ERFCL13       False erfcl13cn001 Online ERFCL13DTC                                           1        4294967295              6                0
			ERFCL13       False erfcl13cn001 Online INST01                                               1        4294967295              6                0
			ERFCL13       False erfcl13cn002 Online INST02                                               1        4294967295              6                0
			ERFCL13       False erfcl13cn003 Online INST03                                               1        4294967295              6                0
			ERFCL13       False erfcl13cn004 Online INST04                                               1        4294967295              6                0
			ERFCL32       False erfcl32cn001 Online ERFCL32                                              1        4294967295              6                0
			ERFCL32       False erfcl32cn001 Online ERFCLFS001                                           1        4294967295              6                0
			ERFCL32       False erfcl32cn002 Online ERFCLFS002                                           1        4294967295              6                0
			ERFCL32       False erfcl32cn001 Online ERFCLFS003                                           1        4294967295              6                0
			ERFCL32       False erfcl32cn002 Online ERFCLFS004                                  

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
		[Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
		[string[]] $ClusterName,
		[switch] $IncludeCoreGroup,
		[string] $LPP = "#"
	)
	BEGIN{
		if(!$__nPSMS.Settings.IsCSLoaded){Initialize-nCS}
		Write-Verbose -Message "$LPP Entering $($MyInvocation.MyCommand)"
		
		$ClusterName = $ClusterName | Sort-Object -Unique
		$len = $ClusterName.Length
		
		if($__nPSMS.__IsWin32()){
			Write-Verbose -Message "$LPP# The session is current running in x86 (Win32). Please restart the cmdlet must from required x64-bit process."
			break
		}
		elseif ((Get-Module -Name FailoverClusters -ErrorAction SilentlyContinue) -eq $null ){
			Write-Verbose -Message "$LPP# Importing FailoverClusters module. Please wait..."
			Import-Module -Name FailoverClusters
		}
		#Do not change to arraylist. Reason. $groups is not a hash object and causes problem in Finally section
		$Headers = @("DateTimeStamp","Environment","Cluster","IsCoreGroup","OwnerNode","State","Name","Description","PersistentState","FailoverThreshold","FailoverPeriod","AutoFailbackType","FailbackWindowStart","FailbackWindowEnd","Priority","DefaultOwner","AntiAffinityClassNames","Id")
		$DateTimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
	}
	PROCESS{
		try{
			forEach ($cluster in $ClusterName){
				if([String]::IsNullOrEmpty($cluster)){ continue }
				$c = "$i($len)";$i++
				Write-Verbose -Message "$LPP# $c Processing cluster=$cluster"
				
				if(-not (Get-Cluster -Name $cluster -ErrorAction SilentlyContinue)){
					Write-Verbose -Message "$LPP## The cluster $cluster is either invalid or unable to connect"
					continue
				}
				if(!$IncludeCoreGroup){
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
	END{
		Write-Verbose -Message "$LPP Exiting $($MyInvocation.MyCommand)"
	}
} # End Get-nCSClusterGroup