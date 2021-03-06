#  Copyright (c) nOsliw Solutions. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

Function Get-nCSMicrosoftUpdates
{
	<#
	.SYNOPSIS
       Retrieves Microsoft updates on system(s)

    .DESCRIPTION
        Retrieves Microsoft updates on system(s)

	.PARAMETER SystemName
        Describes the system names(s)
		Default is localhost

	.PARAMETER TitleSearch
		Filter out a title
		Default is: *

	.PARAMETER RangeMinimal
		Export minimal number of updates
		Default is: 0

	.PARAMETER RangeMaximal
		Export all updates

	.PARAMETER LPP
		Log progess prefix. Default is '#'

	.EXAMPLE
		Get-nCSMicrosoftUpdates -Allupdates -SystemName server1,server2

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
		[Alias('Computer','ComputerName','System')]
		[Parameter(ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
		[string[]] $SystemName = @($env:COMPUTERNAME),

		[string] $TitleSearch = "*",
		[ValidateRange(0,10000)]
		[int] $RangeMinimal = 0,
		[ValidateRange(1,10000)]
		[int] $RangeMaximal,

		[string] $LPP = "#"
	)
	begin{
		if(!$__nPSMS.Settings.IsCSLoaded){Initialize-nCS}
		Write-Verbose -Message "$LPP Entering $($MyInvocation.MyCommand)"
		
		$SystemName = $SystemName -match "[^ \t]+" # removes empty cells
		$SystemName = $SystemName | Sort-Object -Unique
		$len = $SystemName.Length
		
		$TitleMatch = $TitleSearch -replace "\*",".+" -replace "\?",".{1}"
		if(!$RangeMaximal){
			$RangeMaximal = 10000
		}
		elseif($RangeMaximal -lt $RangeMinimal){
			Write-Verbose -Message "$LPP# RangeMinimal range value must be lower than RangeMaximal"
			break
		}

		$updateblock = {
			$Session  = New-Object -ComObject "Microsoft.Update.Session"
			$Searcher = $Session.CreateUpdateSearcher()

			$max = $args[1]
			if($args[1] -eq 10000){
				$max= $Searcher.GetTotalHistoryCount()
			}
			$Searcher.QueryHistory($args[0],$max) |
				Where-Object -FilterScript {$_.Title -match $args[2]}
		}
		$i = 1
	}
	PROCESS{
		try{
			forEach ($system in $SystemName){
				if([String]::IsNullOrEmpty($system)){ continue }
				$c = "$i($len)";$i++
				Write-Verbose -Message "$LPP# $c Processing system=$system"
				if(-not (Test-Connection -ComputerName $system -count 1 -Delay 2 -BufferSize 256 -Quiet)){
                    Write-Verbose -Message "$LPP### Unable to make a network connection to system=$system"
                    Log -noDateTime
                    continue
                }

				Invoke-Command -ComputerName $system -ScriptBlock $updateblock `
					-ArgumentList $RangeMinimal,$RangeMaximal,$TitleMatch
			}
		}
		catch [Exception] {
			Write-Error -Exception $_
		}
	}
	END{
		Write-Verbose -Message "$LPP Exiting $($MyInvocation.MyCommand)"
	}
}
