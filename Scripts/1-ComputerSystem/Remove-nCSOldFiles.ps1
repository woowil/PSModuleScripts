#  Copyright (c) nOsliw Solutions. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

Function Remove-nCSOldFiles {
    <#
	.SYNOPSIS
        Removes Log files based on days and/or months

    .DESCRIPTION
        Removes any type of files based on LastWrite date by choosing either
        days or/and months to remove

    .PARAMETER Path
        Describes the directory path
        Add a comma if more that one path
        Mandatory parameter

    .PARAMETER Include
        Describes the a wildcard of any file type. For example *.log or myfile*.log
        Add a comma if more than on file type. For example *.log,myfile*.log
        Default is *.log

    .PARAMETER DaysToRemove
        Describe days back in time to remove.
        Default is -120

	.PARAMETER MonthsToRemove
        Describe months back in time to remove.
        Default is 0

    .PARAMETER Recurse
        Search recursively directory

    .EXAMPLE
		.\Remove-nCSOldFiles.ps1 -Path $Env:temp -Include *.tmp -DaysToRemove -15


		Description
		-----------
		The Description..

	.EXAMPLE
		.\Remove-nCSOldFiles.ps1 -Path


		Description
		-----------
		The Description..

	.EXAMPLE
		.\Remove-nCSOldFiles.ps1

		Result
		-----------
		...

		Description
		-----------
		The Description..

    .EXAMPLE
		Remove-nCSOldFiles -Path \\server\share -Include u*.log* -Recurse -MonthsToRemove 5 -DaysToRemove 0 -WhatIf

		Description
		-----------
		The Description..

	.OUTPUTS
		Remove-nASOldFiles


	.LINK

	#>

    param (
        [Parameter(Mandatory = $True, HelpMessage = "Enter the directory path")]
        [string[]] $Path,

        [Parameter(HelpMessage = "Enter one more file type with extension separated by comma")]
        [ValidateScript(
            {
                If ($_ -match ".+\.[a-z0-9_\-*]+") {
                    $True
                }
                Else {
                    Throw "$_ is does not match Regular Expression '.+\.[a-z0-9_\-*]+'. The the file argument must have a basename and extension with or without wildcard (*)"
                }
            }
        )]
        [string[]] $Include = "*.log",

        [Parameter(HelpMessage = "Enter a number equal or greater than zero")]
        [ValidateScript( {$_ -ge 0})]
        [int] $DaysToRemove = 120,

        [Parameter(HelpMessage = "Enter a number equal or greater than zero")]
        [ValidateScript( {$_ -ge 0})]
        [int] $MonthsToRemove = 0,

        [switch] $Recurse,
        [switch] $WhatIf,
        [string] $LPP = "#"

    )
    BEGIN {
        if (!$__nPSMS.Settings.IsCSLoaded) {Initialize-nCS}
        Write-Verbose -Message "$LPP Entering $($MyInvocation.MyCommand)"

        $dt = Get-Date
        $DateToRemove = $dt.AddDays( - $DaysToRemove).AddMonths( - $MonthsToRemove)
        Write-Verbose -Message "$LPP# Using DateTime = $DateToRemove"
    }
    PROCESS {
        try {
            forEach ($p in $Path) {
                $p = $p -replace "(.+)\\$", '$1'
                Write-Verbose -Message "$LPP# Processing path=$p"

                if (-not (Test-Path -Path $p -PathType Container)) {
                    Write-Verbose -Message "$LPP## Either no access or unable to locate folder=$p"
                    continue
                }
                Get-ChildItem -Path "$p\*" -Recurse:$Recurse -Include $Include |
                    Where-Object -FilterScript {$_.LastWriteTime -lt $DateToremove} |
                    ForEach-Object -Proces {
                    $FullName = $_.FullName
                    $LastWriteTime = $_.LastWriteTime
                    Write-Verbose -Message "$LPP## Removing File=$FullName, LastWriteTime=$LastWriteTime"
                    Remove-Item -Path $_.FullName -Force -WhatIf:$WhatIf -Confirm:$False
                    #$_.Delete()
                }
            }
        }
        catch [Exception] {
            Write-Error -Exception $_
        }
    }
    END {
        Write-Verbose -Message "$LPP Exiting $($MyInvocation.MyCommand)"
    }
} # End Remove-nCSOldFiles