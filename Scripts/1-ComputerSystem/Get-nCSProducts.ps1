#  Copyright (c) nOsliw Solutions. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

Function Get-nCSProducts {
    <#
	.SYNOPSIS
        Retrieves the Products on systems

    .DESCRIPTION
        Retrieves the Products on systems
		Outputs to CSV and HTM file

    .PARAMETER SystemName
        Describes the system names(s)
		Default is localhost

	.PARAMETER ADGroupName
		Describes the an AD Group containing servers

	.PARAMETER LPP
		Log progess prefix. Default is '#'

    .EXAMPLE
		Get-nCSProducts

		Result
		-----------
		...

		Description
		-----------
		Retrieves all Products for production envinronment

	.OUTPUTS

	.LINK

#>
    [CmdletBinding()]
    param(
        [Alias('Computer', 'ComputerName', 'System')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [string[]] $SystemName = @($env:COMPUTERNAME),
        [string] $ADGroupName,
        [string] $LPP = "#"
    )
    BEGIN {
        if (!$__nPSMS.Settings.IsCSLoaded) {Initialize-nCS}
        Write-Verbose -Message "$LPP Entering $($MyInvocation.MyCommand)"

        $Headers = @("SystemName", "DisplayName", "InstallDate", "Publisher", "Version", "ProdID")

        $SystemName = $SystemName -match "[^ \t]+" # removes empty cells
        if ($ADGroupName) {
            Write-Verbose -Message "$LPP# Getting servers from AD group=$ADGroupName*"
            $tmp = dsquery group -name $ADGroupName* | dsget group -members -c 2>$null | dsget computer -samid -c 2>$null | Select-String -Pattern "-114"
            if ($tmp -ne $null) {
                $SystemName += $tmp -replace "[ \t$]+"
            }
        }
        $SystemName = $SystemName | Sort-Object -Unique
        $len = ($SystemName | Measure-Object).Count
        $i = 1
    }
    PROCESS {
        try {
            forEach ($system in $SystemName) {
                $c = "$i($len)"; $i++
                if ([String]::IsNullOrEmpty($system)) { continue }
                Write-Verbose -Message "$LPP# $c Processing services on system=$system"
                if (-not (Test-Connection -ComputerName $system -count 1 -Delay 2 -BufferSize 256 -Quiet)) {
                    Write-Verbose -Message "$LPP## Unable to make a network connection to system=$system"
                    Log -noDateTime
                    continue
                }

                try {
                    $products = Get-WmiObject -Query "Select DisplayName,InstallDate,Publisher,Version,ProdID from Win32Reg_AddRemovePrograms" -ComputerName $system |
                        Select-Object -Property DisplayName, InstallDate, Publisher, Version, ProdID
                }
                catch [Exception] {
                    Write-Error -Exception $_ -Message "Unable to make a WMI connection to $system"
                    continue
                }

                ForEach ($object in $products) {
                    $object | Add-Member -MemberType NoteProperty -Name SystemName -Value $system -Force

                    $object | Select-Object -Property $Headers
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
} # End Get-nCSProducts