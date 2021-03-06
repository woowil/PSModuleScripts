#  Copyright (c) nOsliw Solutions. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

Function Get-nCSOpenSessions {
    <#

	.SYNOPSIS
       Enumerates open files on system

    .DESCRIPTION
        Enumerates open files on system by using command: openfiles /query /FO CSV /NH /V /S <server>

	.PARAMETER SystemName
        Describes the system names(s)
		Default is localhost

	.PARAMETER UserName
		Describes the username search string of the session
		Default: *

	.PARAMETER LPP
		Log progess prefix. Default is '#'

	.EXAMPLE
		Get-nCSOpenSessions -SystemName FILSERVER1,FILSERVER2

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
        [Alias('Computer', 'ComputerName', 'System')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [string[]] $SystemName = @($env:COMPUTERNAME),
        [string] $UserName = "*",

        [string] $LPP = "#"
    )
    BEGIN {
        if (!$__nPSMS.Settings.IsCSLoaded) {Initialize-nCS}
        Write-Verbose -Message "$LPP Entering $($MyInvocation.MyCommand)"

        $SystemName = $SystemName -match "[^ \t]+" # removes empty cells
        $SystemName = $SystemName | Sort-Object -Unique
        $len = $SystemName.Length

        $UserNameLike = $UserName -replace "\*", "%"
        $Query = "Select * from Win32_ServerSession where UserName like '%$UserNameLike%'"
        $i = 1

    }
    PROCESS {
        try {
            forEach ($system in $SystemName) {
                $c = "$i($len)"; $i++
                Write-Verbose -Message "$LPP# $c Processing system=$system"
                if (($PingObj = Test-Connection -ComputerName $system -count 1 -Delay 2 -BufferSize 256 -ErrorAction 0) -eq $Null) {
                    $Pingable = $False
                    $IPV4Address = ""
                }
                else {
                    $Pingable = $True
                    $IPV4Address = $PingObj.IPV4Address.IPAddressToString
                }
                Get-CimInstance -ComputerName $system -Query $Query -ErrorAction 0 | ForEach-Object -Begin {
                    Write-Verbose -Message "$LPP## Getting network sessions"
                } `
                    -Process {
                    $object = New-Object -TypeName Object
                    $object | Add-Member -MemberType NoteProperty -Name ActiveTime -Value $_.ActiveTime
                    $ActiveTimeStart = (Get-Date).AddSeconds( - $_.ActiveTime)
                    $ActiveTimeStartStr = Get-Date -Date $ActiveTimeStart -Format "yyyy-MM-dd HH:mm:ss"
                    $object | Add-Member -MemberType NoteProperty -Name ActiveTimeStart -Value $ActiveTimeStartStr

                    $object | Add-Member -MemberType NoteProperty -Name Caption -Value $_.Caption
                    $object | Add-Member -MemberType NoteProperty -Name ClientType -Value $_.ClientType

                    $ComputerFQDN = [system.net.dns]::resolve($_.ComputerName).HostName
                    $ComputerName = $ComputerFQDN.toString().toUpper() -replace "\..+"
                    $object | Add-Member -MemberType NoteProperty -Name ComputerFQDN -Value $ComputerFQDN
                    $object | Add-Member -MemberType NoteProperty -Name ComputerIP -Value $_.ComputerName
                    $object | Add-Member -MemberType NoteProperty -Name ComputerName -Value $ComputerName

                    $object | Add-Member -MemberType NoteProperty -Name Description -Value $_.Description

                    $object | Add-Member -MemberType NoteProperty -Name IdleTime -Value $_.IdleTime
                    $IdleTimeStart = (Get-Date).AddSeconds( - $_.IdleTime)
                    $IdleTimeStartStr = Get-Date -Date $IdleTimeStart -Format "yyyy-MM-dd HH:mm:ss"
                    $object | Add-Member -MemberType NoteProperty -Name IdleTimeStart -Value $IdleTimeStartStr

                    $object | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name
                    $object | Add-Member -MemberType NoteProperty -Name ResourcesOpened -Value $_.ResourcesOpened
                    $object | Add-Member -MemberType NoteProperty -Name SessionType -Value $_.SessionType
                    $object | Add-Member -MemberType NoteProperty -Name SystemName -Value $_.PSComputerName
                    $object | Add-Member -MemberType NoteProperty -Name Status -Value $_.Status
                    $object | Add-Member -MemberType NoteProperty -Name TransportName -Value $_.TransportName
                    $object | Add-Member -MemberType NoteProperty -Name UserName -Value $_.UserName

                    Write-Output -InputObject $object
                } `
                    -End {

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
}
