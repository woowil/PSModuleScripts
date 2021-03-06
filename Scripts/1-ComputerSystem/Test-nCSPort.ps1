#  Copyright (c) nOsliw Solutions. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

Function Test-nCSPort {
    <#
	.SYNOPSIS
       Test TCP and UDP port connection on system(s)

    .DESCRIPTION
        Test Transmission control protocol (TCP) and User Datagram protocol (UDP) port connection on system(s)
		Replaces Ping and Telnet

	.PARAMETER SystemName
        Describes the system names(s)
		Default is localhost

	.PARAMETER Port
		Port numbers to test. Mandatory. Example: 80,139,"1024-2000"
		Valid port range is: 1-65535

	.PARAMETER Protocol
		Choose TCP, UDP or BOTH
		Default: TCP

	.PARAMETER TCPTimeOut
		Sets a timeout (in milliseconds) for TCP port query
		Default is 1000
		Valid number range is: 1-60000

	.PARAMETER UDPTimeOut
		Sets a timeout (in milliseconds) for UDP port query
		Default is 1000
		Valid number range is: 1-60000

	.PARAMETER Quiet
		Return true or false

	.PARAMETER LPP
		Log progess prefix. Default is '#'

	.EXAMPLE
		. .\Test-nCSPort.ps1
		Test-Port -SystemName server1,server2 -Port 21,445,"80-93",8080

		Result
		-----------
		...

		Description
		-----------
		The Description..

	.EXAMPLE
		. .\Test-nCSPort.ps1
		Test-Port -SystemName server1 -Port 135-139 | Out-GridView

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

        [ValidatePattern("[0-9]{1,5}-[0-9]{1,5}$|[0-9]{1,5}$")]
        [Parameter(Mandatory = $true)]
        [string[]] $Port,

        [ValidateSet('TCP', 'UDP', 'BOTH')]
        [string] $Protocol = "TCP",

        [ValidateRange(1, 60000)]
        [int] $TCPTimeOut = 1000,

        [ValidateRange(1, 60000)]
        [int] $UDPTimeOut = 1000,

        [switch] $Quiet,

        [string] $LPP = "#"
    )
    BEGIN {
        if (!$__nPSMS.Settings.IsCSLoaded) {Initialize-nCS}
        Write-Verbose -Message "$LPP Entering $($MyInvocation.MyCommand)"

        $SystemName = $SystemName -match "[^ \t]+" # removes empty cells
        $SystemName = $SystemName | Sort-Object -Unique
        $len = $SystemName.Length

        $IsTCP = $Protocol -match "BOTH|TCP"
        $IsUDP = $Protocol -match "BOTH|UDP"

        $ToTalPorts = @()
        ForEach ($tmp in $Port) {
            if ($tmp -match "([0-9]+)-([0-9]+)") {
                [int]$min = $matches[1]
                [int]$max = $matches[2]
                if ($max -lt $min -or $min -gt 65534 -or $max -gt 65535) {
                    Write-Host -Object "$LPP# The range $tmp is invalid. Enter minimal-maximal range value is between 1-65535" -fore Red
                    return
                }
                $ToTalPorts += $min..$max
            }
            else {
                $ToTalPorts += [int]$tmp
            }
        }
        $ToTalPorts = $ToTalPorts | Sort-Object -Unique

        $file = "$Env:windir\system32\drivers\etc\services"
        Get-Content -Path $file | Select-string -Pattern "/TCP|/UDP" | ForEach-Object `
            -Begin {
            $dServices = @{}
        } `
            -Process {
            $line = $_ -replace "[ \t]{2,}", ";" -replace "[#]+"
            $a_line = $line.Split(";")
            $dServices.Add($a_line[1], $a_line)
        }

        $system = "$Env:COMPUTERNAME"
        $systemipv4 = [system.net.dns]::resolve($system).AddressList[0].IPAddressToString

        $Headers = @("Comments", "DateTime", "HostName", "HostIPV4", "IANAService", "Listening", "Pingable", "Port", "Protocol", "SystemName", "SystemIPV4")
        $scriptblock = {
            $i = 0
            $IANAService = ""
            $Port = $args[3]
            $Protocol = $args[4]

            if ($Port -match "5985|5986") {
                $Remote = if ($Port -eq "5986") {"Secure Remote"} else {"Remote"}
                $IANAService = "ms-powershell (PowerShell $Remote Port)"
            }
            elseif ($dServices.ContainsKey("$Port/$Protocol")) {
                $a = $dServices."$Port/$Protocol"
                $IANAService = if ($a.Count -gt 2) {$a[0] + " (" + $a[2..($a.Length - 1)] + ")" } else {$a[0]}

            }

            $object = New-Object -TypeName Object
            $DateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
            $object | Add-Member -MemberType NoteProperty -Name DateTime   -Value $DateTime
            $object | Add-Member -MemberType NoteProperty -Name HostName   -Value $system
            $object | Add-Member -MemberType NoteProperty -Name HostIPV4   -Value $systemipv4
            $object | Add-Member -MemberType NoteProperty -Name SystemName -Value $args[$i++]
            $object | Add-Member -MemberType NoteProperty -Name SystemIPV4 -Value $args[$i++]
            $object | Add-Member -MemberType NoteProperty -Name Pingable   -Value $args[$i++]
            $object | Add-Member -MemberType NoteProperty -Name Port       -Value $args[$i++]
            $object | Add-Member -MemberType NoteProperty -Name Protocol   -Value $args[$i++]
            $object | Add-Member -MemberType NoteProperty -Name Listening  -Value $args[$i++]
            $object | Add-Member -MemberType NoteProperty -Name IANAService -Value $IANAService
            $object | Add-Member -MemberType NoteProperty -Name Comments   -Value $args[$i++]

            $object = $object | Select-Object -Property $Headers
            Write-Output -InputObject $object
        }
        $i = 1
        $result = $true
    }
    PROCESS {
        try {
            forEach ($system in $SystemName) {
                if (!$Quiet) {
                    $c = "$i($len)"; $i++
                    Write-Verbose -Message "$LPP# $c Processing system=$system"
                }
                if (($PingObj = Test-Connection -ComputerName $system -count 1 -Delay 2 -BufferSize 256 -ErrorAction 0) -eq $Null) {
                    $Pingable = $False
                    $IPV4Address = ""
                }
                else {
                    $Pingable = $True
                    $IPV4Address = $PingObj.IPV4Address.IPAddressToString
                }
                forEach ($p in $ToTalPorts) {
                    if ($IsTCP) {
                        $tcpobject = new-Object system.Net.Sockets.TcpClient
                        Write-Verbose "Making TCP connection to target machine=$system on port=$p"
                        $connect = $tcpobject.BeginConnect($system, $p, $null, $null)

                        $Listening = $False
                        $Protocol = "TCP"
                        $Comments = ""

                        if (!($connect.AsyncWaitHandle.WaitOne($TCPtimeout, $false))) {
                            $comments = "Connection timed-out on port $Protocol/$p after $TCPtimeout milliseconds from $__systemipv4 to $IPV4Address"
                        }
                        else {
                            try {
                                $tcpobject.EndConnect($connect) #| out-Null
                                $Listening = $True
                            }
                            catch [Exception] {
                                $comments = $_.Exception.Message.ToString().Trim()
                            }
                        }
                        $tcpobject.Close()
                        if ($Quiet -and !$Listening) { return $false}

                        Invoke-Command -ScriptBlock $scriptblock `
                            -ArgumentList $system, $IPV4Address, $Pingable, $p, $Protocol, $Listening, $Comments
                    }
                    if ($IsUDP) {
                        $udpobject = new-Object system.Net.Sockets.UdpClient
                        $udpobject.client.ReceiveTimeout = $UDPTimeout

                        $Listening = $False
                        $Protocol = "UDP"
                        $Comments = ""

                        Write-Verbose "Making UDP connection to target machine=$system on port=$p"
                        $udpobject.Connect($system, $p)

                        Write-Verbose "Sending UDP message to target machine"
                        $a = new-object system.text.asciiencoding
                        $byte = $a.GetBytes("$(Get-Date)")
                        [void]$udpobject.Send($byte, $byte.length)
                        #IPEndPoint object will allow us to read datagrams sent from any source.
                        Write-Verbose "Creating remote endpoint"
                        $remoteendpoint = New-Object system.net.ipendpoint([system.net.ipaddress]::Any, 0)
                        try {
                            #Write-Verbose "Waiting for message return"
                            $receivebytes = $udpobject.Receive([ref]$remoteendpoint)
                            [string]$returndata = $a.GetString($receivebytes)
                            if ($returndata) {
                                $Listening = $True
                                $Comments = $returndata
                                $udpobject.Close()
                            }
                        }
                        catch [Exception] {
                            $message = $_.Exception.Message.ToString().Trim()
                            $udpobject.Close()
                            if ($message -match "Respond after a period of time") {
                                $Comments = "Unable to verify if port is open/listening or target machine is unavailable. Try "
                            }
                            elseIf ($message -match "forcibly closed by the remote host") {
                                $Comments = "The connection to port timed-out (forcibly closed) on target machine"
                            }
                        }
                        if ($Quiet -and !$Listening) { return $false}
                        Invoke-Command -ScriptBlock $scriptblock `
                            -ArgumentList $system, $IPV4Address, $Pingable, $p, $Protocol, $Listening, $Comments
                    }
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
# Test-nCSPort