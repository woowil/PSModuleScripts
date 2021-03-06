#  Copyright (c) nOsliw Solutions. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

Function Get-nCSLocalGroupMembership {
    <#
	.SYNOPSIS
        Get the local group membership

    .DESCRIPTION
        Get the local group membership from any domain server using ADSI WinNT:// query
		This is also possible by using: psexec \\server1,server2 net localgroup Administartors

    .PARAMETER SystemName
        Describes the system names(s)
		Default is localhost

    .Parameter GroupName
		Name of the GroupName to get members from. Default is "Administrators"

    .EXAMPLE
		Get-nCSLocalGroupMembership

		Result
		-----------
		...

		Description
		-----------
		Get the Administrators group membership for the localhost

	.EXAMPLE
		Get-nCSLocalGroupMembership -ComputerName SERVER01 -GroupName "Remote Desktop Users"

		Result
		-----------
		...

		Description
		-----------
		Get the membership for the group "Remote Desktop Users" on the computer SERVER01

	.EXAMPLE
		Get-nCSLocalGroupMembership -ComputerName SERVER01,SERVER02 -GroupName "Administrators"

		Result
		-----------
		...

		Description
		-----------
		Get the membership for the group "Administrators" on the computers SERVER01 and SERVER02

	.OUTPUTS
		PSCustomObject

	.LINK


#>
    [CmdletBinding()]
    param(
        [Alias('DnsHostName', '__SERVER', 'IPAddress', 'Computer', 'ComputerName', 'System')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [string[]] $SystemName = @($env:COMPUTERNAME),
        [string] $GroupName = "Administrators",

        [Parameter(HelpMessage = "Progress log prefix char")]
        [string] $LPP = "#"
    )
    BEGIN {
        if (!$__nPSMS.Settings.IsCSLoaded) {Initialize-nCS}
        Write-Verbose -Message "$LPP Entering $($MyInvocation.MyCommand)"

        $i = 1
        $SystemName = $SystemName | Sort-Object -Unique
        $len = ($SystemName | Measure-Object).Count

        $Headers = @("Date", "SystemName", "Account", "Type", "Class", "Group", "Path", "DNSDomain", "HostSystem", "IPV4Address", "Accessible", "Pingable", "Comment")
        $ipmatch = "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
    }
    PROCESS {
        try {
            forEach ($system in $SystemName) {
                $c = "$i($len)"; $i++
                if ([String]::IsNullOrEmpty($system)) { continue }

                $object = New-Object -TypeName PSObject -Property @{
                    Date        = Get-date -Format "yyyy-MM-dd"
                    HostSystem  = $__system
                    SystemName  = $system.toUpper() -replace "\..+"
                    DNSDomain   = "N/A"
                    IPV4Address = "0.0.0.0"
                    Pingable    = $True
                    Accessible  = $False
                    Account     = "N/A"
                    Class       = "N/A"
                    Group       = "N/A"
                    Path        = "N/A"
                    Type        = "N/A"
                    Comment     = "N/A"
                }

                Write-Verbose -Message "$LPP# $c Processing localgroup membership on system=$system"
                if (-not (Test-Connection -ComputerName $system -count 1 -Delay 2 -BufferSize 256 -Quiet)) {
                    Write-Verbose -Message "$LPP## Unable to make a network connection to server $system"
                    $object | Add-Member -Name Pingable -Value $False -MemberType NoteProperty -Force
                    $object | Add-Member -Name Comment -Value "Unable to make a network connection to server $system" -MemberType NoteProperty -Force
                    Write-Output -InputObject ($object | Select-Object -Property $Headers)
                    continue
                }
                try {
                    if ($system -match "$ipmatch") {
                        $o = [System.Net.Dns]::GetHostbyAddress($system)
                    }
                    else {
                        $o = [System.Net.Dns]::GetHostbyName($system)
                    }
                    $DNSDomain = $o.HostName -replace "$system\."
                    $system = $o.HostName.toUpper() -replace "\..+"
                    $IPV4Address = $o.AddressList[0].IPAddressToString

                    $object | Add-Member -Name DNSDomain    -Value $DNSDomain   -MemberType NoteProperty -Force
                    $object | Add-Member -Name SystemName   -Value $system      -MemberType NoteProperty -Force
                    $object | Add-Member -Name IPV4Address  -Value $IPV4Address -MemberType NoteProperty -Force
                }
                catch [Exception] {
                    $Message = ($_.Exception.Message).ToString().Trim()
                    Write-Verbose -Message $Message
                }
                try {
                    Write-Verbose -Message "$LPP## Querying WinNT://$system/$GroupName,group"
                    $Group = [ADSI]"WinNT://$system/$GroupName,group"
                    $Members = @($group.psbase.Invoke("Members"))
                    $object | Add-Member -Name Accessible -Value $True -MemberType NoteProperty -Force
                }
                catch [Exception] {
                    $Message = ($_.Exception.Message).ToString().Trim()
                    Write-Verbose -Message "$LPP## Unable to make an system access to server $system"
                    $object | Add-Member -Name Comment -Value "Unable $Message" -MemberType NoteProperty -Force
                    Write-Output -InputObject ($object | Select-Object -Property $Headers)
                    continue
                }
                $members | ForEach-Object {
                    $name = $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
                    $class = $_.GetType().InvokeMember("Class", 'GetProperty', $null, $_, $null)
                    $path = $_.GetType().InvokeMember("ADsPath", 'GetProperty', $null, $_, $null)

                    if ($path -like "*/$system/*") {
                        $Type = "Local"
                        $name = "$system\$name"
                    }
                    else {
                        $Type = "Domain"
                        $name = "$Env:USERDOMAIN\$name"
                    }

                    $object | Add-Member -Name Account -Value $Name -MemberType NoteProperty -Force
                    $object | Add-Member -Name Class -Value $class -MemberType NoteProperty -Force
                    $object | Add-Member -Name Group -Value $GroupName -MemberType NoteProperty -Force
                    $object | Add-Member -Name Path -Value $Path -MemberType NoteProperty -Force
                    $object | Add-Member -Name Type -Value $Type -MemberType NoteProperty -Force

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
} # End Get-nCSLocalGroupMembership