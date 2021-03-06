#  Copyright (c) nOsliw Solutions. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

Function Initialize-nCS {
    <#
	.SYNOPSIS
        Initializes Computer System methods and properties

    .DESCRIPTION
        Initializes Computer System methods and properties

	.PARAMETER Force
		Force Initialize even if its already loaded

	.PARAMETER LPP
		Log progess prefix. Default is '#'

	.EXAMPLE
		Initialize-nCS

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
        [switch] $Force,
        [string] $LPP = "#"
    )
    BEGIN {
        Write-Verbose -Message "$LPP Entering $($MyInvocation.MyCommand)"

        $__nPSMS.Settings.CSRegistry = @{}

        if (-not (Test-Path -Path "$Env:windir\System32\dsquery.exe" -PathType Leaf)) {
            Write-Verbose -Message "$LPP# Installing required: ADDS Snap-Ins and Command-Line Tools"
            cmd /c servermanagercmd.exe -install RSAT-ADDS-Tools
        }
    }
    PROCESS {
        try {

            Add-Member -InputObject $__nPSMS -MemberType ScriptMethod -Name "__GetCSRegistryValue" -Force -Value {
                param(
                    [string] $system = $__system,
                    [ValidateSet('ClassesRoot', 'CurrentUser', 'LocalMachine', 'Users', 'PerformanceData', 'CurrentConfig', 'DynData', 'HKLM', 'HKCU', 'HKCR', 'HKCC', 'HKU')]
                    [string] $Hive = "LocalMachine",
                    [Parameter(Mandatory = $true)]
                    [ValidateNotNullOrEmpty()]
                    [string] $Key,
                    [Parameter(Mandatory = $true)]
                    [ValidateNotNullOrEmpty()]
                    [string] $Value,
                    [ValidateSet("String", "DWORD", "MultiString", "Binary", "ExpandedString", 'REG_SZ', 'REG_MULTI_SZ', 'REG_EXPAND_SZ', 'REG_DWORD', 'REG_BINARY')]
                    [string] $Type = "String"
                )
                $scriptblock = {
                    param(
                        [string]$Key,
                        [string]$Value
                    )
                    Get-ChildItem -Path "HKLM:\$Key\$Value"
                }
                [uint32]$HiveInt = switch -regex ($Hive) {
                    "ClassesRoot|HKCR" {2147483648; break}
                    "CurrentUser|HKCU" {2147483649; break}
                    "LocalMachine|HKLM" {2147483650; break}
                    "Users|HKU" {2147483651; break}
                    "PerformanceData" {2147483648; break}
                    "CurrentConfig|HKCC" {2147483653; break}
                    "DynData" {2147483654; break}
                    default {2147483650}
                }

                # This statement was created to connect to the remote computer WMI registry only once
                if (!$__nPSMS.Settings.CSRegistry.ContainsKey($system)) {
                    $Registry = Get-WmiObject -List -Namespace "root\default" -ComputerName $system -ErrorAction 0 | Where-Object {$_.Name -eq "StdRegProv"}
                    if ($Registry -eq $Null) {return $null}
                    $__nPSMS.Settings.CSRegistry.Add($system, $Registry)
                }
                else {
                    $Registry = $__nPSMS.Settings.CSRegistry.Item($system)
                }
                # https://msdn.microsoft.com/en-us/library/aa390458%28v=vs.85%29.aspx
                $Result, $RegValue = switch -regex ($Type) {
                    "^String|REG_SZ" {$Registry.GetStringValue($HiveInt, $Key, $Value), "sValue"; break}
                    "DWORD|REG_DWORD" {$Registry.GetDWORDValue($HiveInt, $Key, $Value), "uValue"; break}
                    "MultiString|REG_MULTI_SZ" {$Registry.GetMultiStringValue($HiveInt, $Key, $Value), "sValue"; break}
                    "Binary|REG_BINARY" {$Registry.GetBinaryValue($HiveInt, $Key, $Value), "uValue"; break}
                    "ExpandedString|REG_EXPAND_SZ" {$Registry.GetExpandedStringValue($HiveInt, $Key, $Value), "sValue"; break}
                    default {$Registry.GetStringValue($HiveInt, $Key, $Value), "sValue"}
                }

                if ($Result.ReturnValue -ne 0) {
                    if ($Key -match "Wow6432Node") {
                        # Problems opening Win64 registry remotely from an x86 system
                        $Result = Invoke-Command -ComputerName $system -ScriptBlock $scriptblock -ArgumentList $Key, $Value -ErrorAction 0
                    }
                    else {
                        $Result = $Null
                    }
                }
                else {
                    $Result = $Result."$RegValue"
                }
                #$key1 = $key -replace "\\Wow6432Node"
                #$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]$Hive,$system)
                # if($reg -ne $Null){
                # if(($subKey = $reg.OpenSubKey($Key,$true)) -ne $Null){
                # $Result = $subKey.GetValue($Value)
                # $subKey.close()
                # }
                # }

                return $Result
            }

            Add-Member -InputObject $__nPSMS -MemberType ScriptMethod -Name "__CSIsDomainMember" -Force -Value {
                param(
                    [string] $system = $Env:ComputerName,
                    [string] $domain = $Env:UserDomain
                )
                $ErrorActionPreferenceOrg = $ErrorActionPreference
                $ErrorActionPreference = "Continue"

                $matchIP = "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
                if ($system -match $matchIP) {
                    $system_ns = nslookup $system 2>$null | Select-String -Pattern "Name:"
                    if ($system_ns -ne $null) {
                        $system = $system_ns -replace "[ \t]+|name:"
                        return $this.__CSIsDomainMember($system)
                    }
                    $system_ping = ping -a $system  2>$null | Select-String -Pattern "Pinging"
                    if ($system_ping -ne $null) {
                        $system = $system_ping.toString().split(" ")[1]
                        return $this.__CSIsDomainMember($system)
                    }
                }
                $system = $system -replace "([^.]+)\..+", '$1' # removes %userdnsdomain%
                $searcher = [adsisearcher] "(&(objectclass=computer)(name=$system))"
                $result = $searcher.FindOne()
                $ErrorActionPreference = $ErrorActionPreferenceOrg
                return ($result -ne $null)
            }

            Add-Member -InputObject $__nPSMS -MemberType ScriptMethod -Name "__CSGetCredential" -Force -Value {
                param(
                    [string] $username,
                    [string] $password
                )
                if ([string]::IsNullOrEmpty($username) -or [string]::IsNullOrEmpty($password)) {return $null}
                $passwordsec = (ConvertTo-SecureString -String $password -AsPlainText -Force)
                $cred = new-object -typename System.Management.Automation.PSCredential `
                    -argumentlist $username, $passwordsec

                return $cred
            }

            Add-Member -InputObject $__nPSMS -MemberType ScriptMethod -Name "__CSGetDefaultBrowser" -Force -Value {
                $name = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice').Progid
                $name = switch -regex ($name) {
                    "IE\.HTTP" {"Internet Explorer"; break}
                    "FirefoxURL" {"Firefox"; break}
                    "ChromeHTML" {"Chrome"; break}
                    "Max3\.Association.HTML" {"Maxthon"; break}
                    "Opera" {"Opera"; break}
                    "Safari" {"Safari"; break}
                    default {$name}
                }
                return $name
            }

            Add-Member -InputObject $__nPSMS -MemberType ScriptMethod -Name "__CSSetDefaultBrowser" -Force -Value {
                param(
                    [string] $name
                )
                $Ftp, $Http, $Https = switch -regex ($name) {
                    "Internet Explorer|IE" {"IE.FTP", "IE.HTTP", "IE.HTTPS"; break}
                    "Firefox|FF" {"FirefoxURL", "FirefoxURL", "FirefoxURL"; break}
                    "Chrome" {"ChromeHTML", "ChromeHTML", "ChromeHTML"; break}
                    "Maxthon" {"Max3.Association.HTML", "Max3.Association.HTML", "Max3.Association.HTML"; break}
                    default {$null, $null, $null}
                }
                if ($Http -ne $null) {
                    Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\ftp\UserChoice' -Name ProgId $Ftp
                    Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice' -Name ProgId $Http
                    Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice' -Name ProgId $Https
                }
            }

            Add-Member -InputObject $__nPSMS -MemberType ScriptMethod -Name "__IsCSIPPortOpened" -Force -Value {
                param(
                    [string] $IP,
                    [int] $Port,
                    [int] $Wait = (Get-Random -Minimum 127 -Maximum 1777)
                )
                $client = New-Object Net.Sockets.TcpClient
                $Connection = $client.BeginConnect($IP, $port, $Null, $Null)
                $TimeOut = $Connection.AsyncWaitHandle.WaitOne($Wait, $False)
                if (!$TimeOut) {$client.Close()}
                return ($TimeOut -ne $Null)
            }

            Add-Member -InputObject $__nPSMS -MemberType ScriptMethod -Name "__GetCSExtensionDescription" -Force -Value {
                param(
                    [string] $Extension
                )
                try {
                    $desc = $Extension -replace "\."
                    $desc = $desc.toUpper() + " File"
                    $desc = $desc -replace "\."
                    $desc = (cmd /c assoc ".$Extension").Split("=")[1]
                    $desc = (cmd /c assoc $desc).Split("=")[1]
                }
                catch {} # File association not found for extension .war
                return $desc
            }

            Add-Member -InputObject $__nPSMS -MemberType ScriptMethod -Name "__CSGetScheduleTasks" -Force -Value {
                param(
                    [string[]] $system = @("$Env:computername")
                )

                ForEach ($s in $system) {
                    if (!$__taskschedular.ContainsKey($s)) {
                        $__taskschedular.Add($s, $null)
                        $tmp = cmd /c schtasks.exe /s $s /query /v /fo csv |
                            ConvertFrom-Csv -Delimiter "," |
                            Where-Object { $_.TaskName -ne 'TaskName' } |
                            Sort-Object TaskName
                        $__taskschedular.Item($s) = $tmp
                    }
                    Write-Output -InputObject $__taskschedular.Item($s)
                }
            }

            # Add-Member -InputObject $__nPSMS -MemberType ScriptMethod -Name "__CSGetDFSTarget" -Force -Value {
            # param(
            # [string] $DFSFolder
            # )
            # if([string]::IsNullOrEmpty($DFSFolder)){return $null}
            # if($DFSFolder -match $__userdomain -and (Test-Path -Path $DFSFolder -PathType Container)){
            # $Viewdfspath = cmd /c dfsutil diag Viewdfspath $DFSFolder | select-string "resolve"
            # $DFSTarget = $Viewdfspath.ToString().Trim() -replace "(.+)<([a-z0-9\-.\\]+)>$",'$2'
            # return $DFSTarget
            # }
            # return $null
            # }

            Add-Member -InputObject $__nPSMS -MemberType ScriptMethod -Name "__CSGetDFSTarget" -Force -Value {
                param (
                    [string[]] $DFSFolder
                )
                $result = @()

                ForEach ($f in $DFSFolder) {
                    if ($f -match $__userdnsdomain -and (Test-Path -Path $f -PathType Container)) {
                        $r = cmd /c dfsutil.exe diag viewdfspath $f | Select-string -Pattern "\\\\"
                        $r = $r.ToString().trim() `
                            -replace ".+-> <|>$" `
                            -replace "›", "ø" `
                            -replace "‘", "æ" `
                            -replace "†", "å" `
                            -replace "", "Ø"
                        $result += $r
                    }
                    else {
                        Write-Verbose -Message "__CSGetDFSTarget: Unable to locate DFS folder $f"
                        $result += ""
                    }
                }
                return $result
            }

            $__nPSMS.Settings.IsCSLoaded = $True
        }
        catch [Exception] {
            Write-Error -Exception $_
        }
    }
    END {
        Write-Verbose -Message "$LPP Exiting $($MyInvocation.MyCommand)"
    }
}
