#  Copyright (c) nOsliw Solutions. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

Function Get-nCSProcess {
    <#
	.SYNOPSIS
        Get processes

    .DESCRIPTION
        Get processes

    .PARAMETER SystemName
        Describes the system names(s)
		Default is localhost

	.Parameter ProcessName
		Name of the ProcessName. If not entered, all processes will be showed

	.Parameter ProcessId
		Number of the ProcessId

    .Parameter VirtualSizeMax
		Value on maximal virtual memory size in KB

    .EXAMPLE
		Get-nCSProcess

		Result
		-----------
		...

		Description
		-----------
		Get the Administrators group membership for the localhost

	.EXAMPLE
		Get-nCSProcess -ComputerName SERVER01 -ProcessName "Notepad.exe"

		Result
		-----------
		...

		Description
		-----------



	.OUTPUTS
		PSCustomObject

	.LINK


#>
    [CmdletBinding()]
    param(
        [Alias('Computer', 'ComputerName', 'System')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [string[]] $SystemName = @($env:COMPUTERNAME),

        [Alias('Name')]
        [string] $ProcessName = "*",

        [Alias('PID')]
        [ValidateRange(0, 9999)]
        [int] $ProcessID,

        [Alias('VM')]
        [int32] $VirtualSizeMax = 100,

        [string] $LocalUser = $__username,
        [string] $LocalPass,

        [string] $LPP = "#"
    )
    BEGIN {
        if (!$__nPSMS.Settings.IsCSLoaded) {Initialize-nCS}
        Write-Verbose -Message "$LPP Entering $($MyInvocation.MyCommand)"

        $i = 1

        $SystemName = $SystemName -match "[^ \t]+" # removes empty cells
        $SystemName = $SystemName | Sort-Object -Unique
        $len = ($SystemName | Measure-Object).Count

        $ProcessName = $ProcessName -replace "\*", "%"

        $Headers = @("DateTimeStamp", "Environment", "SystemName", "SystemNameFQDN", "IPV4Address", "Company", "ProductVersion", "ProcessOwner", "ProcessOwnerSid", "ProcessName", "ProcessId", "ParentProcessId", "ProcessState", "SessionId", "Priority", "CreatedDate", "Status", "TerminationDate", "Processor", "Handles", "PageFaults", "PageFileUsage", "PeakVirtualSize", "PeakWorkingSetSize", "VirtualSize", "WorkingSetSize", "OperatingSystem", "WindowsVersion", "ImageName", "ImagePath", "ExecutablePath", "CommandLine", "IndexNumber")
        $ProcessIDStr = ""
        if ($ProcessID) {
            $ProcessIDStr = "and ProcessId='$ProcessID'"
        }
        $Query = "Select * from Win32_Process where Name like '%$ProcessName%' and VirtualSize > '$VirtualSizeMax' $ProcessIDStr"
        [int]$IndexNumber = -1

        $Credential = $__nPSMS.__CSGetCredential($LocalUser, $LocalPass)
    }
    PROCESS {
        try {
            forEach ($system in $SystemName) {
                $c = "$i($len)"; $i++
                if ([String]::IsNullOrEmpty($system)) { continue }
                Write-Verbose -Message "$LPP# $c Processing system=$system"
                if (($Ping = Test-Connection -ComputerName $system -count 1 -Delay 2 -BufferSize 256 -ErrorAction 0) -eq $Null) {
                    Write-Verbose -Message "$LPP## System=$system - Unable to make a network connection"
                    #Log -noDateTime
                    continue
                }
                if ($__nPSMS.__CSIsDomainMember($system)) {
                    $wObject = Get-WmiObject -ComputerName $system -Query $Query -Locale "MS_409" -Namespace "root\cimv2" -ErrorVariable ErrorVariable -ErrorAction SilentlyContinue # Do not work locally. -Authority "ntlmdomain:$Domain"
                    $IsDomainSystem = $True
                    $IPV4Address = $Ping.IPV4Address.IPAddressToString
                }
                else {
                    Write-Verbose -Message "$LPP# Making connection to a system not part of domain. Hold on.."
                    if ($Credential -eq $null) {
                        if ($__nPSMS.IsInteractive) {
                            $Credential = Get-Credential -Message "Enter credentials to local system=$system" -UserName "$system\"
                        }
                        else {
                            Write-Verbose -Message "$LPP## Parameter LocalUser and LocalPass must entered for system=$system (not part of domain)"
                            continue
                        }
                    }

                    $wObject = Get-WmiObject -ComputerName $system -Query $Query -Locale "MS_409" -Namespace "root\cimv2" -Credential $Credential -Authority "ntlmdomain:$system" -ErrorVariable ErrorVariable -ErrorAction SilentlyContinue # Do not work locally. -Authority "ntlmdomain:$Domain"
                    $IsDomainSystem = $False
                    $IPV4Address = $system
                    # Needs to do this since SYSTEM fails inspite ErrorActionPreference = Continue
                    $HasNetUse = try {Test-Path -Path "\\$system\admin$" -PathType Container -ErrorAction SilentlyContinue} catch {$False}
                    if (!$HasNetUse) {
                        $LocalUser = $Credential.Username -replace ".+\\"
                        $LocalPass = $__nPSMS.__ConvertSecureString($Credential.Password)
                        $tmp = cmd /c net use \\$system\admin$ /user:$system\$LocalUser $LocalPass /persistent:no
                        $__nPSMS.DoCmdOnRemove += "net use \\$system\admin`$ /del"
                    }
                }
                if ($wObject -eq $null) {
                    if ($ErrorVariable.Count -gt 0) {
                        Write-Verbose -Message "$LPP## System=$system - Unable to make a WMi connection or the RPC server is unavailable"
                    }
                    continue
                }
                $wObject | ForEach-Object `
                    -Begin {
                    $DateTimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                } `
                    -Process {
                    Write-Verbose -Message "$LPP## Processing process=$($_.ProcessId)"

                    $owner = $_.GetOwner()
                    $OperatingSystem = $_.OSName.Split("|")[0]
                    $CreatedDate = Get-Date -Date ([Management.ManagementDateTimeConverter]::ToDateTime($_.CreationDate)) -Format "yyyy-MM-dd HH:mm:ss"
                    #$ImagePath = $_.ExecutablePath -replace "(.+\.(exe|cmd|bat|com))(.+)",'$1'  -replace """"
                    if (($ImagePath = $_.ExecutablePath -replace """") -ne "") {
                        $ImagePath = $ImagePath.Substring(0, $ImagePath.IndexOf(".exe") + 4)
                    }
                    $ImageName = ""
                    $Company = ""
                    $ProductVersion = ""
                    if (![string]::IsNullOrEmpty($ImagePath)) {
                        $ImagePathUNC = "\\$system\" + ($ImagePath -replace "([a-z]):", '$1$')
                        $ImageName = $ImagePath -replace ".+\\"
                        $Item = Get-ItemProperty -Path $ImagePathUNC
                        $Company = $Item.VersionInfo.CompanyName
                        $ProductVersion = $Item.VersionInfo.ProductVersion
                    }
                    $_ | Add-Member -MemberType NoteProperty -Name DateTimeStamp     -Value $DateTimeStamp
                    $_ | Add-Member -MemberType NoteProperty -Name SystemName        -Value $_.CSName
                    $_ | Add-Member -MemberType NoteProperty -Name SystemNameFQDN    -Value ($_.CSName + ".$__userdnsdomain")
                    $_ | Add-Member -MemberType NoteProperty -Name IPV4Address       -Value $IPV4Address
                    $_ | Add-Member -MemberType NoteProperty -Name Company           -Value $Company
                    $_ | Add-Member -MemberType NoteProperty -Name ProductVersion    -Value $ProductVersion
                    $_ | Add-Member -MemberType NoteProperty -Name ImageName         -Value $ImageName
                    $_ | Add-Member -MemberType NoteProperty -Name ImagePath         -Value $ImagePath
                    $_ | Add-Member -MemberType NoteProperty -Name ProcessOwner      -Value ($owner.Domain + "\" + $owner.User)
                    $_ | Add-Member -MemberType NoteProperty -Name ProcessOwnerSid   -Value $_.GetOwnerSid().Sid
                    $_ | Add-Member -MemberType NoteProperty -Name CreatedDate       -Value $CreatedDate
                    $_ | Add-Member -MemberType NoteProperty -Name Processor         -Value "0.00 %"
                    $_ | Add-Member -MemberType NoteProperty -Name OperatingSystem   -Value $OperatingSystem
                    $_ | Add-Member -MemberType NoteProperty -Name IndexNumber       -Value ($IndexNumber = $IndexNumber + 1)

                    $object = $_ | Select-Object -Property $Headers

                    Add-Member -InputObject $object -MemberType ScriptMethod -Name _UpdateProcessor -Value {
                        param(
                            [System.Management.ManagementBaseObject] $Process,
                            [System.Management.Automation.PSCredential] $Credential
                        )
                        $ipaddress = $this.IPV4Address
                        $system = $this.SystemName
                        $pid = $this.ProcessId

                        if ($this.Status -eq "Stopped") {return "0.00 %"}
                        $Query = "Select KernelModeTime,UserModeTime from Win32_Process where ProcessId=$pid"
                        if (!$Credential) {
                            if ($Process -eq $Null) {
                                $Process = Get-WmiObject -ComputerName $system -Query $Query -ErrorAction 0
                            }

                            $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $system -ErrorAction 0
                            $np = if ($os.Version -match "^5\.2\.|^5\.1\.") {"NumberOfProcessors"} else {"NumberOfLogicalProcessors"}
                            $NumberOfLogicalProcessors = (Get-WmiObject -Class Win32_ComputerSystem -ComputerName $system -ErrorAction 0)."$np"
                        }
                        else {
                            if ($Process -eq $Null) {
                                $Process = Get-WmiObject -ComputerName $ipaddress -Query $Query -Credential $Credential -Authority "ntlmdomain:$system"
                            }

                            $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ipaddress -Credential $Credential -Authority "ntlmdomain:$system" -ErrorAction 0
                            $np = if ($os.Version -match "^5\.2\.|^5\.1\.") {"NumberOfProcessors"} else {"NumberOfLogicalProcessors"}
                            $NumberOfLogicalProcessors = (Get-WmiObject -Class Win32_ComputerSystem -ComputerName $ipaddress -Credential $Credential -Authority "ntlmdomain:$system")."$np"
                        }

                        $VirtualUptime = [TimeSpan]([DateTime]::Now - [System.Management.ManagementDateTimeconverter]::ToDateTime($os.LastBootUpTime))
                        try {
                            for ($i = 0; $i -lt $NumberOfLogicalProcessors; $i++) {$VirtualUptime += $VirtualUptime}
                        }
                        catch {}
                        $ProcessorTime = [TimeSpan]::FromSeconds(($Process.KernelModeTime + $Process.UserModeTime) / 10000000) # 100 nanoseconds
                        $Percentage = "{0:p}" -f ($ProcessorTime.TotalSeconds / $VirtualUptime.TotalSeconds)

                        $this.Processor = $Percentage
                        $this.Processor
                    }
                    $object._UpdateProcessor($_) | Out-Null

                    Add-Member -InputObject $object -MemberType ScriptMethod -Name _TerminateProcess -Value {
                        $comp = $this.SystemName
                        $pid = $this.ProcessId
                        $Result = -1
                        if ($this.ProcessState -eq "Terminated") {return 0}
                        $obj = Get-WmiObject -ComputerName $comp -Query "Select ProcessId from Win32_Process where ProcessId='$pid'" -ErrorAction 0
                        if ($obj -ne $null) {
                            $Result = ($obj.Terminate()).ReturnValue
                            if ($Result -eq 0) {
                                $this.ProcessState = "Terminated"
                                $this.TerminationDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                            }
                        }
                        return $Result
                    }

                    Write-Output -InputObject $object
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
} # End Get-nCSProcess