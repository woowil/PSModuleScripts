#  Copyright (c) nOsliw Solutions. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

Function Get-nCSService
{
	<#
	.SYNOPSIS
        Get services on system(s)

    .DESCRIPTION
        Get services on system(s)

    .PARAMETER SystemName
        Describes the system names(s)
		Default is localhost
	
	.PARAMETER ProcessName
		Name of the ProcessName. Wildcard is allowed
		Default is "*"
		
    .PARAMETER VirtualSizeMax
		Value on maximal virtual memory size in KB

    .EXAMPLE
		Get-nCSService

		Result
		-----------
		...

		Description
		-----------
		Get the Administrators group membership for the localhost

	.EXAMPLE
		Get-nCSService -ComputerName SERVER01 -ProcessName "Notepad.exe"

		Result
		-----------
		...

		Description
		-----------
		Get on the computer SERVER01

	.EXAMPLE
		Get-nCSService -ComputerName SERVER01,SERVER02 -ProcessName "Administrators"

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
	# System.Management.ManagementBaseObject 
	param(
		[Alias('Computer','ComputerName','System')]
		[Parameter(ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
		[string[]] $systemName = @($env:COMPUTERNAME),
		
		[Alias('Name')]
		[string] $ServiceName = "",
		
		[Alias('Display')]
		[string] $DisplayName = "",
		
		[Alias('Desc')]
		[string] $Description = "",
		
		[Alias('ImagePath')]
		[string] $PathName = "",
		
		[string] $LocalUser = $__username,
		[string] $LocalPass,
		
		[string] $LPP = "#"
	)
	BEGIN{
		if(!$__nPSMS.Settings.IsCSLoaded){Initialize-nCS}
		Write-Verbose -Message "$LPP Entering $($MyInvocation.MyCommand)"
		$i = 1
		$SystemName = $SystemName -match "[^ \t]+" # removes empty cells
		$SystemName = $SystemName | Sort-Object -Unique
		$len = ($SystemName | Measure-Object).Count
		
		$ServiceName = $ServiceName -replace "\*","%"
		$DisplayName = $DisplayName -replace "\*","%"
		$Header = @("DateTimeStamp","Environment","SystemName","SystemNameFQDN","IPV4Address","Company","ProductVersion","ServiceAccount","ServiceName","DisplayName","Description","Status","Started","StartMode","Processor","State","ServiceType","AcceptPause","AcceptStop","CreatedDate","DesktopInteract","ProcessId","SessionId","Memory","ImageName","ImagePath","ImagePathExist","CommandLine","IndexNumber")
		$__nPSMS.Settings.CSServiceLock = $True
		
		$Query = "Select * from Win32_Service where Name like '%$ServiceName%' and DisplayName like '%$DisplayName%' and (Description like '%$Description%' Or Description=null) and PathName like '%$PathName%' and PathName like '%:\\%'"
		[int]$IndexNumber = -1
		
		$Credential = $__nPSMS.__CSGetCredential($LocalUser,$LocalPass)
		
	}
	PROCESS{
		try{
			forEach ($system in $SystemName){
            	$c = "$i($len)";$i++
				if([String]::IsNullOrEmpty($system)){ continue }
				
				Write-Verbose -Message "$LPP# $c Processing system=$system"
				if(($Ping = Test-Connection -ComputerName $system -count 1 -Delay 2 -BufferSize 256 -ErrorAction 0) -eq $Null){
					Write-Verbose -Message "$LPP## System=$system - Unable to make a network connection"
                    #Log -noDateTime
                    continue
                }
				if($__nPSMS.__CSIsDomainMember($system)){
					$wObject = Get-WmiObject -ComputerName $system -Query $Query -Locale "MS_409" -Namespace "root\cimv2" -ErrorVariable ErrorVariable -ErrorAction SilentlyContinue # Do not work locally. -Authority "ntlmdomain:$Domain" 
					$IsDomainSystem = $True
					$IPV4Address = $Ping.IPV4Address.IPAddressToString
				}
				else {
					Write-Verbose -Message "$LPP# Making connection to a system not part of domain. Hold on.."
					if($Credential -eq $null){
						if($__nPSMS.IsInteractive){
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
					$HasNetUse = try{Test-Path -Path "\\$system\admin$" -PathType Container -ErrorAction SilentlyContinue} catch {$False}
					if(!$HasNetUse){
						$LocalUser = $Credential.Username -replace ".+\\"
						$LocalPass = $__nPSMS.__ConvertSecureString($Credential.Password)					
						$tmp = cmd /c net use \\$system\admin$ /user:$system\$LocalUser $LocalPass /persistent:no
						$__nPSMS.DoCmdOnRemove += "net use \\$system\admin`$ /del"
					}
				}
				$Domain = $__userdomain
				#Write-Verbose -Message $Query 
				if($wObject -eq $null){
					if($ErrorVariable.Count -gt 0){
						Write-Verbose -Message "$LPP## System=$system - Unable to make a WMI connection or the RPC server is unavailable"
					}
					continue
				}
				$wObject | ForEach-Object `
					-Begin {
						$DateTimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
					} `
					-Process {
						Write-Verbose -Message "$LPP## Processing Service=$($_.Name)"
						Write-Verbose -Message "$LPP### Getting process information for ProcessId=$($_.ProcessId)"
						
						if($_.StartMode -eq "disabled"){
							Write-Verbose -Message "$LPP#### The service=$($_.Name) is Started=$($_.Started) and StartMode=Disabled"
						}
						
						$Query2 = "Select CreationDate,KernelModeTime,ProcessId,SessionId,UserModeTime,WorkingSetSize from Win32_Process where ProcessId=$($_.ProcessId)"
						if($IsDomainSystem){
							$WMIProcess = Get-WmiObject -ComputerName $system -Query $Query2 -Locale "MS_409" -Namespace "root\cimv2" #-Authority "ntlmdomain:$Domain"
						}
						else {
							$WMIProcess = Get-WmiObject -ComputerName $system -Query $Query2 -Locale "MS_409" -Namespace "root\cimv2" -Credential $Credential -Authority "ntlmdomain:$system"
						}
						
						#$ImagePath = $_.PathName -replace "(.+\.(exe|cmd|bat|com))(.+)",'$1' -replace """"
						# Bug: Must do this for complex and long imagepath
						$ImagePath = $_.PathName -replace """"
						$ImagePath = $ImagePath.Substring(0,$ImagePath.IndexOf(".exe")+4)
						$ImagePathUNC = "\\$system\" + ($ImagePath -replace "([a-z]):",'$1$')
						Write-Verbose -Message "$LPP### Getting version information for ImagePath=$ImagePathUNC"
						$Item = Get-ItemProperty -Path $ImagePathUNC -ErrorAction 0
						if($Item -eq $Null){
							Write-Verbose -Message "$LPP#### Unable to locate ImagePath=$ImagePathUNC"
							$Company = $Null
							$ProductVersion = $Null
							$ImagePathExist = $False
						}
						else {
							$Company = $Item.VersionInfo.CompanyName
							$ProductVersion = $Item.VersionInfo.ProductVersion
							$ImagePathExist = $True
						}
						
						if($WMIProcess.CreationDate -ne $Null){
							$CreatedDate = Get-date -Date ([Management.ManagementDateTimeConverter]::ToDateTime($WMIProcess.CreationDate)) -Format "yyyy-MM-dd HH:mm:ss"
						}
						else {
							#Log -message $ImagePathUNC
							$dt = [System.IO.File]::GetCreationTime($ImagePathUNC)
							$CreatedDate = Get-Date -Date $dt -Format "yyyy-MM-dd HH:mm:ss"
						}
						$Environment = switch -regex ($_.SystemName){
									"^P-|MSTGS" {"Production";break}
									"^Q-" {"Staging";break}
									"^D-|^TST" {"Development";break}
									"^T-" {"Test";break}
									default {$Null}
								}
						
						Write-Verbose -Message "$LPP### Adding service object member properties and sorting object"
						
						$_ | Add-Member -MemberType NoteProperty -Name DateTimeStamp     -Value $DateTimeStamp
						#$_ | Add-Member -MemberType NoteProperty -Name SystemName        -Value $_.SystemName
						$_ | Add-Member -MemberType NoteProperty -Name SystemNameFQDN    -Value ($_.SystemName + ".$__userdnsdomain")
						$_ | Add-Member -MemberType NoteProperty -Name IPV4Address       -Value $IPV4Address
						$_ | Add-Member -MemberType NoteProperty -Name Environment       -Value $Environment
						$_ | Add-Member -MemberType NoteProperty -Name Company           -Value $Company
						$_ | Add-Member -MemberType NoteProperty -Name ProductVersion    -Value $ProductVersion
						$_ | Add-Member -MemberType NoteProperty -Name SessionId         -Value $WMIProcess.SessionId
						$_ | Add-Member -MemberType NoteProperty -Name ServiceName       -Value $_.Name
						$_ | Add-Member -MemberType NoteProperty -Name CommandLine       -Value $_.PathName
						$_ | Add-Member -MemberType NoteProperty -Name ImageName         -Value ($ImagePath -replace ".+\\")
						$_ | Add-Member -MemberType NoteProperty -Name ImagePath         -Value $ImagePath
						$_ | Add-Member -MemberType NoteProperty -Name ImagePathExist    -Value $ImagePathExist
						$_ | Add-Member -MemberType NoteProperty -Name CreatedDate       -Value $CreatedDate
						$_ | Add-Member -MemberType NoteProperty -Name ServiceAccount    -Value $_.StartName
						$_ | Add-Member -MemberType NoteProperty -Name Processor         -Value "0.00 %"
						$_ | Add-Member -MemberType NoteProperty -Name Memory            -Value $WMIProcess.WorkingSetSize
						$_ | Add-Member -MemberType NoteProperty -Name IsDomainSystem    -Value $IsDomainSystem
						$_ | Add-Member -MemberType NoteProperty -Name IndexNumber       -Value ($IndexNumber = $IndexNumber + 1)
						
						$object = $_ | Select-Object -Property $Header
						
						Write-Verbose -Message "$LPP### Adding service object member methods"
						
						Add-Member -InputObject $object -MemberType ScriptMethod -Name _UpdateProcessor -Value {
							param(
								[System.Management.ManagementBaseObject] $Process,
								[System.Management.Automation.PSCredential] $Credential
							)
							$ipaddress = $this.IPV4Address
							$system = $this.SystemName
							$pid  = $this.ProcessId
							
							if($this.State -eq "Stopped"){return "0.00 %"}
							$Query = "Select KernelModeTime,UserModeTime from Win32_Process where ProcessId=$pid"
							if(!$Credential){
								if($Process -eq $Null){
									$Process = Get-WmiObject -ComputerName $system -Query $Query -ErrorAction 0
								}
								
								$os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $system -ErrorAction 0
								$np = if($os.Version -match "^5\.2\.|^5\.1\."){"NumberOfProcessors"} else {"NumberOfLogicalProcessors"}
								$NumberOfLogicalProcessors = (Get-WmiObject -Class Win32_ComputerSystem -ComputerName $system -ErrorAction 0)."$np"
							}
							else {
								if($Process -eq $Null){
									$Process = Get-WmiObject -ComputerName $ipaddress -Query $Query -Credential $Credential -Authority "ntlmdomain:$system"
								}
								
								$os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ipaddress -Credential $Credential -Authority "ntlmdomain:$system" -ErrorAction 0
								$np = if($os.Version -match "^5\.2\.|^5\.1\."){"NumberOfProcessors"} else {"NumberOfLogicalProcessors"}
								$NumberOfLogicalProcessors = (Get-WmiObject -Class Win32_ComputerSystem -ComputerName $ipaddress -Credential $Credential -Authority "ntlmdomain:$system")."$np"
							}
							
							$VirtualUptime = [TimeSpan]([DateTime]::Now - [System.Management.ManagementDateTimeconverter]::ToDateTime($os.LastBootUpTime))
							try{
								for($i = 0; $i -lt $NumberOfLogicalProcessors; $i++){$VirtualUptime += $VirtualUptime}
							}
							catch{}
							$ProcessorTime = [TimeSpan]::FromSeconds(($Process.KernelModeTime + $Process.UserModeTime) / 10000000) # 100 nanoseconds
							$Percentage    = "{0:p}" -f ($ProcessorTime.TotalSeconds / $VirtualUptime.TotalSeconds) 
							
							$this.Processor = $Percentage
							$this.Processor
						}
						if($IsDomainSystem){
							$object._UpdateProcessor($WMIProcess) | Out-Null
						}
						else{
							$object._UpdateProcessor($WMIProcess,$Credential) | Out-Null
						}
						
						Add-Member -InputObject $object -MemberType ScriptMethod -Name _GetService -Value {
							#$this
							Get-nCSService -ComputerName $this.SystemName -ServiceName $this.ServiceName
						}
						
						Add-Member -InputObject $object -MemberType ScriptMethod -Name _GetServiceByName -Value {
							param(
								[ValidateNotNullOrEmpty()]
								[string] $ServiceByWildcard = "*"
							)
							$by = $this.ServiceName
							$ByMatch = $ServiceByWildcard -replace "\*",".*" -replace "\?",".{1}" -replace "\\","\\"
							if($by -match $ByMatch){ $this}
						}
						
						Add-Member -InputObject $object -MemberType ScriptMethod -Name _GetServiceByDisplay -Value {
							param(
								[ValidateNotNullOrEmpty()]
								[string] $DisplayByWildcard = "*"
							)
							$by = $this.DisplayName
							$ByMatch = $DisplayByWildcard -replace "\*",".*" -replace "\?",".{1}" -replace "\\","\\"
							if($by -match $ByMatch){ $this}
						}
						
						Add-Member -InputObject $object -MemberType ScriptMethod -Name _GetServiceByPath -Value {
							param(
								[ValidateNotNullOrEmpty()]
								[string] $PathByWildcard = "*"
							)
							$by = $this.ImagePath
							$ByMatch = $PathByWildcard -replace "\*",".*" -replace "\?",".{1}" -replace "\\","\\"
							if($by -match $ByMatch){ $this}
						}
						
						Add-Member -InputObject $object -MemberType ScriptMethod -Name _GetServiceProcess -Value {
							$name = $this.ServiceName
							$comp = $this.SystemName
							$pid  = $this.ProcessId
							$Result = -1
							if($this.Status -eq $Null){return 0}
							Get-nCSProcess -ComputerName $comp -ProcessId $pid
						}
						
						Add-Member -InputObject $object -MemberType ScriptMethod -Name _ChangeService -Value {
							param( # https://msdn.microsoft.com/en-us/library/aa384901(v=vs.85).aspx
								[ValidateNotNullOrEmpty()]
								[string] $DisplayName,
								[ValidateScript({$_ -match "^[a-z]:.+" -and (Test-Path -Path $_ -PathType Leaf)})]
								[string] $PathName,
								[ValidateSet('1','2','4','8','16','32','256')]
								[int32]  $ServiceType,
								[ValidateRange(0,3)]
								[int32]  $ErrorControl,
								[Parameter(Mandatory=$True, HelpMessage="Enter 'Boot','System','Automatic','Manual' or 'Disabled'")]
								[ValidateSet('Boot','System','Automatic','Manual','Disabled')]
								[string] $StartMode,
								[boolean] $DesktopInteract,
								[string] $StartName, # if $NULL then LOCALSYSTEM account will be used
								[string] $StartPassword, # Specify $NULL if you are not changing password. Specify "" if changing to StartMode is LOCALSYSTEM
								[string] $LoadOrderGroup,
								[string] $LoadOrderGroupDependencies,
								[string] $ServiceDependencies
							)
							$name = $this.ServiceName
							$comp = $this.SystemName
							$Result = -1
							if($this.Status -eq $Null){return $Result}
							$obj = Get-WmiObject -ComputerName $comp -Query "Select Name from Win32_Service where Name='$name'" -ErrorAction 0
							if($obj -ne $Null){
								# $Result = ($obj.Change($DisplayName,$PathName,$ServiceType,$ErrorControl,$StartMode,$DesktopInteract,$StartName,$StartPassword,$LoadOrderGroup,$LoadOrderGroupDependencies,$ServiceDependencies).ReturnValue
								$Result = ($obj.Change($args)).ReturnValue
							}
							return $Result
						}
						
						Add-Member -InputObject $object -MemberType ScriptMethod -Name _ChangeServiceStartMode -Value {
							param(
								[Parameter(Mandatory=$True, HelpMessage="Enter 'Boot','System','Automatic','Manual' or 'Disabled'")]
								[ValidateSet('Boot','System','Automatic','Manual','Disabled')]
								[string] $StartMode
							)
							$name = $this.ServiceName
							$comp = $this.SystemName
							$Result = -1
							if($this.Status -eq $Null){return $Result}
							$obj = Get-WmiObject -ComputerName $comp -Query "Select Name from Win32_Service where Name='$name'" -ErrorAction 0
							if($obj -ne $Null){
								# https://msdn.microsoft.com/en-us/library/aa384896%28v=vs.85%29.aspx
								$Result = ($obj.ChangeStartMode($StartMode)).ReturnValue
								if($Result -eq 0){$this.StartMode = $StartMode}
							}
							return $Result
						}
						
						Add-Member -InputObject $object -MemberType ScriptMethod -Name _DeleteService -Value {
							$name = $this.ServiceName
							$comp = $this.SystemName
							$Service = $this.ServiceName
							$Result = -1
							if($this.Status -eq $Null){
								Write-Verbose -Message "[$__identity] The service=$Service is already deleted"
								return 0
							}
							if($__nPSMS.Settings.CSServiceLock){
								Write-Verbose -Message "[$__identity] _DeleteService is lock by default for security reasons. Set global property `$__nPSMS.Settings.CSServiceLock=`$False on object for system=$system, service=$Service and try again :)" -ForeGroundColor Magenta #-AppendFile $InfoFile
								return
							}
							$obj = Get-WmiObject -ComputerName $comp -Query "Select Name from Win32_Service where Name='$name'" -ErrorAction 0
							if($obj -ne $Null){
								$Result = ($obj.Delete()).ReturnValue
								if($Result -eq 0){
									$this.Status = $Null
									$this.State = "Deleted"
									$this.Started = $False
									$this.StartMode = $Null
									Write-Verbose -Message "[$__identity] The service=$Service was deleted on system=$comp. Note: verify also ImagePath=$(this.ImagePath) and registry paths"
								}
							}
							return $Result
						}
						
						Add-Member -InputObject $object -MemberType ScriptMethod -Name _PauseService -Value {
							$name = $this.ServiceName
							$comp = $this.SystemName
							$Result = -1
							if($this.Status -eq $Null){return $Result}
							if(!$this.AcceptPause){return $Result}
							if($this.State -eq "Paused") {return 0}
							if($this.State -match "Stopped|Stopping") {return $Result}
							$obj = Get-WmiObject -ComputerName $comp -Query "Select Name from Win32_Service where Name='$name'" -ErrorAction 0
							if($obj -ne $Null){
								$Result = ($obj.PauseService()).ReturnValue
								if($Result -eq 0){$this.State = "Paused";$this.Started = $True}
							}
							return $Result
						}
						
						Add-Member -InputObject $object -MemberType ScriptMethod -Name _RestartService -Value {
							
							if($this.State -eq "Paused") {$Result = $this._ResumeService()}
							$Result = $this._StopService()
							Start-Sleep -Milliseconds (Get-Random -Minimum 77 -Maximum 777)
							$Result = $this._StartService()
							
							return $Result
						}
						
						Add-Member -InputObject $object -MemberType ScriptMethod -Name _ResumeService -Value {
							$name = $this.ServiceName
							$comp = $this.SystemName
							$Result = -1
							if($this.Status -eq $Null){return $Result}
							if($this.State -ne "Paused"){return 0}
							$obj = Get-WmiObject -ComputerName $comp -Query "Select Name from Win32_Service where Name='$name'" -ErrorAction 0
							if($obj -ne $Null){
								$this.State = "Resuming"
								$Result = ($obj.ResumeService()).ReturnValue
								if($Result -eq 0){$this.State = "Running"}
								
							}
							return $Result
						}
						
						Add-Member -InputObject $object -MemberType ScriptMethod -Name _StartService -Value {
							$name = $this.ServiceName
							$comp = $this.SystemName
							$Result = -1
							if($this.Status -eq $Null){return $Result}
							if($this.State -match "Paused|Started") {return 0}
							$obj = Get-WmiObject -ComputerName $comp -Query "Select Name from Win32_Service where Name='$name'" -ErrorAction 0
							if($obj -ne $Null){
								$this.State = "Starting"
								$Result = ($obj.StartService()).ReturnValue
								if($Result -eq 0){
									$this.Started = $True
									$this.State = "Running"
								}
							}
							return $Result
						}
						
						Add-Member -InputObject $object -MemberType ScriptMethod -Name _StopService -Value {
							$name = $this.ServiceName
							$comp = $this.SystemName
							$Result = -1
							if($this.Status -eq $Null){return $Result}
							if(!$this.AcceptStop){return $Result}
							if($this.State -eq "Stopped"){return 0}
							$obj = Get-WmiObject -ComputerName $comp -Query "Select Name from Win32_Service where Name='$name'" -ErrorAction 0
							if($obj -ne $Null){
								$this.State = "Stopping"
								$Result = ($obj.StopService()).ReturnValue
								if($Result -eq 0){
									$this.Started = $False;
									$this.State = "Stopped"
								}
							}
							return $Result
						}
						
						Write-Output -InputObject $object
					} `
					-End {
						
					}
			}
		}
		catch [Exception] {
			Write-Error -Exception $_ -Message "Failed for system=$system"
		}
	}
	END{
		Write-Verbose -Message "$LPP Exiting $($MyInvocation.MyCommand)"
	}
} # End Get-nCSService