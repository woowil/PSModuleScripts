#  Copyright (c) nOsliw Solutions. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

Function Get-nCSPendingReboot
{
	<#
	.SYNOPSIS
        Gets the pending reboot status on a local or remote computer.

    .DESCRIPTION
        This function will query the registry on a local or remote computer and determine if the
		system is pending a reboot, from either Microsoft Patching or a Software Installation.
		For Windows 2008+ the function will query the CBS registry key as another factor in determining
		pending reboot state.  "PendingFileRenameOperations" and "Auto Update\RebootRequired" are observed
		as being consistant across Windows Server 2003 & 2008.

		CBServicing = Component Based Servicing (Windows 2008)
		WindowsUpdate = Windows Update / Auto Update (Windows 2003 / 2008)
		PendFileRename = PendingFileRenameOperations (Windows 2003 / 2008)

	.PARAMETER SystemName
        Describes the system names(s)
		Default is localhost

	.PARAMETER ADGroupName
		Describes the an AD Group containing servers

	.PARAMETER LPP
		Log progess prefix. Default is '#'

    .EXAMPLE
		Get-nCSPendingReboot

		Result
		-----------
		...

		Description
		-----------
		The Description..

	.EXAMPLE
		Get-nCSPendingReboot -SystemName FILESERVER

		Result
		-----------
		...

		Description
		-----------
		The Description..

	.OUTPUTS


	.LINK
         Component-Based Servicing:
		http://technet.microsoft.com/en-us/library/cc756291(v=WS.10).aspx

		PendingFileRename/Auto Update:
		http://support.microsoft.com/kb/2723674
		http://technet.microsoft.com/en-us/library/cc960241.aspx
		http://blogs.msdn.com/b/hansr/archive/2006/02/17/patchreboot.aspx

	.LINK

	#>

	[CmdletBinding()]
	param(
		[Alias('DnsHostName','__SERVER','IPAddress','Computer','ComputerName','System')]
		[Parameter(ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
		[string[]] $SystemName = @($Env:COMPUTERNAME),

		[string] $ADGroupName,
		[string] $LPP = "#"
	)
	BEGIN{
		if(!$__nPSMS.Settings.IsCSLoaded){Initialize-nCS}
		Write-Verbose -Message "$LPP Entering $($MyInvocation.MyCommand)"

		$SystemName = $SystemName -match "[^ \t]+" # removes empty cells
		if($ADGroupName){
			Write-Verbose -Message "$LPP# Getting servers from AD group=$ADGroupName*"
			$tmp = dsquery group -name $ADGroupName* | dsget group -members -c 2>$null | dsget computer -samid -c 2>$null | Select-String -Pattern "-114"
			if($tmp -ne $null){
				$SystemName += $tmp -replace "[ \t$]+"
			}
		}
		$SystemName = $SystemName | Sort-Object -Unique
		$len = ($SystemName | Measure-Object).Count
		$i = 1


		$Headers = @("DateTimeStamp","HostName","SystemName","NetworkConnection","RemoteProcedureCall","ComponentBasedServicing","WindowsUpdate","CCMClientVersion","CCMClientUtilities","CCMClientRebootDeadline","FileRename","FileRenameOperations","PendingReboot","LastBootUpTime","LastBootUpDays","Comments")

		$RegkeyAutoUpdate     = "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
		$RegkeySessionManager = "SYSTEM\CurrentControlSet\Control\Session Manager"
		$RegkeyComponentBasedServicing = "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing"
		[uint32]$HiveHKLM = 2147483650

		$ouputblock = {
			$i = 0
			$object = New-Object -TypeName PSObject -Property @{
				DateTimeStamp           = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
				HostName                = $__system
				SystemName              = $args[$i++]
				NetworkConnection       = $args[$i++]
				RemoteProcedureCall     = $args[$i++]
				ComponentBasedServicing = $args[$i++]
				WindowsUpdate           = $args[$i++]
				CCMClientVersion        = $args[$i++]
				CCMClientUtilities      = $args[$i++]
				CCMClientRebootDeadline = $args[$i++]
				FileRename              = $args[$i++]
				FileRenameOperations    = $args[$i++]
				PendingReboot           = $args[$i++]
				LastBootUpTime          = $args[$i++]
				LastBootUpDays          = $args[$i++]
				Comments                = $args[$i++]
			}
			$object = $object | Select-Object -Property $Headers
			$object
		}
	}
	PROCESS{
		try{
			forEach($system in $SystemName){
				$c = "$i($len)";$i++
				if([String]::IsNullOrEmpty($system)){ continue }

				$ComponentBasedServicing = $False
				$WindowsUpdate           = $False
				$CCMClientUtilities      = $False
				$CCMClientRebootDeadline = $null
				$FileRename              = $False
				$FileRenameOperations    = $Null
				$PendingReboot           = $False
				$Comments                = ""
				$LastBootUpTime          = ""
				$LastBootUpDays          = -1
				$CCMClientVersion        = ""

				Write-Verbose -Message "$LPP# $c Processing system=$system"
				if(-not (Test-Connection -ComputerName $system -count 1 -Delay 2 -BufferSize 256 -Quiet)){
					Write-Verbose -Message "$LPP## Unable to make a network connection to $__system ==> $system"
					$Comments = "Unable to make a network ping connection $__system ==> $system"
					$object = Invoke-Command -ScriptBlock $ouputblock `
						-ArgumentList $system,$False,$False,$False,$False,$CCMClientVersion,$False,$Null,$False,$null,$False,$LastBootUpTime,$LastBootUpDays,$Comments
					Write-Output -InputObject $object
					continue
				}

				Write-Verbose -Message "$LPP## Getting UNC connection to \\$system\c$\Windows\CCM\"
				try{
					if(Test-Path -Path "\\$system\c$\Windows\CCM\SCClient.exe" -PathType Leaf){
						$CCMClientVersion = (Get-ChildItem -Path "\\$system\c$\Windows\CCM\SCClient.exe").VersionInfo.FileVersion
					}
				}
				catch {
					$message = $_.Exception.Message.toString().trim()
					Write-Verbose -Message "$LPP## Unable to make a UNC connection on \\$system\c$, reason = $message"
					$Comments = "$message on UNC connection on \\$system\c$"
					$object = Invoke-Command -ScriptBlock $ouputblock `
						-ArgumentList $system,$False,$False,$False,$False,$CCMClientVersion,$False,$Null,$False,$null,$False,$LastBootUpTime,$LastBootUpDays,$Comments
					Write-Output -InputObject $object
					continue
				}

				Write-Verbose -Message "$LPP## Making registry connection to the local/remote computer and getting pending reboot values"
				try{
					$Registry = Get-WmiObject -List -Namespace "root\default" -ComputerName $system -ErrorAction 0 | Where-Object {$_.Name -eq "StdRegProv"}
					if($Registry -eq $Null){throw "Unable to connect to registry"}
				}
				catch{
					Write-Verbose -Message "$LPP### Either RPC unavailable or unable to make a registry connection to system=$system"
					$Comments = "Either RPC unavailable or unable to make a WMI registry connection $__system ==> $system"
					$object = Invoke-Command -ScriptBlock $ouputblock `
						-ArgumentList $system,$True,$False,$False,$False,$CCMClientVersion,$False,$Null,$False,$null,$False,$LastBootUpTime,$LastBootUpDays,$Comments
					Write-Output -InputObject $object
					continue
				}

				if(($result = $Registry.EnumKey($HiveHKLM,$RegkeyAutoUpdate)).sNames -ne $Null){
					 if($result -match "RebootRequired"){
						$WindowsUpdate = $true
					 }
				}
				if(($result = ($Registry.GetMultiStringValue($HiveHKLM,$RegkeySessionManager,"PendingFileRenameOperations")).sValue) -ne $Null){
					$FileRenameOperations = $result  -match "[^ \t]+" # removes empty cells
					$FileRename = $true
				}

				Write-Verbose -Message "$LPP## Querying WMI Win32_OperatingSystem for build version"
				$OS = Get-WmiObject -ComputerName $system -Class Win32_OperatingSystem -Property BuildNumber,Caption,CSName,LastbootUptime -ErrorAction 0
				if($OS.BuildNumber -ge 6001){ # If Vista/2008 & Above query the CBS Reg Key
					if(($result = ($Registry.EnumKey($HiveHKLM,$RegkeyComponentBasedServicing)).sNames) -ne $Null){
						 if($result -match "RebootPending"){
							$ComponentBasedServicing = $true
						 }
					}

				}
				else {
					$Comments += """$($OS.Caption)"" does not support Component Based Servicing."
				}
				$system = $OS.CSName
				$LastBootUpTime = [System.Management.ManagementDateTimeconverter]::ToDateTime($OS.LastBootUpTime)
				$LastBootUpDays = (New-TimeSpan -Start $LastBootUpTime -End (get-date)).Days
				$LastBootUpTime = Get-Date -Date $LastBootUpTime -Format "yyyy-MM-dd HH:mm:ss.fff"
				$result   = $Null
				$Registry = $Null

				Write-Verbose -Message "$LPP## Determining SCCM 2012 Client Reboot Pending Status"
				try{
					#invoke-method is only available for W7/W2008R2 or higher
					$result = Invoke-WmiMethod -ComputerName $system `
						-Class "CCM_ClientUtilities" `
						-Name "DetermineIfRebootPending" `
						-EnableAllPrivileges `
						-Namespace "ROOT\ccm\ClientSDK" `
						-ErrorAction 0
				}
				catch {
					Write-Verbose -Message "$LPP### Unable to make a WSMan WMI connection to $system. PowerShell Remoting is not configured properly"
					$Comments += " PowerShell Remoting is not configured."
				}
				if($result -ne $Null -and $result.ReturnValue -eq 0){
					$IsHardRebootPending = $result.IsHardRebootPending
					if($result.IsHardRebootPending -or $result.RebootPending){
						$CCMClientUtilities = $true
					}
					$dt = [System.Management.ManagementDateTimeconverter]::ToDateTime($result.RebootDeadline)
					if($dt -is [datetime]){
						$CCMClientRebootDeadline = Get-Date -Date $dt -Format "yyyy-MM-dd HH:mm:ss.fff"
					}
				}
				else {
					$Comments += " OS=$($OS.Caption), System=$system is not a CCM 2012 client"
				}
				$PendingReboot = ($ComponentBasedServicing -or $WindowsUpdate -or $CCMClientUtilities -or $FileRename)

				$object = Invoke-Command -ScriptBlock $ouputblock `
						-ArgumentList $system,$True,$true,$ComponentBasedServicing,$WindowsUpdate,$CCMClientVersion,$CCMClientUtilities,$CCMClientRebootDeadline,$FileRename,$FileRenameOperations,$PendingReboot,$LastBootUpTime,$LastBootUpDays,$Comments.Trim()
				Write-Output -InputObject $object
			}
		}
		catch [Exception] {
			Write-Error -Exception $_ -Message "System=$system, Comments=$Comments"
		}
	}
	END{
		Write-Verbose -Message "$LPP Exiting $($MyInvocation.MyCommand)"
	}
} # End Get-nCSPendingReboot