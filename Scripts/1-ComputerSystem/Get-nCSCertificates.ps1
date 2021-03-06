#  Copyright (c) nOsliw Solutions. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

Function Get-nCSCertificates
{
	<#
	.SYNOPSIS
        Retrieves the certificates on systems

    .DESCRIPTION
        Retrieves the certificates on systems
		Outputs a CSV and HTM file

    .PARAMETER SystemName
        Describes the system names(s)
		Default is localhost
	
	.PARAMETER OutFile
		Export result to CSV file
		Default is $__eCsvFileRandomDFS
	
	.PARAMETER CertPaths
		Certification paths 
		Default is: @("My","TrustedPeople","CA","Trust","Root","AuthRoot")
		
	.PARAMETER LPP
		Log progess prefix. Default is '#'


    .EXAMPLE
		Get-nCSCertificates 

		Result
		-----------
		...

		Description
		-----------
		Retrieves all certificates for production envinronment
		
	.OUTPUTS
		

    .LINK

#>
	[CmdletBinding()]
	param(
		[Alias('Computer','ComputerName','System')]
		[Parameter(ValueFromPipelineByPropertyName=$true,ValueFromPipeline=$true)]
		[string[]] $SystemName = $env:COMPUTERNAME,
		[ValidateScript({$_ -match "\.csv$"})]
		[string[]] $CertPaths = @("My","TrustedPeople","CA","Trust","Root","AuthRoot"),
		
		[string] $LPP = "#"
	)
	BEGIN{
		if(!$__nPSMS.Settings.IsCSLoaded){Initialize-nCS}
		Write-Verbose -Message "$LPP Entering $($MyInvocation.MyCommand)"
		
		$Headers = @("SystemName","PSCertificatePath","FriendlyName","SubjectShort","NotAfter","NotBefore","ExpireInDays","Thumbprint","Issuer","Subject","SendAsTrustedIssuer","Archived","HasPrivateKey","SerialNumber","SignatureName","ProviderName","Exportable","PrivateKeySize","PrivateKeyAlgorithm")
		
		#$certpaths = $("My","TrustedPeople","CA","Trust","Root","AuthRoot")
		#$certpaths = $("My","TrustedPeople","CA","Trust","Root","AuthRoot")
		
		$SystemName = $SystemName -match "[^ \t]+" # removes empty cells
		$SystemName = $SystemName | Sort-Object -Unique
		$len = ($SystemName | Measure-Object).Count
		
		$i = 1
	}
	PROCESS{
		try{
			forEach ($system in $SystemName){
				$c = "$i($len)";$i++
				Write-Verbose -Message "$LPP# $c Processing system=$system"
				if(-not (Test-Connection -ComputerName $system -count 1 -Delay 2 -BufferSize 256 -Quiet)){
					Write-Verbose -Message "$LPP## Unable to make a network connection to system=$system"
                    continue
                }
				
				ForEach($certpath in $certpaths){
					Write-Verbose -Message "$LPP## Getting remote X509 Certificates on $system::LocalMachine\$certpath"
					try{
						$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("\\$system\$certpath","LocalMachine")
						$store.open("ReadOnly")
					}
					catch [Exception] {
						Write-Error -Exception $_ -Message "Certificates connection for LocalMachine\$certpath' was denied on $system"
						continue
					}
					# This must convert an array even if its one object
					[array] $array_object = $store.certificates | Select-Object -Property *
					if($array_object -eq $Null){ continue }
					<#
EnhancedKeyUsageList : {}
DnsNameList          : {}
SendAsTrustedIssuer  : False
Archived             : False
Extensions           : {System.Security.Cryptography.Oid, System.Security.Cryptography.Oid, System.Security.Cryptography.Oid
                       , System.Security.Cryptography.Oid...}
FriendlyName         :
IssuerName           : System.Security.Cryptography.X509Certificates.X500DistinguishedName
NotAfter             : 18.03.2015 13:56:02
NotBefore            : 18.03.2013 13:56:02
HasPrivateKey        : True
PrivateKey           : System.Security.Cryptography.RSACryptoServiceProvider
PublicKey            : System.Security.Cryptography.X509Certificates.PublicKey
RawData              : {48, 130, 4, 229...}
SerialNumber         : 00CAEF
SubjectName          : System.Security.Cryptography.X509Certificates.X500DistinguishedName
SignatureAlgorithm   : System.Security.Cryptography.Oid
Thumbprint           : 3F0360A9114BD7561B91799DC3DEAD9C1AED5070
Version              : 3
Handle               : 671525856
Issuer               : CN=DnB NOR ASA PKI Class G, O=DnB NOR ASA 981276957, C=NO
Subject              : CN=ERFTS997.ERF01.NET, OU=OtherTS, OU=Pol2008R2Ver1, OU=Win2008R2, O=DnB NOR ASA 981276957, C=NO
ExpireInDays         : 521

					#>

					for($j = 0; $j -lt $array_object.Count; $j++){
						$object = $array_object[$j]
						$ExpireInDays = ($object.NotAfter - (Get-Date)).Days
						$NotAfterStr  = Get-Date -Date $object.NotAfter  -Format "yyyy-MM-dd HH:mm:ss"
						$NotBeforeStr = Get-Date -Date $object.NotBefore -Format "yyyy-MM-dd HH:mm:ss"
						$SubjectShort = $object.Subject + "," # Must have a ',' in case comma is not in Subject
						$SubjectShort = $SubjectShort.Substring(0,$SubjectShort.IndexOf(",")) + "..."
						$IssuerShort  = $object.Issuer + "," # Must have a ',' in case comma is not in Subject
						$IssuerShort  = $IssuerShort.Substring(0,$IssuerShort.IndexOf(",")) + "..."

						Write-Verbose -Message "$LPP### Getting Subject='$SubjectShort' Issuer='$IssuerShort'"

						if($object.PrivateKey -eq $Null){
							$ProviderName        = "N/A"
							$Exportable          = $False
							$PrivateKeySize      = 0
							$PrivateKeyAlgorithm = "N/A"
						}
						else{
							$ProviderName        = $object.PrivateKey.CspKeyContainerInfo.ProviderName
							$Exportable          = $object.PrivateKey.CspKeyContainerInfo.Exportable
							$PrivateKeySize      = $object.PrivateKey.KeySize
							$PrivateKeyAlgorithm = $object.PrivateKey.KeyExchangeAlgorithm
						}

						if($ExpireInDays -le 0){
							Write-Verbose -Message "$LPP### The certificate on system=$system has been expired since $($ExpireInDays*-1) days "
						}
						elseif($ExpireInDays -lt 45){
							Write-Verbose -Message "$LPP### The certificate will Expire in $ExpireInDays days"
						}

						$object | Add-Member -MemberType NoteProperty -Name "PSCertificatePath" -Value "LocalMachine\$certpath" -Force
						$object | Add-Member -MemberType NoteProperty -Name "SystemName" -Value "$system" -Force
						$object | Add-Member -MemberType NoteProperty -Name "SignatureName" -Value $object.SignatureAlgorithm.FriendlyName -Force
						$object | Add-Member -MemberType NoteProperty -Name "ProviderName" -Value $ProviderName -Force
						$object | Add-Member -MemberType NoteProperty -Name "Exportable" -Value $Exportable -Force
						$object | Add-Member -MemberType NoteProperty -Name "PrivateKeySize" -Value $PrivateKeySize -Force
						$object | Add-Member -MemberType NoteProperty -Name "PrivateKeyAlgorithm" -Value $PrivateKeyAlgorithm -Force
						$object | Add-Member -MemberType NoteProperty -Name "ExpireInDays" -Value $ExpireInDays -Force
						$object | Add-Member -MemberType NoteProperty -Name "SubjectShort" -Value $SubjectShort -Force
						$object | Add-Member -MemberType NoteProperty -Name "NotAfter" -Value $NotAfterStr -Force
						$object | Add-Member -MemberType NoteProperty -Name "NotBefore" -Value $NotBeforeStr -Force

						$object | Select-Object -Property $Headers
					}
				}
			}
		}
		catch [Exception] {
			Write-Error -Exception $_
		}
	}
	END{
		Write-Verbose -Message "$LPP Exiting $($MyInvocation.MyCommand)"
	}
} # End Get-nCSCertificates