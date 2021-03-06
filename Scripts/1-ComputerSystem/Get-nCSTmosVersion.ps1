#  Copyright (c) nOsliw Solutions. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

Function Get-nCSTmosVersion {
    <#
	.SYNOPSIS
        Retrieves the Trend OfficeScan Client file version info on systems

    .DESCRIPTION
		Retrieves the Trend OfficeScan Client file version info on systems
		Outputs to CSV and HTM file

	.PARAMETER SystemName
        Describes the system names(s)
		Default is localhost

    .PARAMETER ReferenceName
        Describes a reference OfficeScan client computer to use
		Default is localhost

	.PARAMETER LPP
		Log progess prefix. Default is '#'

    .EXAMPLE
		Get-nCSTmosVersion

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
        [string] $ReferenceName = $env:COMPUTERNAME,
        [ValidateScript( {$_ -match "\.csv$"})]
        [string] $LPP = "#"
    )
    BEGIN {
        if (!$__nPSMS.Settings.IsCSLoaded) {Initialize-nCS}
        Write-Verbose -Message "$LPP Entering $($MyInvocation.MyCommand)"

        $SystemName = $SystemName | Sort-Object -Unique
        $len = $SystemName.Length

        $Headers = @("Environment", "System", "Name", "FileSize", "FileVersion", "FileDescription", "FileFolder", "FileType", "CreationTime", "LastAccessTime", "LastWriteTime", "Company", "DateTimeDataInput")

        Write-Verbose -Message "$LPP# Getting Trend Office Scan Client info using reference server $ReferenceName"

        $localpath = "C$\Program Files (x86)\Trend Micro\OfficeScan Client"
        if (!(Test-Path -Path "\\$ReferenceName\$localpath" -PathType Container)) {
            Write-Error -Message "OfficeScan Client on $ReferenceName. Please verify \\$ReferenceName\$localpath"
            break
        }
        # VirusPattern changes extension. The last file in the list is the newest.
        $virusPattern = (Get-ChildItem "\\$ReferenceName\$localpath\lpt*" | Select-Object -Property Name -Last 1).Name
        # intelliTrapExceptionPattern changes extension. The last file in the list is the newest.
        $intelliTrapExceptionPattern = (Get-ChildItem "\\$ReferenceName\$localpath\Tmwhite.*" | Select-Object -Property Name -Last 1).Name

        [array] $Files = @("$localpath\PccNtMon.exe", "$localpath\VsapiNT.sys", "$localpath\$virusPattern", "$localpath\ssapiptn.da6", "$localpath\$intelliTrapExceptionPattern")
        $DateTimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $i = 1
    }
    PROCESS {
        try {
            forEach ($system in $SystemName) {
                if ([String]::IsNullOrEmpty($system)) { continue }
                $c = "$i($len)"; $i++
                Write-Verbose -Message "$LPP# $c Processing system=$system"
                if (-not (Test-Connection -ComputerName $system -count 1 -Delay 2 -BufferSize 256 -Quiet)) {
                    Write-Verbose -Message "$LPP### Unable to make a network connection to system=$system. Skipping"
                    Log -noDateTime
                    continue
                }
                forEach ($File in $Files) {
                    $File = "\\$system\$File"
                    Write-Verbose -Message "$LPP## Getting Trend client version from file $File"
                    if (-not (Test-Path -Path "$File" -PathType Leaf)) {
                        Write-Verbose -Message "$LPP### Unable to locate file $File"
                        continue
                    }

                    $FileTmp = Get-Item -Path $File | Select-Object -Property VersionInfo, Name, Length, Directory, CreationTime, LastAccessTime, LastWriteTime, Extension
                    $object = New-Object -TypeName PSObject -Property @{
                        DateTimeStamp   = $DateTimeStamp
                        Environment     = $system.Substring(0, 3)
                        System          = $system
                        Name            = $FileTmp.Name
                        FileSize        = $FileTmp.Length
                        FileVersion     = $FileTmp.VersionInfo.FileVersion
                        FileDescription = $FileTmp.VersionInfo.FileDescription
                        FileFolder      = $FileTmp.Directory
                        FileType        = $FileTmp.Extension
                        CreationTime    = Get-Date -Date $FileTmp.CreationTime -Format "yyyyMMdd HH:mm:ss"
                        LastAccessTime  = Get-Date -Date $FileTmp.LastAccessTime -Format "yyyyMMdd HH:mm:ss"
                        LastWriteTime   = Get-Date -Date $FileTmp.LastWriteTime -Format "yyyyMMdd HH:mm:ss"
                        Company         = $FileTmp.VersionInfo.CompanyName
                    }
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
} # End Get-nCSTmosVersion