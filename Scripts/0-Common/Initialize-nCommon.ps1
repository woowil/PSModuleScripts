#  Copyright (c) nOsliw Solutions. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

Function Initialize-nCommon {
    <#
	.SYNOPSIS
        Initializize the module

    .DESCRIPTION
        Initializize the module and set global variables

	.PARAMETER InputObject
		This is the main global variable object (__nPSMS)


	.PARAMETER LPP
		Log progess prefix. Default is '#'
		This parameter is Optional and the data type is [string]

    .EXAMPLE
		Initialize-nCommon

		Result
		-----------
		...

		Description
		-----------
		The Description..

	.OUTPUTS


	.LINK


#>
    param(
        [object] $InputObject,
        [string] $LPP = "#"
    )
    BEGIN {
        if ($InputObject.Settings.InitializedCommon) {return}
        $ErrorActionPreference = 'stop'
        Write-Verbose -Message "$LPP Entering $($MyInvocation.MyCommand)"

        if (-not (Test-Path -Path "$Env:TEMP" -PathType Container)) {
            mkdir "$Env:TEMP" -ErrorAction 0 | Out-null
        }
        $TextInfo = (Get-Culture).TextInfo

        $__nPSMS.Settings.IsADLoaded = $False
        $__nPSMS.Settings.IsCSLoaded = $False
        $__nPSMS.Settings.IsFSLoaded = $False
    }
    PROCESS {
        try {
            Write-Verbose -Message "Initializing DefaultMethods"

            Add-Member -InputObject $InputObject -MemberType ScriptMethod -Name "__SetCredInRegistry" -Force -Value {
                param(
                    [string] $User,
                    [System.Security.SecureString] $PassSec,
                    [string] $Desc = "",
                    [int] $Limit = 100
                )
                $Rootkey = "$($this.Registry.CurrentUser)\Security"
                $i = 0
                while ($true) {
                    $NameUser = "credential_" + $i + "_user"
                    $NamePass = "credential_" + $i + "_pass"
                    $NameDesc = "credential_" + $i + "_desc"
                    $ValuePass = ConvertFrom-SecureString -SecureString $PassSec

                    if (($tmp = Get-ItemProperty -Path $Rootkey -Name $NameUser -ErrorAction 0) -eq $null) {
                        Set-ItemProperty -Path $Rootkey -Name $NameUser -Value $User -Force
                        Set-ItemProperty -Path $Rootkey -Name $NamePass -Value $ValuePass -Force
                        Set-ItemProperty -Path $Rootkey -Name $NameDesc -Value $Desc -Force
                        break
                    }
                    if ($i++ > $Limit) {
                        throw "Limit credentials of $Limit has been reach"
                    }
                }
            }

            Add-Member -InputObject $InputObject -MemberType ScriptMethod -Name "__GetCredInRegistry" -Force -Value {
                param(
                    [string] $User,
                    [boolean] $SetIfNotExist = $false
                )
                $Rootkey = "$($this.Registry.CurrentUser)\Security"
                [array]$Keys = (Get-Item -Path $Rootkey).Property -match "credential_[0-9]{1,2}_user"
                for ($i = 0; $i -lt $keys.Count; $i++) {
                    $NameUser = $Keys[$i]
                    $NamePass = $NameUser -replace "user", "pass"

                    $tmp = Get-ItemProperty -Path $Rootkey -Name $NameUser -ErrorAction 0
                    if (![string]::IsNullOrEmpty($tmp) -and $tmp."$NameUser" -eq $User) {
                        $Pass = (Get-ItemProperty -Path $Rootkey -Name $NamePass)."$NamePass"
                        $Pass = ConvertTo-SecureString -String $Pass
                        $Pass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Pass))
                        return $Pass
                    }
                }
                if ($SetIfNotExist) {
                    $Cred = Get-Credential -Credential $User
                    $this.__SetCredInRegistry($User, $Cred.Password)
                    return $this.__GetCredInRegistry($User)
                }
                return $null
            }

            Add-Member -InputObject $InputObject -MemberType ScriptMethod -Name "__GetCallback" -Force -Value {
                param(
                    [object[]] $callback  # Get-Callback
                )
                $object = @{
                    FromFunction          = ""
                    FromFunctionStatement = ""
                    FromMethodInFunction  = ""
                    FromScriptLine        = ""
                    FromArguments         = @{}
                    ScriptName            = ""
                    FromScriptLineNumber  = 0
                    ToFunction            = $callback[0].Command
                    ToFunctionMethodLine  = ""
                }
                for ($i = 1; ; $i++) {
                    if ($callback[$i].Command -ne "") {
                        $object.FromFunction = $callback[$i].Command
                        $object.FromFunctionStatement = ""
                        if ($this.IsPS3) {
                            $object.FromFunction = $callback[$i].functionname -replace "<End>|<Begin>|<Process>" # $callback.comand[$i]
                            $object.FromFunctionStatement = $callback[$i].functionname -replace ".*<(End|Begin|Process)>.*", '$1'
                        }
                        $object.FromScriptLine = $callback[$i].Location
                        $object.FromArguments = $callback[$i].Arguments
                        $object.FromScriptName = $callback[$i].ScriptName
                        $object.FromScriptLineNumber = $callback[$i].ScriptLineNumber
                        $object.ToFunctionMethodLine = if ($this.IsPS3) { $callback[$i].Position.Text} else {""}
                        $object.FromMethodInFunction = $object.ToFunctionMethodLine -replace ".+\."
                        break
                    }
                }
                if ($object.FromMethodInFunction -eq $object.ToFunction) {
                    $object.FromMethodInFunction = ""
                    $object.ToFunctionMethodLine = ""
                }
                return $object
            }

            Add-Member -InputObject $InputObject -MemberType ScriptMethod -Name "__ExportToCsvHtm" -Force -Value {
                param(
                    [System.Object] $objects,
                    [string] $OutFileCSV = $__eCsvFile,
                    [switch] $LogPopup,
                    [string] $Delimiter = ";"
                )
                $HTMLHead = $this.Settings["HTMLHead1"].Value
                $OutFileHTM = $OutFileCSV -replace ".csv", ".htm"
                if (Test-Path -Path $OutFileCSV -PathType Leaf) {
                    Set-ItemProperty $OutFileCSV -Name IsReadOnly -value $False
                }
                $objects | Select-Object -Property * | Export-Csv -Path $OutFileCSV -NoTypeInformation -Delimiter $Delimiter -Force -Encoding Default # Encoding must be Default to convert å,ø,æ etc
                $data = $objects | ConvertTo-Html -Head $HTMLhead -Property *
                Set-Content -Value $data -Path $OutFileHTM -Encoding ASCII
                Set-ItemProperty $OutFileCSV -Name IsReadOnly -value $True

                if ($this.IsSystem -or $this.IsService -or !$this.IsInteractive) {return}
                if ($LogPopup) {
                    $__eWsh.Exec("%comspec% /c start $OutFileCSV") | Out-Null
                    $__eWsh.Exec("%comspec% /c start $OutFileHTM") | Out-Null
                }
            }

            Add-Member -InputObject $InputObject -MemberType ScriptMethod -Name "__ConvertCsvToXls" -Force -Value {
                param(
                    [ValidateScript( {$_ -match "\.csv$" -and (Test-Path -Path $_ -PathType Leaf)})]
                    [string] $PathCSV,
                    [string] $PathXLS,
                    [boolean] $Popup = $true,
                    [string] $LPP = "#"
                )
                try {
                    if (!$this.HasExcel) {
                        if ($Popup) {
                            Start-Process -FilePath $PathCSV
                        }
                        return
                    }

                    if ([string]::IsNullorEmpty($PathXLS)) {
                        $PathXLS = $PathCSV.Replace(".csv", ".xls")
                    }
                    Write-Verbose -Message "$LPP Konverterer fil=$PathCSV til fil=$PathXLS"

                    [reflection.assembly]::LoadWithPartialName("Microsoft.Office.InterOp.Excel") | Out-Null
                    # Add-Type -AssemblyName Microsoft.Office.Interop.Excel
                    # [System.Enum]::GetValues([Microsoft.Office.Interop.Excel.XlFileFormat])
                    $xlFixedFormat = [Microsoft.Office.Interop.Excel.XlFileFormat]::xlWorkbookDefault # if Excel 2010or higher on system then format .xlsx
                    $xlExcel8 = [Microsoft.Office.Interop.Excel.XlFileFormat]::xlExcel8 # Excel 2003, format .xls
                    $Excel = New-Object -ComObject "Excel.Application"
                    # https://msdn.microsoft.com/en-us/library/office/ff837097.aspx
                    $Excel.Workbooks.OpenText($PathCSV, 850, 1, 1, 1, $True, $True, $True, $False, $True, $False)
                    $Excel.Visible = $False

                    if (Test-Path -Path $PathXLS -PathType Leaf) {
                        Set-ItemProperty -Path $PathXLS -Name IsReadOnly -value $False
                    }
                    $Excel.DisplayAlerts = $False
                    $Excel.ActiveWorkbook.SaveAs($PathXLS, $xlExcel8)#$xlFixedFormat)
                    $Excel.ActiveSheet.UsedRange.EntireColumn.AutoFit() | Out-Null
                    $Excel.ActiveSheet.UsedRange.AutoFilter() | Out-Null
                    $Excel.Save($PathXLS)
                }
                catch [Exception] {
                    Err $_
                }
                finally {
                    $Excel.Workbooks.Close()
                    $Excel.Quit()
                    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Excel) | Out-Null
                    $Excel = $null
                    Set-ItemProperty -Path $PathCSV -Name IsReadOnly -Value $True
                    if (Test-Path -Path $PathXLS -PathType Leaf) {
                        Set-ItemProperty -Path $PathXLS -Name IsReadOnly -value $True
                        if ($Popup) {
                            Start-Process -FilePath $PathXLS
                        }
                    }
                }
            }

            Add-Member -InputObject $InputObject -MemberType ScriptMethod -Name "__GetTasks" -Force -Value {
                return (Get-ItemProperty -Path $this.Registry.LocalMachine | Select-Object -Property Task*)
            }

            Add-Member -InputObject $InputObject -MemberType ScriptMethod -Name "__IsWow64" -Force -Value {
                # http://stackoverflow.com/questions/8588960/determine-if-current-powershell-process-is-32-bit-or-64-bit
                # Is this a Wow64 powershell host
                return ($this.__IsWin32()) -and (Test-Path Env:\PROCESSOR_ARCHITEW6432)
            }

            Add-Member -InputObject $InputObject -MemberType ScriptMethod -Name "__IsWin64" -Force -Value {
                # http://depsharee.blogspot.no/2011/06/how-do-detect-operating-system.html
                # http://stackoverflow.com/questions/8588960/determine-if-current-powershell-process-is-32-bit-or-64-bit
                # Is this a 64 bit process
                # $bit = Get-WmiObject -Class Win32_OperatingSystem | Select-Object -Property OSArchitecture
                # return $bit.OSArchitecture -eq "64-bit"

                # If you're shell is running on .NET 4.0 (PowerShell 3.0):
                # return [Environment]::Is64BitProcess
                return ($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") -and ([IntPtr]::size -eq 8)
            }

            Add-Member -InputObject $InputObject -MemberType ScriptMethod -Name "__IsWin32" -Force -Value {
                # http://depsharee.blogspot.no/2011/06/how-do-detect-operating-system.html
                # http://stackoverflow.com/questions/8588960/determine-if-current-powershell-process-is-32-bit-or-64-bit
                # Is this a 32 bit process
                # $bit = Get-WmiObject -Class Win32_OperatingSystem | Select-Object -Property OSArchitecture
                # return $bit.OSArchitecture -eq "32-bit"
                return ($Env:PROCESSOR_ARCHITECTURE -eq "x86") -and [IntPtr]::size -eq 4
            }

            Add-Member -InputObject $InputObject -MemberType ScriptMethod -Name "__GetWeekOfYear" -Force -Value {
                param(
                    [datetime] $date = (Get-Date)
                )
                # Note: first day of week is Sunday
                $intDayOfWeek = (Get-Date -date $date).DayOfWeek.value__
                $daysToWednesday = (3 - $intDayOfWeek)
                $wednesdayCurrentWeek = ((Get-Date -date $date)).AddDays($daysToWednesday)

                # %V basically gets the amount of '7 days' that have passed this year (starting at 1)
                $weekNumber = Get-Date -date $wednesdayCurrentWeek -uFormat %V

                $zero = if ([int]::Parse($weekNumber) -lt 10) {"0"} else {""}
                $weekNumber = "$zero{0:D2}" -f $weekNumber

                return $weekNumber
            }

            Add-Member -InputObject $InputObject -MemberType ScriptMethod -Name "__GetInt64Time" -Force -Value {
                param(
                    [System.Int64] $Int64Time
                )
                $d = Get-Date -Date "1900-01-01"
                try {
                    $d = Get-Date -Date ([datetime]::FromFileTime($Int64Time))
                }
                catch {}
                return Get-Date $d
            }

            Add-Member -InputObject $InputObject -MemberType ScriptMethod -Name "__ConvertSecureString" -Force -Value {
                param(
                    [SecureString] $SecureString
                )
                $SecureStringFrom = ConvertFrom-SecureString -SecureString $SecureString
                $SecureStringTo = ConvertTo-SecureString -String $SecureStringFrom
                $SecureStringConvert = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureStringTo))

                return $SecureStringConvert
            }


            Write-Verbose -Message "Initializing Global"

            if (($global:__userdnsdomain = $Env:USERDNSDOMAIN) -eq $Null) {
                # %USERDNSDOMAIN% is not defined for SYSTEM account
                $nvd = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" -Name "NV Domain"
                if ($nvd.'NV Domain' -eq "") {
                    # Workgroup Computer
                    $global:__userdnsdomain = $Env:COMPUTERNAME
                }
                else {
                    $global:__userdnsdomain = $nvd.'NV Domain'
                }
            }

            $global:__userdnsdomain = $__userdnsdomain.ToLower()
            $global:__cmdlet = $MyInvocation.MyCommand # This will be used as the current cmdlet
            $global:__userdomain = "$Env:USERDOMAIN"
            $global:__system = "$Env:COMPUTERNAME"
            $global:__systemipv4 = [system.net.dns]::resolve($__system).AddressList[0].IPAddressToString
            $global:__username = "$Env:USERNAME".ToUpper()
            $global:__identity = "$Env:USERDOMAIN\$Env:USERNAME".ToUpper()
            $global:__domuser = "$Env:UserDomain\$Env:UserName".ToUpper()
            $global:__locopdata = "$Env:PROGRAMDATA\nOsliw Solutions\PSModules\$($InputObject.Name)"
            $global:__environment = ""
            $global:__yyyyMMdd = Get-Date -Format "yyyyMMdd"
            $global:__yyMMdd = Get-Date -Format "yyMMdd"
            $global:__yyyyMM = Get-Date -Format "yyyyMM"
            $global:__yyyy = Get-Date -Format "yyyy"
            $global:__MM = Get-Date -Format "MM" # 12
            $global:__MMMM = Get-Date -Format "MMMM" #december
            $global:__weekday = (Get-Date).DayOfWeek
            $global:__weeknum = $InputObject.__GetWeekOfYear()
            $global:__month = $Textinfo.ToTitleCase($__MMMM)

            if (-not (Test-Path -Path $__locopdata -PathType Container)) {
                Write-Verbose -Message "Creating local log folder $__locopdata"
                mkdir -Path $__locopdata -Force | Out-Null
                cmd /c takeown /F "$Env:ALLUSERSPROFILE\nOsliw Solutions" /A /R | Out-Null
                cmd /c icacls "$Env:ALLUSERSPROFILE\nOsliw Solutions" /setowner "$__system\Administrators" /T /C | Out-Null
                cmd /c icacls "$Env:ALLUSERSPROFILE\nOsliw Solutions" /inheritance:d | Out-Null
                cmd /c icacls "$Env:ALLUSERSPROFILE\nOsliw Solutions" /grant "$__userdomain\Task-Data-Administrators`:(OI)(CI)(F)" /T /C | Out-Null
                New-Item -path (split-path $InputObject.Registry.LocalMachine) -Name $InputObject.Name -Force | Out-Null
            }

            if ($InputObject.IsInteractive) {
                $Arguments = "/c robocopy.exe $($InputObject.Path)\Tools\ $__locopdata\Tools\ /NP /R:0 /W:0 /XO /XX "
                Start-Process -FilePath "$Env:SystemRoot\system32\cmd.exe" -WorkingDirectory "$Env:TEMP" -ArgumentList $Arguments -WindowStyle Hidden
            }
            try {
                $InputObject.HasExcel = $True
                #New-Object -ComObject Excel.Application -ErrorAction 0 | Out-Null
                Add-Type -AssemblyName "Microsoft.Office.Interop.Excel" | Out-null
            }
            catch {
                $InputObject.HasExcel = $false
            }

            $InputObject.Settings.InitializedCommon = $True

        }
        catch [Exception] {
            Write-Error -Exception $_
        }
    }
    END {
        Write-Verbose -Message "$LPP Exiting $($MyInvocation.MyCommand)"
    }
} # End Initialize-nCommon