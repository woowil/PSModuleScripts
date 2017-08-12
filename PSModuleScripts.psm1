
#  Copyright (c) nOsliw Solutions. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

#Set-StrictMode -Version Latest

# Error default handling. Check Get-Help about_commonparameters
$ErrorActionPreference = "Stop" # Do not change. This shows all error upon import-module
#$DebugPreference = "Continue" # Uncomment this if you want to enable debugging mode
#$VerbosePreference = "Continue" # Uncomment this if you want to enable verbose mode

$script:modulename = ($ExecutionContext.SessionState.Module).ToString().toUpper()
$script:identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$script:IsAdmin = (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
$script:IsSVC = $identity.name -match "SVC-|s-|s_"

if (-not ($IsAdmin -or $IsSVC)) {
    # whoami /groups | select-string "BUILTIN\\Administrators" | select-string "Enabled"
    Clear-Host
    Write-Host
    $msg = "Problem`n`tThis $modulename module requires to be run as an service account or an Administrator account.`n`tPlease re-import the module with an administrator"
    Write-Host -Object "$msg" -ForegroundColor Red
    Write-Host
    #Start-Sleep -Milliseconds 5056
    Break
    #Exit
}
elseif (-not (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Clear-Host
    Write-Host
    $msg = "Problem`n`tThis $modulename module requires an Elevated Mode session environment.`n`tPlease re-import the module with an administrator elevated environment"
    Write-Host -Object "$msg" -ForegroundColor Red
    Write-Host
    #Start-Sleep -Milliseconds 5056
    Break
    #Exit
}

# Creating profile files for later use
# http://blogs.technet.com/b/heyscriptingguy/archive/2013/01/04/understanding-and-using-powershell-profiles.aspx
if ("${Env:USERNAME}" -ne "${Env:COMPUTERNAME}`$" -and "${Env:USERNAME}" -notlike "SVC*") {
    $WPPath = Split-Path -Path $PROFILE
    if (-not (Test-Path -Path $WPPath -PathType Container)) {
        mkdir "$WPPath" | Out-Null
    }
    if (-not (Test-Path -Path $PROFILE.CurrentUserAllHosts)) {
        #mkdir $Home\Documents\WindowsPowerShell
        # TODO
        "# `$PROFILE.CurrentUserAllHosts was created $([DateTime]::now)" >> $PROFILE.CurrentUserAllHosts
    }
    if (-not (Test-Path -Path $PROFILE.CurrentUserCurrentHost)) {
        # TODO
        "# `$PROFILE.CurrentUserCurrentHost was created $([DateTime]::now)" >> $PROFILE.CurrentUserCurrentHost
    }
}

if ($IsISE -and ([Console]::OutputEncoding).CodePage -eq 1252) {
    # http://stackoverflow.com/questions/5796339/printing-unicode-characters-to-powershell-prompt
    # This is needed on redirection with
    Write-Host "Changing Windows PowerShell Console CodePage from 1252 (Western) to 850 (UNICODE)" -ForegroundColor Green
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(850)
        #[System.Text.Encoding]::Default
    }
    catch {
        Write-Warning -Message $_.Exception.Message.toString().Trim()
    }
}

# Clears all variables
Remove-Variable -Name __e* | Out-Null

# Global Variables
#$path = [Environment]::CurrentDirectory
$path = Split-Path $MyInvocation.MyCommand.Path -Parent
$hash = New-Object -TypeName HashTable -ArgumentList @{
    Module            = $ExecutionContext.SessionState.Module
    Name              = $ExecutionContext.SessionState.Module.Name
    Path              = $path
    Registry          = New-Object -TypeName HashTable -ArgumentList @{
        LocalMachine = "HKLM:\SOFTWARE\nOsliw Solutions\ProgramData\PSModules\$modulename"
        CurrentUser  = "HKCU:\SOFTWARE\nOsliw Solutions\ProgramData\PSModules\$modulename"
    }
    IsMaintenanceMode = $False
    IsSystem          = "$Env:USERNAME" -eq "$($Env:COMPUTERNAME)`$"
    IsService         = "$Env:USERNAME" -match "SVC-|s-"
    IsInModuleGroup   = $True
    IsInteractive     = [Environment]::UserInteractive
    IsPS3             = $PSVersionTable.PSVersion.Major -ge 3
    HasExcel          = $False
    LogToDFS          = $True
    ShowLog           = $True
    EventLogSource    = "PowerShell Module " + $modulename.ToString().toUpper()
    Scripts           = @()
    Configs           = New-Object -TypeName HashTable -ArgumentList @{
        Global            = "$path\Config\$modulename.Configuration.config"
        GlobalInitialized = $False
        Custom            = "$path\Config\$modulename.Configuration.Custom.config"
        CustomInitialized = $False
        Local             = "${Env:TEMP}\$modulename.Configuration.Local.config"
        External          = "${Env:TEMP}\$modulename.Configuration.External.config"
        HelpText          = "$path\Config\$modulename.Help.Text.config"
    }
    Settings          = New-Object -TypeName HashTable -ArgumentList @{}
    Invocation        = New-Object -TypeName HashTable -ArgumentList @{
        Arguments  = ""
        Identity   = ""
        Time       = Get-Date
        LastPrefix = ""
    }
    Misc              = New-Object -TypeName HashTable -ArgumentList @{
        IsSQLLoaded      = $False
        IsGFLoaded       = $False
        IsOKLoaded       = $False
        IsFSLoaded       = $False
        IsBTSLoaded      = $False
        IsCSLoaded       = $False
        IsADLoaded       = $False
        RoboCopyExitCode = New-Object -TypeName HashTable -ArgumentList @{}
    }
    Errors            = [System.Collections.ArrayList] @()  # [Environment]::ExitCode, [Environment]::Exit(8)
    Warnings          = [System.Collections.ArrayList] @()  # [Environment]::ExitCode, [Environment]::Exit(8)
    ErrorsCmdlet      = @{}
    WarningsCmdlet    = @{}
    DoCmdOnRemove     = [System.Collections.ArrayList] @()
    DoPSHOnRemove     = [System.Collections.ArrayList] @()
}

# Main Global variable
New-Variable -Name __eModule -Value $hash -Option AllScope -Scope Global -ErrorAction Stop -Description "Global Module variable" -Force

# Loading PowerShell Script files
$Files = Get-ChildItem -Path "$path\Scripts" -Recurse -Include "*.ps1" -Filter "*-e*" -Exclude "*-eBTS*", "*-eGF*", "*-eAO"
ForEach ($File in $Files) {
    try {
        $FullName = $File.FullName
        Write-Debug -Message "Loading:  $FullName"
        . $FullName
    }
    catch [Exception] {
        $Message = ($_.Exception.Message).ToString().Trim()
        $Message = "Loading error file=$FullName, Message: $Message"
        Write-Host -Object $Message -ForegroundColor Red
        break
    }
    finally {
        $__eModule.Scripts += $FullName
    }
}

# Export all commands except for TheVerb-TheNoun
# Export-ModuleMember -Function * -Alias *

# Initializing the Module
$sSiteCode = (([WmiClass]"ROOT\ccm:SMS_Client").getassignedsite()).sSiteCode
$script:customerid = if ([string]::IsNullOrEmpty($sSiteCode)) {""} else {$sSiteCode}

#$script:customerid = "${Env:COMPUTERNAME}".Substring(0,3)
Initialize-eSettings -InputObject $__eModule -DefaultMethods -DefaultGlobal  # These must be initialized FIRST
Import-eSettingsXML -Path $__eModule.Configs.Global -CustomerID $customerid
Import-eSettingsXML -Path $__eModule.Configs.Custom -CustomerID $customerid
$global:__dfsopdata = $__eModule.Settings.PathOpData.Value #
Initialize-eSettings -InputObject $__eModule -DefaultCustom # This must be initialized EXACTLY HERE for DefaultCustom
if (Test-Path -Path $__eModule.Configs.Local -PathType Leaf) {
    Import-eSettingsXML -Path $__eModule.Configs.Local -CustomerID $customerid
}
if (Test-Path -Path $__eModule.Configs.External -PathType Leaf) {
    Import-eSettingsXML -Path $__eModule.Configs.External -CustomerID $customerid
}

Initialize-eSettings -InputObject $__eModule -DefaultLogs # This must be initialized EXACTLY HERE for DefaultLogs
if (!$__eModule.Configs.GlobalInitialized -or !$__eModule.Configs.CustomInitialized) {
    Write-Host -Object "Exiting import of PowerShell module $modulename due to error"
    break
}
Initialize-eSettings -InputObject $__eModule -DefaultOther

$script:mObj = $MyInvocation.MyCommand.ScriptBlock.Module
$script:mName = $MyInvocation.MyCommand.ScriptBlock.Module.name

# Create EventLog Source for the module if not already exists
if (-not [System.Diagnostics.EventLog]::SourceExists($__eModule.EventLogSource)) {
    Log -Message "`rCreating EventLog Source ""$($__eModule.EventLogSource)""" -ForegroundColor Green
    [System.Diagnostics.EventLog]::CreateEventSource($__eModule.EventLogSource, "Application") #| Out-Null
    if ([System.Diagnostics.EventLog]::SourceExists("$mName")) {
        # This statement remove old source name
        Log -Message "`rDeleting old EventLog Source ""$mName""" -ForegroundColor Green
        [System.Diagnostics.EventLog]::DeleteEventSource("$mName")
    }
}

if (-not (Test-Path -Path $__eModule.Registry.LocalMachine -PathType Container)) {
    Log -Message "`rCreating registry key ""$($__eModule.Registry.LocalMachine)""" -ForegroundColor Green
    New-Item -Path (Split-Path -Path $__eModule.Registry.LocalMachine) -Name $modulename -Value "Default Value" -Force | Out-Null
    New-Item -Path "$($__eModule.Registry.LocalMachine)\Security" -Value "Default Value" -Force  | Out-Null
    New-Item -Path "$($__eModule.Registry.LocalMachine)\Tasks" -Value "Default Value" -Force  | Out-Null
}

if ((Get-Service -Name Seclogon).Status -ne "Running") {
    Log -Message "`rStarting Secondary Service (must be started for the Start-Process cmdlet)" -ForegroundColor Green
    Set-Service -Name Seclogon -StartupType Automatic
    Start-Service -Name Seclogon
}

"`r`r============================================================================================`r" | Out-File -FilePath "$__eLogFile" -Append -Force -Encoding ASCII
Log -Message "`tTHE MODULE $mName WAS IMPORTED" -ShowLog:$False
"`r============================================================================================`r" | Out-File -FilePath "$__eLogFile" -Append -Force -Encoding ASCII

$mObj.OnRemove = {
    if (Test-path -path Alias:\Log -PathType Leaf) {
        "`r============================================================================================`r" | Out-File -FilePath "$__eLogFile" -Append -Force -Encoding ASCII
        Log -Message "`tTHE MODULE $mName WAS REMOVED" -ShowLog:$False
        "`r============================================================================================`r" | Out-File -FilePath "$__eLogFile" -Append -Force -Encoding ASCII

        if ($__eModule.LogToDFS) {
            if ([System.IO.File]::ReadAllLines($__eLogFile) | Select-String -Pattern "Entering" -Quiet) {
                Copy-eModuleLogs -ToDFS
            }
        }
        forEach ($do in $__eModule.DoCmdOnRemove) {
            Start-Process -FilePath cmd -ArgumentList "/c", $do -WindowStyle Hidden
        }
        forEach ($do in $__eModule.DoPSHOnRemove) {
            & "$do"  | Out-Null
        }
        $__eModule.Errors.Clear()
        $__eModule.ErrorsCmdlet.Clear()
        $__eModule.WarningsCmdlet.Clear()
        $__eModule.DoCmdOnRemove.Clear()
        $__eModule.DoPSHOnRemove.Clear()
        $__eModule.Settings.Clear()
        Remove-Variable -Name __e* -Force | Out-Null
    }
    $Error.Clear()
}
