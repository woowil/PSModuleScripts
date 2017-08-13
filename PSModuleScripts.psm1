
#  Copyright (c) nOsliw Solutions. All rights reserved.
#
# THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
# WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
# IF THIS CODE AND INFORMATION IS MODIFIED, THE ENTIRE RISK OF USE OR RESULTS IN
# CONNECTION WITH THE USE OF THIS CODE AND INFORMATION REMAINS WITH THE USER.

# Error default handling. Check Get-Help about_commonparameters
$ErrorActionPreference = "Stop" # Do not change. This shows all error upon import-module
$VerbosePreference = "Continue"

$script:modulename = ($ExecutionContext.SessionState.Module).ToString()
$script:identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$script:IsAdmin = (New-Object Security.Principal.WindowsPrincipal $identity).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

if (!$IsAdmin) {
    Clear-Host
    Write-Host
    $msg = "Problem`n`tThis $modulename module requires an Elevated Mode session environment.`n`tPlease re-import the module with an administrator elevated environment"
    Write-Host -Object "$msg" -ForegroundColor Red
    Write-Host
    Break
}

# Clears all variables
Remove-Variable -Name __n* | Out-Null

# Global Variables
$path = Split-Path $MyInvocation.MyCommand.Path -Parent
$hash = New-Object -TypeName HashTable -ArgumentList @{
    Module            = $ExecutionContext.SessionState.Module
    Name              = $ExecutionContext.SessionState.Module.Name
    Path              = $path
    Registry          = New-Object -TypeName HashTable -ArgumentList @{
        LocalMachine = "HKLM:\SOFTWARE\nOsliw Solutions\PSModules\$modulename"
        CurrentUser  = "HKCU:\SOFTWARE\nOsliw Solutions\PSModules\$modulename"
    }
    IsMaintenanceMode = $False
    IsSystem          = "$Env:USERNAME" -eq "$($Env:COMPUTERNAME)`$"
    IsInModuleGroup   = $True
    IsInteractive     = [Environment]::UserInteractive
    IsPS3             = $PSVersionTable.PSVersion.Major -ge 3
    HasExcel          = $False
    EventLogSource    = "PowerShell Module " + $modulename.ToString().toUpper()
    Settings          = New-Object -TypeName HashTable -ArgumentList @{
        IsADLoaded        = $False
        InitializedCommon = $false
    }
    Invocation        = New-Object -TypeName HashTable -ArgumentList @{
        Arguments  = ""
        Identity   = ""
        Time       = Get-Date
        LastPrefix = ""
    }
    Errors            = [System.Collections.ArrayList] @()  # [Environment]::ExitCode, [Environment]::Exit(8)
    Warnings          = [System.Collections.ArrayList] @()  # [Environment]::ExitCode, [Environment]::Exit(8)
    ErrorsCmdlet      = @{}
    WarningsCmdlet    = @{}
    DoCmdOnRemove     = [System.Collections.ArrayList] @()
    DoPSHOnRemove     = [System.Collections.ArrayList] @()
}

# Main Global variable
New-Variable -Name __nPSMS -Value $hash -Option AllScope -Scope Global -ErrorAction Stop -Description "Global Module variable" -Force

# Loading PowerShell Script files
$Files = Get-ChildItem -Path "$path\Scripts" -Recurse -Include "*.ps1" -Filter "*-n*"
ForEach ($File in $Files) {
    try {
        $FullName = $File.FullName
        Write-Verbose -Message "Loading: $FullName"
        . $FullName
    }
    catch [Exception] {
        $Message = ($_.Exception.Message).ToString().Trim()
        $Message = "Loading error file=$FullName, Message: $Message"
        Write-Host -Object $Message -ForegroundColor Red
        break
    }
}

# Export all commands except for TheVerb-TheNoun
# Export-ModuleMember -Function * -Alias *

# Initializing the Module
Initialize-nCommon -InputObject $__nPSMS

$script:mObj = $MyInvocation.MyCommand.ScriptBlock.Module
$script:mName = $MyInvocation.MyCommand.ScriptBlock.Module.name
$mObj.OnRemove = {
    if (Test-path -path Alias:\Log -PathType Leaf) {

        $__nPSMS.Errors.Clear()
        $__nPSMS.ErrorsCmdlet.Clear()
        $__nPSMS.WarningsCmdlet.Clear()
        $__nPSMS.DoCmdOnRemove.Clear()
        $__nPSMS.DoPSHOnRemove.Clear()
        $__nPSMS.Settings.Clear()

        Remove-Variable -Name __n* -Force | Out-Null
    }
    $Error.Clear()
}
