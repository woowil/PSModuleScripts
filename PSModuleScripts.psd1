
@{

    # Author of this module
    Author                 = 'Woody Wilson'

    # Script module or binary module file associated with this manifest
    ModuleToProcess        = 'PSModuleScripts.psm1'

    # Version number of this module.
    ModuleVersion          = '1.0.0.0'

    # ID used to uniquely identify this module. Generated at http://www.guidgenerator.com
    GUID                   = '06DE7C05-006F-4793-89BB-003465167DDC'

    # Company or vendor of this module
    CompanyName            = 'nOsliw Solutions'

    # Copyright statement for this module
    Copyright              = '(c) 2017. All rights reserved'

    # Description of the functionality provided by this module
    Description            = 'PowerShell Module Scipts for Windows infrastructure management'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion      = '3.0'

    # Name of the Windows PowerShell host required by this module
    PowerShellHostName     = ''

    # Minimum version of the Windows PowerShell host required by this module
    PowerShellHostVersion  = '1.0'

    # Minimum version of the .NET Framework required by this module
    DotNetFrameworkVersion = ''

    # Minimum version of the common language runtime (CLR) required by this module
    CLRVersion             = ''

    # Processor architecture (None, X86, Amd64, IA64) required by this module
    ProcessorArchitecture  = '' # This module must be able to be loaded from x86 session. Some cmdlets requires x86

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules        = ''

    # Assemblies that must be loaded prior to importing this module
    RequiredAssemblies     = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module
    ScriptsToProcess       = @()

    # Type files (.ps1xml) to be loaded when importing this module
    TypesToProcess         = @() #@('TypeData\PSMS.Typed.ps1xml')

    # Format files (.ps1xml) to be loaded when importing this module
    FormatsToProcess       = @() #@('TypeData\PSMS.Format.ps1xml')

    # Modules to import as nested modules of the module specified in ModuleToProcess
    NestedModules          = @()

    # Functions to export from this module
    FunctionsToExport      = '*'

    # Cmdlets to export from this module
    CmdletsToExport        = '*'

    # Variables to export from this module
    VariablesToExport      = '*'

    # Aliases to export from this module
    AliasesToExport        = '*'

    # List of all modules packaged with this module
    ModuleList             = @()

    # List of all files packaged with this module
    FileList               = @('PSModuleScripts.psd1', 'PSModuleScripts.psm1', 'TypeData\PSModuleScripts.Format.ps1xml', 'TypeData\PSModuleScripts.Typed.ps1xml', 'about_PSMS_Module.help.txt')

    # Private data to pass to the module specified in ModuleToProcess
    #PrivateData = ''

}

