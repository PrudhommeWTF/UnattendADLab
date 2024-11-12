[CmdletBinding(
    DefaultParameterSetName = 'Preparation'
)]
Param(
    #region Preparation parameters
    [Parameter(
        ParameterSetName = 'Preparation'
    )]
    [String]$FirstDCName = 'Hearth',

    [Parameter(
        ParameterSetName = 'Preparation'
    )]
    [IPAddress]$FirstDCIPAddress = '10.0.0.253',

    [Parameter(
        ParameterSetName = 'Preparation'
    )]
    [Int]$FirstDCIPAddressCIDR = 24,

    [Parameter(
        ParameterSetName = 'Preparation'
    )]
    [IPAddress]$FirstDCGateway = '10.0.0.254',
    #endregion Preparation parameters

    #region Forest creation parameters
    [Parameter(
        ParameterSetName = 'RoleInstallAndForestConfig'
    )]
    [Switch]$RoleInstallAndForestConfig,

    [Parameter(
        ParameterSetName = 'RoleInstallAndForestConfig'
    )]
    [String]$DomainNameDNS = 'tph-it.fr',

    [Parameter(
        ParameterSetName = 'RoleInstallAndForestConfig'
    )]
    [String]$SafeModeClearPassword = 'MyS@f3M0d3P@ssw0rdIsS3cur3d!',
    #endregion Forest creation parameters

    [Parameter(
        ParameterSetName = 'FollowupTasks'
    )]
    [Switch]$FollowupTasks
)

#region Functions
Function Write-LogEntry {
    <#
        .SYNOPSIS
        Write formated entry in the PowerShell Host and a file.

        .DESCRIPTION
        Function to write message within the PowerShell Host and persist it into a select file.

        .PARAMETER Info
        Message to write as basic information.
        It will be displayed as Verbose in the PowerShell Host.

        .PARAMETER Warning
        Message to write as a warning information.
        It will be displayed as Warning in the PowerShell Host.

        .PARAMETER Debugging
        Message to write as a debugging information.
        It will be displayed as Debug in the PowerShell Host

        .PARAMETER ErrorMessage
        Message to write as error information.
        It will be de displayed as an Error message in the PowerShell Host.

        .PARAMETER Success
        Message to write as a success information.
        It will be displayed in grenn as a successfull message in the PowerShell Host.

        .PARAMETER ErrorRecord
        Used to complete the ErrorMessage parameter with the Error Object that may have been generated.
        This information will be displayed in the persistance file.

        .PARAMETER LogFile
        Specify the file to write messages in.

        .EXAMPLE
        Write-LogEntry -Info 'Test log entry' -LogFile 'C:\Logs\TestLogFile.log'
        
        Will output in Write-Verbose and in specified log file the specified Info string.

        .EXAMPLE
        Write-LogEntry -Warning 'Test log entry' -LogFile 'C:\Logs\TestLogFile.log'
        
        Will output in Write-Warning and in specified log file the specified Info string.

        .EXAMPLE
        Write-LogEntry -Debugging 'Test log entry' -LogFile 'C:\Logs\TestLogFile.log'
        
        Will output in Write-Debug and in specified log file the specified Info string.

        .EXAMPLE
        Write-LogEntry -ErrorMessage 'Test log entry' -ErrorRecord Value -LogFile 'C:\Logs\TestLogFile.log'
        
        Will output using Write-Host (sadly) with a red foreground and in specified log file the specified Info string.

        .EXAMPLE
        Write-LogEntry -Success 'Test log entry' -LogFile 'C:\Logs\TestLogFile.log'
        
        Will output using Write-Host (sadly) with a green foreground and in specified log file the specified Info string.

        .NOTES
        Author: Thomas Prud'homme (Blog: https://blog.prudhomme.wtf Tw: @Prudhomme_WTF).

        .LINK
        https://github.com/PrudhommeWTF/Stuffs/blob/master/Write-LogEntry/Write-LogEntry.md

        .INPUTS
        System.String

        .OUTPUTS
        System.IO.File
    #>
    [CmdletBinding(
        DefaultParameterSetName = 'Info', 
        SupportsShouldProcess   = $true, 
        ConfirmImpact           = 'Medium',
        HelpUri                 = 'https://github.com/PrudhommeWTF/Stuffs/blob/master/Write-LogEntry/Write-LogEntry.md'
    )]
    Param(
        [Parameter(
            Mandatory                       = $true, 
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName                = 'Info'
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('Message')]
        [String]$Info,
 
        [Parameter(
            Mandatory                       = $true, 
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName                = 'Warning'
        )]
        [ValidateNotNullOrEmpty()]
        [String]$Warning,
 
        [Parameter(
            Mandatory                       = $true, 
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName                = 'Debugging'
        )]
        [ValidateNotNullOrEmpty()]
        [String]$Debugging,
 
        [Parameter(
            Mandatory                       = $true, 
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName                = 'ErrorMessage'
        )]
        [ValidateNotNullOrEmpty()]
        [String]$ErrorMessage,
 
        [Parameter(
            Mandatory                       = $true, 
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName                = 'Success'
        )]
        [ValidateNotNullOrEmpty()]
        [String]$Success,
 
        [Parameter( 
            ValueFromPipeline               = $true,
            ValueFromPipelineByPropertyName = $true, 
            ValueFromRemainingArguments     = $false, 
            ParameterSetName                = 'ErrorMessage'
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('Record')]
        [Management.Automation.ErrorRecord]$ErrorRecord,
 
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, 
            ParameterSetName                = 'Info'
        )]
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, 
            ParameterSetName                = 'Warning'
        )]
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, 
            ParameterSetName                = 'Debugging'
        )]
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, 
            ParameterSetName                = 'Success'
        )]
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true, 
            ParameterSetName                = 'ErrorMessage'
        )]
        [Alias('File', 'Location')]
        [String]$LogFile
    )
    if (!(Test-Path -Path $LogFile)) {
         try {
            $null = New-Item -Path $LogFile -ItemType File -Force
         }
         catch {
            Write-Error -Message 'Error creating log file'
            break
         }
    }
    
    try {
        $Mutex = [Threading.Mutex]::OpenExisting('Global\AZEOMutex')
    }
    catch {
        $Mutex = New-Object -TypeName 'Threading.Mutex' -ArgumentList $false, 'Global\AZEOMutex'
    }
    
    switch ($PSBoundParameters.Keys) {
         'ErrorMessage' {
            Write-Host -Object "ERROR: [$([DateTime]::Now)] $ErrorMessage" -ForegroundColor Red

            $null = $Mutex.WaitOne()
 
            Add-Content -Path $LogFile -Value "$([DateTime]::Now) [ERROR]: $ErrorMessage"
 
            if ($PSBoundParameters.ContainsKey('ErrorRecord')) {
                $Message = '{0} ({1}: {2}:{3} char:{4})' -f $ErrorRecord.Exception.Message,
                                                            $ErrorRecord.FullyQualifiedErrorId,
                                                            $ErrorRecord.InvocationInfo.ScriptName,
                                                            $ErrorRecord.InvocationInfo.ScriptLineNumber,
                                                            $ErrorRecord.InvocationInfo.OffsetInLine
 
                Add-Content -Path $LogFile -Value "$([DateTime]::Now) [ERROR]: $Message"
            }
 
            $null = $Mutex.ReleaseMutex()
            Continue
         }
         'Info' {
            $VerbosePreference = 'Continue'
            Write-Verbose -Message "[$([DateTime]::Now)] $Info"

            $null = $Mutex.WaitOne()
 
            Add-Content -Path $LogFile -Value "$([DateTime]::Now) [INFO]: $Info"
                
            $null = $Mutex.ReleaseMutex()
            Continue
         }
         'Debugging' {
            Write-Debug -Message "$Debugging"
 
            $null = $Mutex.WaitOne()
                
            Add-Content -Path $LogFile -Value "$([DateTime]::Now) [DEBUG]: $Debugging"
                
            $null = $Mutex.ReleaseMutex()
            Continue
         }
         'Warning' {
            Write-Warning -Message "[$([DateTime]::Now)] $Warning"
 
            $null = $Mutex.WaitOne()
                
            Add-Content -Path $LogFile -Value "$([DateTime]::Now) [WARNING]: $Warning"
                
            $null = $Mutex.ReleaseMutex()
            Continue
         }
         'Success' {
            Write-Host -Object "SUCCESS: [$([DateTime]::Now)] $Success" -ForegroundColor Green
 
            $null = $Mutex.WaitOne()
                
            Add-Content -Path $LogFile -Value "$([DateTime]::Now) [SUCCESS]: $Success"
                
            $null = $Mutex.ReleaseMutex()
            Continue
         }
    }
}
Function Repair-NlaSvcOnDC {
    <#
        .SYNOPSIS
        Fix Network Profile issue detected as public on DC.

        .DESCRIPTION
        When a DC starts, the NLASVC service is not properly detecting the network profile as Domain and fallback to the Public one.
        This script operate a change to the Network Location Awareness services to ensure that detection will works as expected.

        .NOTES
        Version 1.0.1
        Updated by: Thomas PRUD'HOMME
        Orginal Author: Bastien PEREZ 
    #>
    $ServiceName = 'nlasvc'
    $DesiredDependencies = @('DNS')

    #Test if dependency exist
    foreach ($dependency in $DesiredDependencies) {
        if (-not (Get-Service $dependency -ErrorAction 'SilentlyContinue')) {
            return
        }
    }

    #Fetch current dependencies from the registry
    $CurrentDependencies = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name 'DependOnService' -ErrorAction 'SilentlyContinue' | Select-Object -ExpandProperty 'DependOnService'

    #Convert current dependencies to an array if they exist
    if ($null -eq $CurrentDependencies) {
        $CurrentDependencies = @()
    } elseif (-not ($CurrentDependencies -is [Array])) {
        $CurrentDependencies = @($CurrentDependencies)
    }

    #Determine which dependencies are missing
    $MissingDependencies = $DesiredDependencies | Where-Object -FilterScript {$_ -notin $CurrentDependencies}

    #If there are any missing dependencies, add them
    if ($MissingDependencies.Count -gt 0) {
        $TargetDependencies = $CurrentDependencies + $MissingDependencies
        try {
            $null = Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name 'DependOnService' -Value $($TargetDependencies | Out-String)
            return 'Success'
        }
        catch {
            throw $_
        }
    }
}
#endregion Functions

switch ($PSCmdlet.ParameterSetName) {
    'Preparation' {
        Write-LogEntry -Info 'Step 0: Prepare computer starts'
        
        #Rename Computer
        if ([System.Environment]::MachineName -eq $FirstDCName) {
            Write-LogEntry -Info "ComputerName is already $FirstDCName."
        } else {
            Write-LogEntry -Info ('Trying to rename computer from: {0}, to: {1}.' -f [System.Environment]::MachineName, $FirstDCName)
            try {
                Rename-Computer -NewName $FirstDCName -Force
                Write-LogEntry -Success 'Renamed computer.'
            }
            catch {
                Write-LogEntry -ErrorMessage 'Failed renaming computer' -ErrorRecord $_
                Exit
            }
        }
        
        #Get Network Interface Index
        $InterfaceIndex = (Get-NetAdapter).ifIndex
        $InterfaceDetails = Get-NetIPAddress -InterfaceIndex $InterfaceIndex
        
        #Set Fixed IP Address
        if (($InterfaceDetails.PrefixOrigin -eq 'manuel') -and (($InterfaceDetails.IPAddress -eq $FirstDCIPAddress) -and ($InterfaceDetails.PrefixLength -eq $FirstDCIPAddressCIDR))) {
            Write-LogEntry -Info 'IP Address is already manually set to all the target values.'
        } else {
            Write-LogEntry -Info 'IP Address does not match requirments. Trying to configure it like required.'
            try {
                New-NetIPAddress -IPAddress $FirstDCIPAddress -PrefixLength $FirstDCIPAddressCIDR -InterfaceIndex $InterfaceIndex -DefaultGateway $FirstDCGateway
                Write-LogEntry -Success 'Set network configuration like required.'
            }
            catch {
                Write-LogEntry -ErrorMessage 'Failed configuring network like required. Not killing error, continuing with current configuration.' -ErrorRecord $_
            }
        }
        
        #Set DNS Address
        try {
            Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ServerAddresses ('127.0.0.1', $FirstDCGateway)
            Write-LogEntry -Success 'Configured DNS Servers'
        }
        catch {
            Write-LogEntry -ErrorMessage 'Failed configuring DNS Servers' -ErrorRecord $_
            Exit
        }

        #Create Scheduled Task to continue configuration after restart
        $TaskTrigger = New-ScheduledTaskTrigger -AtStartup
        $TaskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File '$PSScriptRoot\Invoke-UnattendADLab.ps1' -RoleInstall" -WorkingDirectory $PSScriptRoot
        try {
            Register-ScheduledTask -TaskName 'Unattended AD Lab Tasks' -Action $TaskAction -Trigger $TaskTrigger
            Write-LogEntry -Success 'Created Scheduled Task to continue configuration after restart.'
        }
        catch {
            Write-LogEntry -ErrorMessage 'Failed creating Scheduled Task' -ErrorRecord $_
            Exit
        }
        
        #Restart Computer
        Restart-Computer
    }
    'RoleInstallAndForestConfig' {
        #region Cleanup previous step Scheduled Task
        Write-LogEntry -Info 'Removing Scheduled Task of previous Unattend AD Lab step.'
        try {
            Unregister-ScheduledTask -TaskName 'Unattended AD Lab Tasks' -Confirm:$false
            Write-LogEntry -Success 'Removed Scheduled Task of previous Unattend AD Lab step.'
        }
        catch {
            Write-LogEntry -ErrorMessage 'Failed removing Scheduled Task of previous Unattend AD Lab step.'
            Exit
        }
        #endregion Cleanup previous step Scheduled Task

        #region Role Installation
        $ADDSFeaturesList = @('RSAT-AD-Tools', 'AD-Domain-Services', 'DNS')

        foreach ($feature in $ADDSFeaturesList){
            if (((Get-WindowsFeature -Name $feature).InstallState) -eq 'Available') {
                Write-LogEntry -Info "Installing: $feature"
                try {
                    Add-WindowsFeature-Name $feature -IncludeManagementTools -IncludeAllSubFeature
                    Write-LogEntry -Success "Feature `"$feature`" has been installed."
                }
                catch {
                    Write-LogEntry -ErrorMessage "Error while installing feature `"$feature`"." -ErrorRecord $_
                    Exit
                }
            }
        }
        #endregion Roles Installation

        #region Forest Configuration
        $ForestConfiguration = @{
            DatabasePath                  = 'C:\Windows\NTDS'
            DomainMode                    = 'Default'
            DomainName                    = $DomainNameDNS
            DomainNetbiosName             = $DomainNameDNS.Split('.')[0].ToUpper()
            ForestMode                    = 'Default'
            InstallDns                    = $true
            LogPath                       = 'C:\Windows\NTDS'
            NoRebootOnCompletion          = $false
            SysvolPath                    = 'C:\Windows\SYSVOL'
            Force                         = $true
            CreateDnsDelegation           = $false
            SafeModeAdministratorPassword = $(ConvertTo-SecureString $SafeModeClearPassword -AsPlaintext -Force)
        }
        
        Install-ADDSForest @ForestConfiguration
        #endre Forest Configuration

        #Create Scheduled Task to continue configuration after restart
        $TaskTrigger = New-ScheduledTaskTrigger -AtStartup
        $TaskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File '$PSScriptRoot\Invoke-UnattendADLab.ps1' -FollowupTasks" -WorkingDirectory $PSScriptRoot
        try {
            Register-ScheduledTask 'Unattended AD Lab Tasks' -Action $TaskAction -Trigger $TaskTrigger
            Write-LogEntry -Success 'Created Scheduled Task to continue configuration after restart.'
        }
        catch {
            Write-LogEntry -ErrorMessage 'Failed creating Scheduled Task' -ErrorRecord $_
            Exit
        }
        
        #Restart Computer
        Restart-Computer
    }
    'FollowupTasks' {
        #region Cleanup previous step Scheduled Task
        Write-LogEntry -Info 'Removing Scheduled Task of previous Unattend AD Lab step.'
        try {
            Unregister-ScheduledTask -TaskName 'Unattended AD Lab Tasks' -Confirm:$false
            Write-LogEntry -Success 'Removed Scheduled Task of previous Unattend AD Lab step.'
        }
        catch {
            Write-LogEntry -ErrorMessage 'Failed removing Scheduled Task of previous Unattend AD Lab step.'
            Exit
        }
        #endregion Cleanup previous step Scheduled Task

        #Fix NLA/DNS detection issue
        Repair-NlaSvcOnDC

        #region Organizational Units
        $DomainDN = Get-ADDomain | Select-Object -ExpandProperty DistinguishedName
        New-ADOrganizationalUnit -Name 'Marvel' -Path $DomainDN
        New-ADOrganizationalUnit -Name 'Users' -Path "OU=Marvel,$DomainDN"
        New-ADOrganizationalUnit -Name 'Devices' -Path "OU=Marvel,$DomainDN"
        New-ADOrganizationalUnit -Name 'Groups' -Path "OU=Marvel,$DomainDN"
        New-ADOrganizationalUnit -Name 'Security' -Path "OU=Groups,OU=Marvel,$DomainDN"
        New-ADOrganizationalUnit -Name 'Distribution' -Path "OU=Groups,OU=Marvel,$DomainDN"
        #endregion Organizational Units

        #region AD Groups
        New-ADGroup -Name 'GG-MarvelLocalAdmins' -GroupScope Global -GroupCategory Security -Path "OU=Security,OU=Groups,OU=Marvel,$DomainDN"
        New-ADGroup -Name 'LG-MarvelLocalAdmins' -GroupScope DomainLocal -GroupCategory Security -Path "OU=Security,OU=Groups,OU=Marvel,$DomainDN"
        Add-ADGroupMember -Identity 'LG-MarvelLocalAdmins' -Members 'GG-MarvelLocalAdmins'
        #endregion AD Groups

        #region AD Users
        $Users = Import-Csv -Path "$PSScriptRoot\Users.csv" -Delimiter ',' -Encoding utf8
        foreach ($user in $Users) {
            $NewUser101 = @{
                SamAccountName       = $user.UserName
                UserPrincipalName    = "$($user.UserName)@marvel.local"
                Name                 = '{0} {1}' -f $user.FirstName, $user.LastName
                GivenName            = $user.FirstName
                Surname              = $user.LastName
                Enabled              = $true
                DisplayName          = '{0} {1}' -f $user.FirstName, $user.LastName
                Path                 = "OU=Users,OU=Marvel,$DomainDN"
                State                = $user.Province
                Department           = $user.Department
                AccountPassword      = $(ConvertTo-SecureString -String $user.Password -AsPlainText -Force)
                PasswordNeverExpires = $True
            }
            New-ADUser @NewUser101
                        
            Add-ADGroupMember -Members $user.UserName -Identity $user.Groups
        }
        #endregion AD Users

        #region AD Groups based on AD Users
        #Security Groups
        $Users | Group-Object -Property Department | ForEach-Object -Process {
            New-ADGroup -Name "GG-$($_.Name)" -GroupCategory Security -GroupScope Global -Path "OU=Security,OU=Groups,OU=Marvel,$DomainDN"
            Add-ADGroupMember -Identity "GG-$($_.Name)" -Members @($_.Group.UserName)
        }

        #Distribution Lists
        $Users | Group-Object -Property Province | ForEach-Object -Process {
            New-ADGroup -Name "DG-$($_.Name)" -GroupCategory Distribution -GroupScope Global -Path "OU=Distribution,OU=Groups,OU=Marvel,$DomainDN"
            Add-ADGroupMember -Identity "DG-$($_.Name)" -Members @($_.Group.UserName)
        }
        #endregion AD Groups based on AD Users
    }
}