﻿<# 
    .NOTES
    ===========================================================================
        FileName:     harden365.ps1
        Author:       Community Harden - contact@harden365.net
        Created On:   09/28/2021
        Last Updated: 11/29/2021
        Version:      v0.7
    ===========================================================================

    .DESCRIPTION
        Protect your data in minutes

    .DEPENDENCIES
        PowerShell 5.1
        Security Default disable

    .UPDATES
    0.8 - 01/15/2023
        Rewrite debug system
    0.7 - 11/27/2021
        Rewrite debug system
    0.6 - 11/26/2021
        Rewrite prerequisites
    0.5 - 11/02/2021
        Add notes
    0.4 - 09/28/2021
        Add Menu


#>

param(
    [Parameter(Mandatory = $false)]
    [switch]$reloadModules
)

# Unblock files
try { Get-ChildItem -Path $pwdt -Recurse -File | Unblock-File -ErrorAction:SilentlyContinue }
catch {}

$totalCountofOperations = 2
$currentCountOfOperations = 0

clear-Host
#(0..10)| ForEach-Object {Write-Host }

$sLogoData = Get-Content (".\Config\Harden365s.logo")
foreach ($line in $sLogoData) { Write-Host $line -ForegroundColor Red }

## CREDENTIALS
try { 
    $null = Get-Command Get-MgContext -ErrorAction Stop
    Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline
    Write-Host ("Check GRAPH Powershell Module OK") -ForegroundColor green
}
catch {
    # CHECK ADMIN RUN
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (!$isAdmin) {
        Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline
        Write-Host 'You must run this script as an administrator to install Powershell Graph module' -ForegroundColor red
        Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline
        Write-Host 'Script execution cancelled' -ForegroundColor Red
        Pause; Break
    }
    # CHECK POWERSHELL
    if (($PSVersionTable.PSVersion.Major -lt 5) -or ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 0)) {
        Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline
        Write-Host 'Please install Powershell version 5.1' -ForegroundColor red
        Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline
        Write-Host 'https://www.microsoft.com/en-us/download/details.aspx?id=54616' -ForegroundColor red
        break Script
    }
    else {
        Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline
        Write-Host 'Powershell Version OK' -ForegroundColor green
    }
    # CHECK / INSTALL NUGET
    if ($(Get-PackageProvider).Name -notcontains 'NuGet') {
        Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline
        Write-Host "NuGet Provider necessary" -ForegroundColor yellow
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted  
        $null = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    }
    # INSTALL GRAPH
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline
    Write-Host ("Installing GRAPH Powershell Module") -ForegroundColor green
    Install-Module 'Microsoft.Graph' -MinimumVersion 2.11.0 -AllowClobber
    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Untrusted
}

try {
    Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline
    Write-Host("PLEASE CONNECT TO GRAPH WITH GLOBAL ADMINISTRATOR") -ForegroundColor Yellow
    Connect-MgGraph -ContextScope Process -Scopes Directory.Read.All, `
        RoleManagement.ReadWrite.Directory, `
        User.ReadWrite.All, `
        Group.ReadWrite.All, `
        Application.Readwrite.All, `
        UserAuthenticationMethod.ReadWrite.All, `
        Policy.Read.All, `
        Policy.ReadWrite.ConditionalAccess, `
        AuditLog.Read.All, `
        UserAuthenticationMethod.Read.All, `
        PrivilegedAccess.ReadWrite.AzureADGroup, `
        PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup, `
        Policy.ReadWrite.Authorization -NoWelcome -Erroraction Stop
}
catch {
    Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline
    Write-Host $_.Exception.Message -ForegroundColor red
    Read-Host -Prompt "Press Enter to quit_"
    Break
}

if ($reloadModules) {
    Remove-Module 'Harden365.debug'
    Remove-Module 'Harden365.prerequisites'
}
    
## INTERFACE
Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline
Write-Host("LOADING HARDEN 365") -ForegroundColor Red
$pwd
Import-Module '.\Config\Harden365.debug.psm1'
Import-Module '.\Config\Harden365.prerequisites.psm1' 
Import-Module '.\Config\Harden365.Menu.psm1'
if ($reloadModules) {
    Remove-AllHarden365Modules
}
    
## PREREQUISITES
Test-AllPrerequisites -OperationCount $currentCountOfOperations -OperationTotal $totalCountofOperations
$currentCountOfOperaions++
Import-AllScriptModules -OperationCount $currentCountOfOperations -OperationTotal $totalCountofOperations
$currentCountOfOperations++

# TODO: duplicate with Check-TenantEdition and Check-O365ATP ??

#TENANT NAME
$TenantName = (Get-MgDomain | Where-Object { $_.IsDefault -eq $true }).Id
#AZUREADEDITION

$mgSubscribedSkuPlans = ((Get-MgSubscribedSku | Where-Object { $_.CapabilityStatus -eq "Enabled" }).ServicePlans).ServicePlanName

if ($mgSubscribedSkuPlans -match "AAD_PREMIUM_P2") {
    $TenantEdition = "Entra ID P2"
}

elseif ($mgSubscribedSkuPlans -match "AAD_PREMIUM") {
    $TenantEdition = "Entra ID P1"
}
elseif($mgSubscribedSkuPlans -match "AAD_BASIC") {
    $TenantEdition = "Entra ID Basic"
}
else {
    $TenantEdition = "Entra ID Free"
}


#OFFICE365ATP
if($mgSubscribedSkuPlans -match "THREAT_INTELLIGENCE") {
    $O365ATP = "Defender for Office365 P2"
}
elseif($mgSubscribedSkuPlans -match "ATP_ENTERPRISE") {
    $O365ATP = "Defender for Office365 P1"
}
elseif($mgSubscribedSkuPlans -match "EOP_ENTERPRISE") {
    $O365ATP = "Exchange Online Protection"
}
else {
    $O365ATP = "No protection"
}

## RUN MAIN MENU
MainMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP