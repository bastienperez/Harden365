<# 
    .NOTES
    ===========================================================================
        FileName:     Harden365.TenantSettings.psm1
        Author:       Community Harden - contact@harden365.net
        Created On:   05/04/2022
        Last Updated: 05/04/2022
        Version:      v0.7
    ===========================================================================

    .SYNOPSYS
        Get tenant information

    .DESCRIPTION
        TenantInfos
        TenantEdition
        Defender ATP
        HashSyncPassword
        SSPR
#>
Function Check-TenantInfos {
    <#
        .Synopsis
         Check Tenant Azure AD Edition plan.
        
        .Description
         Check Tenant Azure AD Edition plan.

        .Notes
         Version: 01.00 -- 
         
    #>

    #SCRIPT
    $mgOrganization = Get-MgOrganization
    $TenantDisplayName = $mgOrganization.DisplayName
    $TenantPrimaryDomain = (Get-MgDomain | Where-Object { $_.IsDefault }).Id
    $TenantDirectorySync = $mgOrganization.OnPremisesSyncEnabled
}

Function Check-TenantEdition {
    <#
        .Synopsis
         Check Tenant Azure AD Edition plan.
        
        .Description
         Check Tenant Azure AD Edition plan.

        .Notes
         Version: 01.00 -- 
         
    #>

    #SCRIPT

    $entraIDPremiumServicePlan = ((Get-MgSubscribedSku | Where-Object { $_.PrepaidUnits.Enabled -gt 0 }).ServicePlans | Where-Object { $_.ServicePlanName -match 'AAD_PREMIUM' }).ServicePlanName

    switch ($entraIDPremiumServicePlan) {
        'AAD_PREMIUM_P2' {
            $TenantEdition = "Microsoft Entra ID Premium P2"
            break
        }
        'AAD_PREMIUM' {
            $TenantEdition = "Microsoft Entra ID Premium P1"
            break
        }
        default {
            $TenantEdition = "Microsoft Entra ID Free"
            break
        }
    }
    <#

(Get-MgSubscribedSku | Where-Object {$_.PrepaidUnits.Enabled -gt 0}).ServicePlans | Where-Object {$_.ServicePlanName -match 'AAD_PREMIUM'}
if (((Get-MsolAccountSku | Where-Object { $_.ActiveUnits -ne "0" }| Select -ExpandProperty ServiceStatus).ServicePlan).ServiceName -match "AAD_PREMIUM_P2")
    { $TenantEdition = ((Get-MsolAccountSku | Where-Object { $_.ActiveUnits -ne "0" } | Select -ExpandProperty ServiceStatus).ServicePlan | Where-Object { $_.ServiceName -match "AAD_PREMIUM_P2" }).ServiceName
      $TenantEdition = "Azure AD Premium P2" }    
elseif (((Get-MsolAccountSku | Where-Object { $_.ActiveUnits -ne "0" } | Select -ExpandProperty ServiceStatus).ServicePlan).ServiceName -match "AAD_PREMIUM")
    { $TenantEdition = ((Get-MsolAccountSku | Where-Object { $_.ActiveUnits -ne "0" } | Select -ExpandProperty ServiceStatus).ServicePlan | Where-Object { $_.ServiceName -match "AAD_PREMIUM" }).ServiceName
       $TenantEdition = "Azure AD Premium P1" }  
else { $TenantEdition = "Azure AD Free" }  
}
#>
}
Function Check-DefenderATP {
    <#
        .Synopsis
         Check Defender ATP plan.
        
        .Description
         Check Defender ATP plan.

        .Notes
         Version: 01.00 -- 
         
    #>

    #SCRIPT
    $atpServicePlan = ((Get-MgSubscribedSku | Where-Object { $_.PrepaidUnits.Enabled -gt 0 }).ServicePlans | Where-Object { $_.ServicePlanName -match 'THREAT_INTELLIGENCE' }).ServicePlanName

    switch ($atpServicePlan) {
        'THREAT_INTELLIGENCE' {
            $TenantEdition = "Defender for Office365 P2"
            $O365ATP = "THREAT_INTELLIGENCE"
            break
        }
        'ATP_ENTERPRISE' {
            $TenantEdition = "Defender for Office365 P1"
            $O365ATP = "ATP_ENTERPRISE"
            break
        }
        'EOP_ENTERPRISE' {
            $TenantEdition = "Exchange Online Protection"
            $O365ATP = "EOP_ENTERPRISE"
            break
        }
    }

    <#
if (((Get-MsolAccountSku | Where-Object { $_.ActiveUnits -ne "0" } | Select -ExpandProperty ServiceStatus).ServicePlan).ServiceName -match "THREAT_INTELLIGENCE")
    { $O365ATP = ((Get-MsolAccountSku | Where-Object { $_.ActiveUnits -ne "0" } | Select -ExpandProperty ServiceStatus).ServicePlan | Where-Object { $_.ServiceName -match "THREAT_INTELLIGENCE" }).ServiceName
      $TenantEdition = "Defender for Office365 P2" }   
elseif (((Get-MsolAccountSku | Where-Object { $_.ActiveUnits -ne "0" } | Select -ExpandProperty ServiceStatus).ServicePlan).ServiceName -match "ATP_ENTERPRISE")
    { $O365ATP = ((Get-MsolAccountSku | Where-Object { $_.ActiveUnits -ne "0" } | Select -ExpandProperty ServiceStatus).ServicePlan | Where-Object { $_.ServiceName -match "ATP_ENTERPRISE" }).ServiceName
      $TenantEdition = "Defender for Office365 P1" }  
elseif (((Get-MsolAccountSku | Where-Object { $_.ActiveUnits -ne "0" } | Select -ExpandProperty ServiceStatus).ServicePlan).ServiceName -match "EOP_ENTERPRISE")
    { $O365ATP = ((Get-MsolAccountSku | Where-Object { $_.ActiveUnits -ne "0" } | Select -ExpandProperty ServiceStatus).ServicePlan | Where-Object { $_.ServiceName -match "EOP_ENTERPRISE" }).ServiceName
      $TenantEdition = "Exchange Online Protection" }  
}
#>
}
Function Check-HashSyncPassword {
    <#
        .Synopsis
         Check Hash Sync Password
        
        .Description
         Check Hash Sync Password

        .Notes
         Version: 01.00 -- 
         
    #>

    #SCRIPT


    # TODO: PasswordSynchronizationEnabled not currently available in Microsoft Graph
    if ($(Get-MsolCompanyInformation).DirectorySynchronizationEnabled -eq $true) {
        if ($(Get-MsolCompanyInformation).PasswordSynchronizationEnabled -eq $false) { 
            Write-LogWarning "Hash Sync Password not enabled!"
            $HashSync = $false
        }
        else {
            Write-LogInfo "Hash Sync Password enabled"
            $HashSync = $true
        }
    }
}

Function Check-SSPR {
    <#
        .Synopsis
         Check SSPR
        
        .Description
         Check SSPR

        .Notes
         Version: 01.00 -- 
         
    #>

    #SCRIPT

    # TODO: SelfServePasswordResetEnabled not currently available in Microsoft Graph
    if ($(Get-MsolCompanyInformation).SelfServePasswordResetEnabled -eq $false) { 
        Write-LogWarning "SSPR not enabled!"
        $SSPR = $false
    }
    else {
        Write-LogInfo "SSPR enabled"
        $SSPR = $true
    }
}

<#
https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference

(Get-MsolAccountSku | Where-Object { $_.ActiveUnits -ne "0" } | Select -ExpandProperty ServiceStatus).ServicePlan | select ServiceType,ServiceName,TargetClass | Sort-Object ServiceType,ServiceName
MDE_SMB : ServiceType "WindowsDefenderATP"
EMS = ENTERPRISE MOBILITY + SECURITY E3
EMSPREMIUM = ENTERPRISE MOBILITY + SECURITY E5
EOP_ENTERPRISE = Exchange Online Protection
ADALLOM_STANDALONE = Microsoft Cloud App Security
WIN_DEF_ATP = MICROSOFT DEFENDER FOR ENDPOINT
ATA = Microsoft Defender for Identity
ADALLOM_O365 = Office 365 Cloud App Security

Security Default : (Get-OrganizationConfig).isDehydrated

#>