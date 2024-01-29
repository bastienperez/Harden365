$FrontStyle = "
            _________________________________________________________________________________________
            
            "
Function CreateMenu () {
    
    Param(
        [Parameter(Mandatory = $False)]
        [String]$MenuTitle,
        [String]$TenantEdition,
        [String]$TenantName,
        [String]$O365ATP,
        [Boolean]$TenantDetail = $false,
        [Parameter(Mandatory = $True)][array]$MenuOptions
    )

    $MaxValue = $MenuOptions.count - 1
    $Selection = 0
    $EnterPressed = $False

    #TENANT NAME
    $TenantName = (Get-MgDomain | Where-Object { $_.IsDefault -eq $true }).Id
    #AZUREADEDITION
    if (((Get-MgSubscribedSku | Where-Object { $_.CapabilityStatus -eq "Enabled" }).ServicePlans).ServicePlanName -match "AAD_PREMIUM_P2")
    { $TenantEdition = "Entra ID P2" } 
    elseif (((Get-MgSubscribedSku | Where-Object { $_.CapabilityStatus -eq "Enabled" }).ServicePlans).ServicePlanName -match "AAD_PREMIUM")
    { $TenantEdition = "Entra ID P1" } 
    elseif (((Get-MgSubscribedSku | Where-Object { $_.CapabilityStatus -eq "Enabled" }).ServicePlans).ServicePlanName -match "AAD_BASIC")
    { $TenantEdition = "Entra ID  Basic" } 
    else
    { $TenantEdition = "Entra ID  Free" }
    #OFFICE365ATP
    if (((Get-MgSubscribedSku | Where-Object { $_.CapabilityStatus -eq "Enabled" }).ServicePlans).ServicePlanName -match "THREAT_INTELLIGENCE")
    { $O365ATP = "Defender for Office365 P2" }   
    elseif (((Get-MgSubscribedSku | Where-Object { $_.CapabilityStatus -eq "Enabled" }).ServicePlans).ServicePlanName -match "ATP_ENTERPRISE")
    { $O365ATP = "Defender for Office365 P1" }  
    elseif (((Get-MgSubscribedSku | Where-Object { $_.CapabilityStatus -eq "Enabled" }).ServicePlans).ServicePlanName -match "EOP_ENTERPRISE")
    { $O365ATP = "Exchange Online Protection" }  
    else
    { $O365ATP = "No protection" }

    $FrontStyle = "    _________________________________________________________________________________________            
            "
    
    Clear-Host

    While ($EnterPressed -eq $False) {
        $LogoData = Get-Content (".\Config\Harden365s.logo")
        foreach ($line in $LogoData) { Write-Host $line }
 
        Write-Host "    $MenuTitle" -ForegroundColor Red
        Write-Host $FrontStyle -ForegroundColor Red

        if ($TenantDetail -eq $True) {
            write-Host "    Tenant               = " -NoNewline -ForegroundColor Red
            write-Host "$TenantName" -ForegroundColor Yellow
            write-Host "    Entra Edition        = " -NoNewline -ForegroundColor Red
            write-Host "$TenantEdition"
            write-Host "    DefenderO365 Edition = " -NoNewline -ForegroundColor Red
            write-Host "$O365ATP"
            Write-Host $FrontStyle -ForegroundColor Red
        }
        For ($i = 0; $i -le $MaxValue; $i++) {
            
            If ($i -eq $Selection) {
                Write-Host -NoNewline "    "
                Write-Host -BackgroundColor yellow -ForegroundColor Black "[ $($MenuOptions[$i]) ]"
            }
            Else {
                Write-Host "      $($MenuOptions[$i])  "
            }

        }

        $KeyInput = $host.ui.rawui.readkey("NoEcho,IncludeKeyDown").virtualkeycode

        Switch ($KeyInput) {
            13 {
                $EnterPressed = $True
                Return $Selection
                Clear-Host
                break
            }

            38 {
                If ($Selection -eq 0) {
                    $Selection = $MaxValue
                }
                Else {
                    $Selection -= 1
                }
                Clear-Host
                break
            }

            40 {
                If ($Selection -eq $MaxValue) {
                    $Selection = 0
                }
                Else {
                    $Selection += 1
                }
                Clear-Host
                break
            }
            Default {
                Clear-Host
            }
        }
    }
}

function MainMenu() {
    Param(
        [Parameter(Mandatory = $False)]
        [String]$TenantName,
        [String]$TenantEdition,
        [String]$O365ATP
    )



    $MainMenu = CreateMenu -TenantName $TenantName -TenantEdition $TenantEdition -TenantDetail $true -O365ATP $O365ATP -MenuOptions @("Audit", "Identity", "Messaging", "Application", "Device", "Quit")
    switch ($MainMenu) {
        0 {
            AuditMenu -TenantEdition $TenantEdition -TenantName $TenantName -O365ATP $O365ATP
        }
        1 {
            IdentityMenu -TenantEdition $TenantEdition -TenantName $TenantName -O365ATP $O365ATP
        }
        2 {
            MessagingMenu  -TenantEdition $TenantEdition -TenantName $TenantName -O365ATP $O365ATP
        }
        3 {
            ApplicationMenu
        }
        4 {
            DeviceMenu
        }
        5 {
            Break
        }
        Default {
            MainMenu -TenantName $TenantName -TenantEdition $TenantEdition -TenantDetail $true -O365ATP $O365ATP
        }
    }
}

function AuditMenu() {
    Param(
        [String]$TenantName,
        [String]$TenantEdition,
        [String]$O365ATP

    )

    $AuditMenu = CreateMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP -MenuTitle "HARDEN 365 - AUDIT" -MenuOptions @("Audit Microsoft Defender for O365 with ORCA", "Audit Administration Roles", "Audit Identity Users", "Audit Autoforwarding", "Audit Mailbox Permissions", "Check DNS Records", "<- Return")
    switch ($AuditMenu) {
        0 {
            Write-Host $FrontStyle -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host "Audit Messaging with ORCA"-ForegroundColor Red	
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Connecting to ExchangeOnline Powershell') -ForegroundColor Green
            try {
                $null = Get-OrganizationConfig 
            }
            catch { Connect-ExchangeOnline  -WarningAction:SilentlyContinue -ShowBanner:$false }
            Invoke-ORCA -ExchangeEnvironmentName "O365Default" -Output HTML -OutputOptions @{HTML = @{OutputDirectory = "$TenantName" } } -Connect $false -ShowSurvey $false -SCC $false
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ("Audit ORCA exported in folder .\$TenantName") -ForegroundColor Green
            Read-Host -Prompt "Press Enter to return_"
            AuditMenu  -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
        }
        1 {
            Write-Host $FrontStyle -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("AUDIT ADMINISTRATION ROLES") -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Connected to Graph') -ForegroundColor Green
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ("EntraID Edition : $TenantEdition") -ForegroundColor Green
            if ( $TenantEdition -eq "Entra ID P2") {
                $scriptFunctions = (Get-ChildItem function: | Where-Object { $_.Name -match 'Get-AADRolesAuditP2' })
            }
            else {
                $scriptFunctions = (Get-ChildItem function: | Where-Object { $_.Name -match 'Get-AADRolesAuditP1' })
            }
            $scriptFunctions | ForEach-Object {
                try { 
                    $null = & $_.Name -ErrorAction:SilentlyContinue
                }
                catch {}
            }
            Read-Host -Prompt "Press Enter to return_"
            Clear-Host
            AuditMenu  -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
        }
        2 {
            Write-Host $FrontStyle -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("AUDIT IDENTITY USERS") -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Connected to Graph') -ForegroundColor Green

            $scriptFunctions = (Get-ChildItem function: | Where-Object { $_.source -match 'Harden365.Identity.Users' })
            $scriptFunctions | ForEach-Object {
                try { 
                    $null = & $_.Name -ErrorAction:SilentlyContinue
                }
                catch {}
            }
            Read-Host -Prompt "Press Enter to return_"
            AuditMenu  -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
        }
        3 {
            Write-Host $FrontStyle -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("AUDIT AUTOFORWARDING") -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Connecting to  ExchangeOnline Powershell') -ForegroundColor Green
            try {
                $null = Get-OrganizationConfig 
            }
            catch { Connect-ExchangeOnline -WarningAction:SilentlyContinue -ShowBanner:$false }

            $scriptFunctions = (Get-ChildItem function: | Where-Object { $_.Name -match 'Start-EOPCheckAutoForward' })
            $scriptFunctions | ForEach-Object {
                try { 
                    $null = & $_.Name -ErrorAction:SilentlyContinue
                }
                catch {}
            }
            Read-Host -Prompt "Press Enter to return_"
            AuditMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
        }
        4 {
            Write-Host $FrontStyle -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("AUDIT MAILBOX PERMISSIONS") -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Connecting to  ExchangeOnline Powershell') -ForegroundColor Green
            try {
                $null = Get-OrganizationConfig
            }
            catch { Connect-ExchangeOnline -WarningAction:SilentlyContinue -ShowBanner:$false }

            $scriptFunctions = (Get-ChildItem function: | Where-Object { $_.Name -match 'Start-EOPCheckPermissionsMailbox' })
            $scriptFunctions | ForEach-Object {
                try { 
                    $null = & $_.Name -ErrorAction:SilentlyContinue
                }
                catch {}
            }
            Read-Host -Prompt "Press Enter to return_"
            AuditMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
        }
        5 {
            Write-Host $FrontStyle -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("CHECK DNS RECORDS (SPF/DKIM/DMARC)") -ForegroundColor Red
            try {
                $null = Get-OrganizationConfig
            }
            catch { Connect-ExchangeOnline -WarningAction:SilentlyContinue -ShowBanner:$false }
            $scriptFunctions = (Get-ChildItem function: | Where-Object { $_.name -match 'Start-AuditSPFDKIMDMARC' })
            $scriptFunctions | ForEach-Object {
                try { 
                    $null = & $_.Name  -ErrorAction:SilentlyContinue
                }
                catch {
                    Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("ERROR --> Harden365.DKIM module not working") -ForegroundColor Red
                }
            }
            Read-Host -Prompt "Press Enter to return_"
            AuditMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
        }
        6 {
            MainMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
        }
        Default {
            AuditMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
        }
    }
}

function IdentityMenu() {
    Param(
        [System.Management.Automation.PSCredential]$Credential,
        [String]$TenantName,
        [String]$TenantEdition,
        [String]$O365ATP
    )
    $IdentityMenu = CreateMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP -MenuTitle "HARDEN 365 - IDENTITY" -MenuOptions @("Emergency Accounts", "MFA per User", "Conditionnal Access Models AAD", "Export user configuration MFA", "Import user configuration MFA", "<- Return")
    switch ($IdentityMenu) {
        0 {
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("Do you want to create Emergency Accounts (Y/N) : ") -NoNewline -ForegroundColor Yellow ; $QID0 = Read-Host
            if ($QID0 -eq 'Y') {             
                Write-Host $FrontStyle -ForegroundColor Red
                Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("HARDENING TIER MODEL") -ForegroundColor Red
                Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Connecting to Graph') -ForegroundColor Green
                $scriptFunctions = (Get-ChildItem function: | Where-Object { $_.source -match 'Harden365.TierModel' })
                $scriptFunctions | ForEach-Object {
                    try { 
                        $null = & $_.Name -ErrorAction:SilentlyContinue
                    }
                    catch {
                        Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host(" --> Harden365.TierModel module not working") -ForegroundColor Red
                    }
                }
                Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ("Emergency Account credentials are saved in .\$TenantName ->Keepass file") -ForegroundColor Green
                Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Password Keepass is : ') -ForegroundColor Green -NoNewline ; Write-host ('Harden365') -ForegroundColor Red
                Read-Host -Prompt "Press Enter to return_"
                IdentityMenu  -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
            }
            else { IdentityMenu  -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP }
        }
        1 {
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("Do you want to configure Legacy MFA (Y/N) : ") -NoNewline -ForegroundColor Yellow ; $QID1 = Read-Host
            if ($QID1 -eq 'Y') {   
                Write-Host $FrontStyle -ForegroundColor Red
                Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("HARDENING ENABLE MFA PER USER") -ForegroundColor Red
                Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Connecting to MSOlService Powershell') -ForegroundColor Green
                try {
                    $null = Get-MsolDomain -ErrorAction Stop
                }
                catch { Connect-MSOlService -WarningAction:SilentlyContinue }
                $scriptFunctions = (Get-ChildItem function: | Where-Object { $_.source -match 'Harden365.MFAperUser' })
                $scriptFunctions | ForEach-Object {
                    try { 
                        $null = & $_.Name  -ErrorAction:SilentlyContinue
                    }
                    catch {
                        Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host(" --> Harden365.MFAperUser module not working") -ForegroundColor Red
                    }
                }
                Read-Host -Prompt "Press Enter to return_"
                IdentityMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
            }
            else { IdentityMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP }
        }
        2 {
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("Do you want to create Conditionnal Access Templates (Y/N) : ") -NoNewline -ForegroundColor Yellow ; $QID2 = Read-Host
            if ($QID2 -eq 'Y') {
                Write-Host $FrontStyle -ForegroundColor Red
                Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("HARDENING CONDITIONNAL ACCESS FOR AAD") -ForegroundColor Red
                Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Connected to Graph') -ForegroundColor Green
                $scriptFunctions = (Get-ChildItem function: | Where-Object { $_.source -match 'Harden365.CA' })
                $scriptFunctions | ForEach-Object {
                    try { 
                        $null = & $_.Name  -ErrorAction:SilentlyContinue
                    }
                    catch {
                        Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host(" --> Harden365.CA module not working") -ForegroundColor Red
                    }
                }
                Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('All CA Template created is disable by default') -ForegroundColor Green
                Read-Host -Prompt "Press Enter to return_"
                IdentityMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
            }
            else { IdentityMenu -TenantName $TenantName -TenantEdition $TenantEdition  -O365ATP $O365ATP }
        }
        3 {
            Write-Host $FrontStyle -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("HARDENING EXPORT CONFIG MFA") -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Connecting to MSOlService Powershell') -ForegroundColor Green
            try {
                $null = Get-MsolDomain -ErrorAction Stop
            }
            catch { Connect-MSOlService -WarningAction:SilentlyContinue }
            $scriptFunctions = (Get-ChildItem function: | Where-Object { $_.source -match 'Harden365.ExportForCA' })
            $scriptFunctions | ForEach-Object {
                try { 
                    $null = & $_.Name -ErrorAction:SilentlyContinue
                }
                catch {}
            }
            Read-Host -Prompt "Press Enter to return_"
            IdentityMenu  -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
        }
        4 {
            Write-Host $FrontStyle -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("HARDENING IMPORT CONFIG MFA") -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Connected to Graph') -ForegroundColor Green
            $scriptFunctions = (Get-ChildItem function: | Where-Object { $_.source -match 'Harden365.ImportPhoneNumbers' })
            $scriptFunctions | ForEach-Object {
                try { 
                    $null = & $_.Name  -ErrorAction:SilentlyContinue
                }
                catch {}
            }
            Read-Host -Prompt "Press Enter to return_"
            IdentityMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
        }
        5 {
            MainMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
        }
        Default {
            IdentityMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
        }
    }
}

function MessagingMenu() {
    Param(
        [String]$TenantName,
        [String]$TenantEdition,
        [String]$O365ATP
    )
    $MessagingMenu = CreateMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP -MenuTitle "HARDEN 365 - MESSAGING" -MenuOptions @("Exchange Online Protection", "Defender for Office365", "Check Autoforward", "Check DNS Records", "DKIM Configuration", "<- Return")
    switch ($MessagingMenu) {
        0 {
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("Do you want to secure Exchange Online Protection (Y/N) : ") -NoNewline -ForegroundColor Yellow ; $QMS0 = Read-Host
            if ($QMS0 -eq 'Y') { 
                Write-Host $FrontStyle -ForegroundColor Red
                Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host(" HARDENING EXCHANGE ONLINE PROTECTION") -ForegroundColor Red
                Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Connecting to ExchangeOnline Powershell') -ForegroundColor Green
                try {
                    $null = Get-OrganizationConfig
                }
                catch { Connect-ExchangeOnline -WarningAction:SilentlyContinue -ShowBanner:$false }
                $scriptFunctions = (Get-ChildItem function: | Where-Object { $_.source -match 'Harden365.ExchangeOnline' }) 
                $scriptFunctions | ForEach-Object {
                    try { 
                        $null = & $_.Name  -ErrorAction:SilentlyContinue
                    }
                    catch {
                        Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("ERROR --> Harden365.ExchangeOnline module not working") -ForegroundColor Red
                    }
                }
                Read-Host -Prompt "Press Enter to return_"
                MessagingMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
            }
            else { MessagingMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP }
        }
        1 {
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("Do you want to secure Defender for Office365 (Y/N) : ") -NoNewline -ForegroundColor Yellow ; $QMS1 = Read-Host
            if ($QMS1 -eq 'Y') { 
                Write-Host $FrontStyle -ForegroundColor Red
                Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("HARDENING DEFENDER FOR OFFICE365") -ForegroundColor Red
                Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Connecting to ExchangeOnline Powershell') -ForegroundColor Green
                try {
                    $null = Get-OrganizationConfig
                }
                catch { Connect-ExchangeOnline -WarningAction:SilentlyContinue -ShowBanner:$false }
                $scriptFunctions = (Get-ChildItem function: | Where-Object { $_.source -match 'Harden365.ExchangeOnline' }) 
                $scriptFunctions | ForEach-Object {
                    try { 
                        $null = & $_.Name  -ErrorAction:SilentlyContinue
                    }
                    catch {
                        Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("ERROR --> Harden365.ExchangeOnline module not working") -ForegroundColor Red
                    }
                }
                $scriptFunctions = (Get-ChildItem function: | Where-Object { $_.source -match 'Harden365.DefenderForO365' })
                $scriptFunctions | ForEach-Object {
                    try { 
                        $null = & $_.Name  -ErrorAction:SilentlyContinue
                    }
                    catch {
                        Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("ERROR --> Harden365.DefenderForO365 module not working") -ForegroundColor Red
                    }
                }
                Read-Host -Prompt "Press Enter to return_"
                MessagingMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
            }
            else { MessagingMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP }
        }
        2 {
            Write-Host $FrontStyle -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host(" CHECK AUTOFORWARDING") -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Connecting to ExchangeOnline Powershell') -ForegroundColor Green
            try {
                $null = Get-OrganizationConfig
            }
            catch { Connect-ExchangeOnline -WarningAction:SilentlyContinue -ShowBanner:$false }
            $scriptFunctions = (Get-ChildItem function: | Where-Object { $_.Name -match 'Start-EOPCheckAutoForward' })
            $scriptFunctions | ForEach-Object {
                try { 
                    $null = & $_.Name  -ErrorAction:SilentlyContinue
                }
                catch {
                    Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("ERROR --> Harden365.ExchangeOnline module not working") -ForegroundColor Red
                }
            }
            Read-Host -Prompt "Press Enter to return_"
            MessagingMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
        }
        3 {
            Write-Host $FrontStyle -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("CHECK DNS RECORDS (SPF/DKIM/DMARC)") -ForegroundColor Red
            try {
                $null = Get-OrganizationConfig
            }
            catch { Connect-ExchangeOnline -WarningAction:SilentlyContinue -ShowBanner:$false }
            $scriptFunctions = (Get-ChildItem function: | Where-Object { $_.Name -match 'Start-AuditSPFDKIMDMARC' })
            $scriptFunctions | ForEach-Object {
                try { 
                    $null = & $_.Name  -ErrorAction:SilentlyContinue
                }
                catch {
                    Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("ERROR --> Harden365.DKIM module not working") -ForegroundColor Red
                }
            }
            Read-Host -Prompt "Press Enter to return_"
            MessagingMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
        }
        4 {
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("Do you want to configure DKIM (Y/N) : ") -NoNewline -ForegroundColor Yellow ; $QMS4 = Read-Host
            if ($QMS4 -eq 'Y') { 
                Write-Host $FrontStyle -ForegroundColor Red
                Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("DKIM CONFIGURATION)") -ForegroundColor Red
                Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Connecting to ExchangeOnline Powershell') -ForegroundColor Green
                try {
                    $null = Get-OrganizationConfig
                }
                catch { Connect-ExchangeOnline -WarningAction:SilentlyContinue -ShowBanner:$false }
                $scriptFunctions = (Get-ChildItem function: | Where-Object { ($_.source -match 'Harden365.DKIM') -and ($_.Name -notmatch 'Start-AuditSPFDKIMDMARC') })
                $scriptFunctions | ForEach-Object {
                    try { 
                        $null = & $_.Name -ErrorAction:SilentlyContinue
                    }
                    catch {
                        Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("ERROR --> Harden365.DKIM module not working") -ForegroundColor Red
                    }
                }
                Read-Host -Prompt "Press Enter to return_"
                MessagingMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
            }
            else { MessagingMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP }
        }
        5 {
            MainMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
        }
        Default {
            MessagingMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
        }
    }
}

function ApplicationMenu() {
    Param(
        [String]$TenantName,
        [String]$TenantEdition,
        [String]$O365ATP
    )
    
    $ApplicationMenu = CreateMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP -MenuTitle "HARDEN 365 - APPLICATIONS" -MenuOptions @("Audit Applications", "Hardening Outlook", "Hardening MS Teams", "Hardening Sharepoint", "Hardening PowerPlatform", "<- Return")
    
    switch ($ApplicationMenu) {
        0 {
            Write-Host $FrontStyle -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("AUDIT APPLICATIONS") -ForegroundColor Red
            <# commented because not used
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Connecting to MSOlService Powershell') -ForegroundColor Green
            try {
                $null = Get-MsolDomain -ErrorAction Stop
            }
            catch { Connect-MsolService -WarningAction:SilentlyContinue }
            #>
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Connecting to ExchangeOnline Powershell') -ForegroundColor Green
            
            try {
                $null = Get-OrganizationConfig
            }
            catch {
                Connect-ExchangeOnline -WarningAction:SilentlyContinue -ShowBanner:$false
            }

            try {
                $null = Get-CsTenant -Erroraction Stop
            }
            catch { 
                try { 
                    Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("Connecting to MS Teams Powershell") -ForegroundColor green
                    $null = Connect-MicrosoftTeams -ErrorAction Stop
                }
                catch {
                    $null = Connect-MicrosoftTeams
                }
            }
            
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Connecting to MSCommerce Powershell') -ForegroundColor Green

            $scriptFunctions = (Get-ChildItem function: | Where-Object { ($_.source -match 'Harden365.AuditApplications') -and ($_.Name -notmatch 'Start-OUTCheckAddIns') })

            $scriptFunctions | ForEach-Object {
                try { 
                    $null = & $_.Name  -ErrorAction:SilentlyContinue
                }
                catch {
                    Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("ERROR --> Harden365.AuditApplications module not working") -ForegroundColor Red
                }
            }

            Read-Host -Prompt "Press Enter to return_"
            ApplicationMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
            
            break
        }

        1 {
            Write-Host $FrontStyle -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("HARDENING OUTLOOK") -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Connecting to ExchangeOnline Powershell') -ForegroundColor Green
            try {
                $null = Get-OrganizationConfig
            }
            catch { Connect-ExchangeOnline -WarningAction:SilentlyContinue -ShowBanner:$false }
            $scriptFunctions = (Get-ChildItem function: | Where-Object { $_.source -match 'Harden365.Outlook' })
            $scriptFunctions | ForEach-Object {
                try { 
                    $null = & $_.Name -ErrorAction:SilentlyContinue 
                }
                catch {
                    Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("ERROR --> Harden365.Teams module not working") -ForegroundColor Red
                }
            }
            Read-Host -Prompt "Press Enter to return_"
            ApplicationMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP

            break
        }

        2 {
            Write-Host $FrontStyle -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("HARDENING MICROSOFT TEAMS") -ForegroundColor Red
            try {
                $null = Get-CsTenant 
            }
            catch { 
                $null = Connect-MicrosoftTeams
            }

            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Connecting to MSTeams Powershell') -ForegroundColor Green
            $scriptFunctions = (Get-ChildItem function: | Where-Object { $_.source -match 'Harden365.Teams' })
            $scriptFunctions | ForEach-Object {
                try { 
                    $null = & $_.Name -ErrorAction:SilentlyContinue
                }
                catch {
                    Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("ERROR --> Harden365.Teams module not working") -ForegroundColor Red
                }
            }
            Read-Host -Prompt "Press Enter to return_"
            ApplicationMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP

            break
        }

        3 {
            Write-Host $FrontStyle -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("HARDENING SHAREPOINT") -ForegroundColor Red
            try {
                $null = Get-OrganizationConfig
            }
            catch { Connect-ExchangeOnline -WarningAction:SilentlyContinue -ShowBanner:$false }
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Connecting to SPO Powershell') -ForegroundColor Green
            $URLSPO = (Get-OrganizationConfig).SharePointUrl -split '.sharepoint.com/'
            $AdminSPO = $URLSPO -join '-admin.sharepoint.com'
            Connect-SPOService -Url $AdminSPO -Credential $Credential -WarningAction:SilentlyContinue
            $scriptFunctions = (Get-ChildItem function: | Where-Object { $_.source -match 'Harden365.Sharepoint' })
            $scriptFunctions | ForEach-Object {
                try { 
                    $null = & $_.Name -ErrorAction:SilentlyContinue
                }
                catch {
                    Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("ERROR --> Harden365.Sharepoint module not working") -ForegroundColor Red
                }
            }
            Read-Host -Prompt "Press Enter to return_"
            ApplicationMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP

            break
        }

        4 {
            Write-Host $FrontStyle -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("HARDENING POWERPLATFORM") -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Connecting to MSOlService Powershell') -ForegroundColor Green
            try {
                $null = Get-MsolDomain -ErrorAction Stop
            }
            catch {
                Connect-MSOlService -WarningAction:SilentlyContinue
            }

            $scriptFunctions = (Get-ChildItem function: | Where-Object { $_.source -match 'Harden365.PowerPlatform' })
            $scriptFunctions | ForEach-Object {
                try { 
                    $null = & $_.Name -ErrorAction:SilentlyContinue
                }
                catch {
                    Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("ERROR --> Harden365.PowerPlatform module not working") -ForegroundColor Red
                }
            }
            Read-Host -Prompt "Press Enter to return_"
            ApplicationMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP

            break
        }

        5 {
            MainMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
            break
        }
        Default {
            ApplicationMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
            break
        }
    }
}

function DeviceMenu() {
    Param(
        [String]$TenantName,
        [String]$TenantEdition,
        [String]$O365ATP,
        [String]$AccessSecret
    )

    $DeviceMenu = CreateMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP -MenuTitle "HARDEN 365 - DEVICE" -MenuOptions @("Install Harden365 App", "Hardening Intune", "<- Return")
    
    switch ($DeviceMenu) {
        0 {
            Write-Host $FrontStyle -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("INSTALL HARDEN365 APP") -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Connecting to Graph') -ForegroundColor Green
            $scriptFunctions = (Get-ChildItem function: | Where-Object { $_.Name -match 'Start-Harden365App' })
            $scriptFunctions | ForEach-Object {
                try { 
                    $null = & $_.Name -ErrorAction:SilentlyContinue
                }
                catch {}
            }
            Read-Host -Prompt "Press Enter to return_"
            DeviceMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP -AccessSecret $AccessSecret
            break
        }
        1 {
            Write-Host $FrontStyle -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("HARDENING INTUNE") -ForegroundColor Red
            Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-host ('Connecting to Graph') -ForegroundColor Green
            if (!$AccessSecret) {
                Write-Host $(Get-Date -UFormat "%m-%d-%Y %T ") -NoNewline ; Write-Host("Please insert Secret of Harden365App :") -NoNewline -ForegroundColor Yellow ; $AccessSecret = Read-Host
            }

            $scriptFunctions = (Get-ChildItem function: | Where-Object { $_.source -match 'Harden365.Device' })
            $scriptFunctions | ForEach-Object {
                try { 
                    $null = & $_.Name -Accesssecret $AccessSecret -ErrorAction:SilentlyContinue
                }
                catch {}
            }
            Read-Host -Prompt "Press Enter to return_"
            DeviceMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP -AccessSecret $AccessSecret

            break
        }
        2 {
            MainMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
            break
        }
        Default {
            DeviceMenu -TenantName $TenantName -TenantEdition $TenantEdition -O365ATP $O365ATP
            break
        }
    }
}