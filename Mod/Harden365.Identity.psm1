function Start-UserConsentToApp {
     <#
        .Synopsis
         Disable User permission consent App registration
        
        .Description
         Disable User permission consent App registration

        .Notes
         Version: 01.00 -- 
         
    #>

     #SCRIPT
     if ((Get-MsolCompanyInformation).UsersPermissionToUserConsentToAppEnabled -eq $true) {
          Set-MsolCompanySettings -UsersPermissionToUserConsentToAppEnabled $false
          Write-LogInfo 'Disable User permission consent App registration' 
     }

     <# Disable User permission consent app with MSGraph - need review
     # we need to keep only the current ManagePermissionGrantsForOwnedResource.* policies
     # https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent?pivots=ms-powershell#disable-user-consent
     $currentPolicies = (Get-MgBetaPolicyAuthorizationPolicy).PermissionGrantPolicyIdsAssignedToDefaultUserRole

     $policyPrefixToKeep = "ManagePermissionGrantsForOwnedResource."

     $userConsentPolicy = 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy'
     $currentPolicies = (Get-MgBetaPolicyAuthorizationPolicy).PermissionGrantPolicyIdsAssignedToDefaultUserRole

     # Cast to array
     $newPolicies = @($currentPolicies | Where-Object { $_ -notlike "$userConsentPolicy" })

     if($null -eq $newPolicies){
          $body = @{permissionGrantPolicyIdsAssignedToDefaultUserRole=""}
     }
     else {
          $body = @{
               "permissionGrantPolicyIdsAssignedToDefaultUserRole" = $newPolicies
          }
     }

     Update-MgBetaPolicyAuthorizationPolicy -AuthorizationPolicyId 'authorizationPolicy' -BodyParameter $body
     #>
}

function Start-UserTenantCreation {
     # Remove AllowedToCreateTenants permission - need review
     <#
     if((Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions.AllowedToCreateTenants){
          Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{AllowedToCreateTenants = $false}
     }
     #>    
}