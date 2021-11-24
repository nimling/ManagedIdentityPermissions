function Set-ManagedIdentityApiPermissions {
    <#
    .SYNOPSIS
    Function for granting application permissions to a managed identity

    .DESCRIPTION
    User either object ID (recommended) or display name of the managed identity
    
    .PARAMETER ManagedIdentityDisplayName
    Display name of the managed identity
    
    .PARAMETER ManagedIdentityID
    Object ID of the managed identity
    
    .PARAMETER ApplicationName
    Display name of the application to be given access to
    
    .PARAMETER PermissionNames
    Names of permissions to be granted to the managed identity
    
    .EXAMPLE
    Set-ManagedIdentityApiPermissions -ManagedIdentityID <object ID> -PermissionNames @("<permission-name>") -ApplicationName <application name>
    
    .NOTES
    Running Connect-AzureAD -tenantID <tenant ID> with Privileged Role Administrator, Cloud Application Administrator, 
    Application Administrator or Global Administrator (required for Microsoft Graph permissions) granted to the user required.
    #>
    [CmdletBinding(DefaultParameterSetName = 'ID')]
    param (
        [Parameter(Mandatory=$true, ParameterSetName = 'Name',Position=0)]
        [string]$ManagedIdentityDisplayName,
        [Parameter(Mandatory=$true, ParameterSetName = 'ID',Position=0)]
        [string]$ManagedIdentityID,
        [Parameter(Mandatory=$true, ParameterSetName = 'Name')]
        [Parameter(Mandatory=$true, ParameterSetName = 'ID')]
        [string]$ApplicationName,
        [Parameter(Mandatory=$true, ParameterSetName = 'Name')]
        [Parameter(Mandatory=$true, ParameterSetName = 'ID')]
        [System.Object[]]$PermissionNames
    )

    # Retrieve object ID of managed identity if display name is provided.
    if ($pSCmdlet.ParameterSetName -eq 'Name') {
        $managedIdentitySP = Get-AzureADServicePrincipal -SearchString $ManagedIdentityDisplayName
        if ($managedIdentitySP.length -gt 1) {
            Write-Output "The displayname $ManagedIdentityDisplayName did not return a unique result."
            Write-Output "Try running the cmdlet with the id of the managed identity instead."
            return
        }
        elseif ($null -eq $managedIdentitySP) {
            Write-Output "No managed identity with displayname $managedIdentityName found."
            return
        }
        $ManagedIdentityID = $managedIdentitySP.ObjectId
    }

    # Get application using application display name
    $application = Get-AzureADServicePrincipal -SearchString $ApplicationName | Select-Object -first 1
    
    # Get existing app permissions names of managed identity
    $spApplicationPermissions = Get-AzureADServiceAppRoleAssignedTo -ObjectId $ManagedIdentityID -All $true | Where-Object { $_.PrincipalType -eq "ServicePrincipal" }
    $spApplicationPermissionsNames = ($application.AppRoles | Where-Object {$_.Id -in $spApplicationPermissions.Id}).Value

    foreach($pName in $PermissionNames) {
        
        if ($pName -in $spApplicationPermissionsNames) {
            Write-Output "$pName already granted to managed identity $($sp.DisplayName)."
            continue
        }
        # Retrieve all available app roles for the application.
        $appRole = $application.AppRoles | Where-Object {$_.Value -eq $pName -and $_.AllowedMemberTypes -contains "Application"}
        
        # Assign permissions to the managed identity.
        New-AzureAdServiceAppRoleAssignment -ObjectId $ManagedIdentityID -PrincipalId $ManagedIdentityID -ResourceId $application.ObjectId -Id $appRole.Id

        Write-Output "$pname granted to managed identity $($sp.DisplayName)."
    }
    return
}

function Remove-ManagedIdentityApiPermissions {
    <#
    .SYNOPSIS
    Function for removing application permissions from a managed identity.
    
    .DESCRIPTION
    User either object ID (recommended) or display name of the managed identity.
    Function removes either all permissions or permissions defined by application name and permission names.    
    
    .PARAMETER ManagedIdentityDisplayName
    Display name of the managed identity
    
    .PARAMETER ManagedIdentityID
    Object ID of the managed identity
    
    .PARAMETER ApplicationName
    Display name of the application to be given access to
    
    .PARAMETER PermissionNames
    Names of permissions to be granted to the managed identity
    
    .PARAMETER All
    Use to remove all permissions from managed identity
    
    .EXAMPLE
    An example
    
    .NOTES
    Running Connect-AzureAD -tenantID <tenant ID> with Privileged Role Administrator, Cloud Application Administrator, 
    Application Administrator or Global Administrator (required for Microsoft Graph permissions) granted to the user required.
    #>
    [CmdletBinding(DefaultParameterSetName = 'ID_All')]
    param (
        # Parameter help description
        [Parameter(Mandatory=$true, ParameterSetName = 'Name_All', Position=0)]
        [Parameter(Mandatory=$false, ParameterSetName = 'Name_PermissionSet', Position=0)]
        [string]$ManagedIdentityDisplayName,
        # Parameter help description
        [Parameter(Mandatory=$true, ParameterSetName = 'ID_All', Position=0)]
        [Parameter(Mandatory=$true, ParameterSetName = 'ID_PermissionSet', Position=0)]
        [string]$ManagedIdentityID,
        # Parameter help description
        [Parameter(Mandatory=$true, ParameterSetName = 'Name_PermissionSet')]
        [Parameter(Mandatory=$true, ParameterSetName = 'ID_PermissionSet')]
        [string]$ApplicationName,
        # Parameter help description
        [Parameter(Mandatory=$true, ParameterSetName = 'Name_PermissionSet')]
        [Parameter(Mandatory=$true, ParameterSetName = 'ID_PermissionSet')]
        [System.Object[]]$PermissionNames,
        # Parameter help description
        [Parameter(Mandatory=$false, ParameterSetName = 'Name_All')]
         [Parameter(Mandatory=$false, ParameterSetName = 'ID_All')]
        [switch]$All = $false
    )

    # Retrieve object ID of managed identity if display name is provided.
    if ($pSCmdlet.ParameterSetName -eq 'Name') {
        $managedIdentitySP = Get-AzureADServicePrincipal -SearchString $ManagedIdentityDisplayName
        if ($managedIdentitySP.length -gt 1) {
            Write-Output "The displayname $ManagedIdentityDisplayName did not return a unique result."
            Write-Output "Try running the cmdlet with the id of the managed identity instead."
            return
        }
        elseif ($null -eq $managedIdentitySP) {
            Write-Output "No managed identity with displayname $managedIdentityName found."
            return
        }
        $ManagedIdentityID = $managedIdentitySP.ObjectId
    }
    # Get Service Principal using objectId
    $sp = Get-AzureADServicePrincipal -ObjectId $ManagedIdentityID

    # Get all application permissions for the service principal
    $spApplicationPermissions = Get-AzureADServiceAppRoleAssignedTo -ObjectId $sp.ObjectId -All $true | Where-Object { $_.PrincipalType -eq "ServicePrincipal" }

    if ($All) {
        # Remove all delegated permissions
        $spApplicationPermissions | ForEach-Object {
        Remove-AzureADServiceAppRoleAssignment -ObjectId $_.PrincipalId -AppRoleAssignmentId $_.objectId

        Write-Output "All permissions removed from managed identity $($sp.DisplayName)."
        return
        }
    }
    elseif($PermissionNames.Count -lt 1){
        Write-Output "No permissions listed."
    }
    
    # Remove permissions matching input given permission names of application
    else {
        foreach($appRole in $spApplicationPermissions) {
            if ($appRole.ResourceDisplayName -eq $ApplicationName) {
                $app = Get-AzureADServicePrincipal -ObjectId $appRole.ResourceId
                if ($(($app.AppRoles | Where-Object {$_.Id -eq $appRole.Id}).Value) -in $PermissionNames) {
                    Remove-AzureADServiceAppRoleAssignment -ObjectId $appRole.PrincipalId -AppRoleAssignmentId $appRole.objectId
                    Write-Output "Permission $(($app.AppRoles | Where-Object {$_.Id -eq $appRole.Id}).Value) removed from managed identity $($sp.DisplayName)."
                }
            }
        }
    }
    return
}


# Your tenant ID.
$tenantID="<tenant-ID>"

# Managed identity object ID .
$managedIdentityID = "<object-ID>"

# Name of application to grant access to
$applicationName = "<application-name>"

# List of permissions names of the application
$permissionNames = @("<permission-1>", "<permission-2>") 

# Connect to Azure AD using tenant ID and interactive sign-in
Connect-AzureAD -TenantId $tenantID


#Set-ManagedIdentityApiPermissions -ManagedIdentityID $managedIdentityID -PermissionNames $permissionNames -ApplicationName $applicationName

#Remove-ManagedIdentityApiPermissions -ManagedIdentityID $ManagedIdentityID -All #-PermissionNames $PermissionNames #-ApplicationName "Microsoft Graph"


