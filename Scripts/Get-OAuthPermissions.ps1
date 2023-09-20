function CacheObject ($Object) {
    if ($Object) {
        if (-not $script:ObjectByObjectClassId.ContainsKey($Object.ObjectType)) {
            $script:ObjectByObjectClassId[$Object.ObjectType] = @{}
        }
        $script:ObjectByObjectClassId[$Object.ObjectType][$Object.ObjectId] = $Object
        $script:ObjectByObjectId[$Object.ObjectId] = $Object
    }
}

# Function to retrieve an object from the cache (if it's there), or from Azure AD (if not).
function GetObjectByObjectId ($ObjectId) {
    if (-not $script:ObjectByObjectId.ContainsKey($ObjectId)) {
        Write-Verbose ("Querying Azure AD for object '{0}'" -f $ObjectId)
        try {
            $object = Get-AzureADObjectByObjectId -ObjectId $ObjectId
            CacheObject -Object $object
        } catch {
            Write-Verbose "Object not found."
        }
    }
    return $script:ObjectByObjectId[$ObjectId]
}

# Function to retrieve all OAuth2PermissionGrants, either by directly listing them (-FastMode)
# or by iterating over all ServicePrincipal objects. The latter is required if there are more than
# 999 OAuth2PermissionGrants in the tenant, due to a bug in Azure AD.
function GetOAuth2PermissionGrants ([switch]$FastMode) {
    if ($FastMode) {
        Get-AzureADOAuth2PermissionGrant -All $true
    } else {
        $script:ObjectByObjectClassId['ServicePrincipal'].GetEnumerator() | ForEach-Object { $i = 0 } {
            if ($ShowProgress) {
                Write-Progress -Activity "Retrieving delegated permissions..." `
                               -Status ("Checked {0}/{1} apps" -f $i++, $servicePrincipalCount) `
                               -PercentComplete (($i / $servicePrincipalCount) * 100)
            }

            $client = $_.Value
            Get-AzureADServicePrincipalOAuth2PermissionGrant -ObjectId $client.ObjectId
        }
    }
}

function GetAzureADServicePrincipal ($ObjectId) {
	Get-AzureADServicePrincipal -ObjectId $ObjectId | ForEach-Object {
		$Output = $_
		$script:homepage = $Output.Homepage
		$script:PublisherName = $Output.PublisherName
		$script:ReplyUrls = $Output.ReplyUrls
		$script:AppDisplayName = $Output.AppDisplayName
		$script:AppId = $Output.AppId
	}
}

function Get-OAuthPermissions
{
<#
.SYNOPSIS
Lists delegated permissions (OAuth2PermissionGrants) and application permissions (AppRoleAssignments).
Script made by: https://gist.github.com/psignoret/41793f8c6211d2df5051d77ca3728c09

.DESCRIPTION
Script to list all delegated permissions and application permissions in Azure AD
The output will be written to a CSV file called "Output\OAuthPermissions\AADSPPermissions.csv".

.PARAMETER OutputDir
outputDir is the parameter specifying the output directory.
Default: Output\OAuthPermissions

.PARAMETER Encoding
Encoding is the parameter specifying the encoding of the CSV output file.
Default: UTF8

.EXAMPLE
Get-OAuthPermissions
Lists delegated permissions (OAuth2PermissionGrants) and application permissions (AppRoleAssignments).

#>

	[CmdletBinding()]
	param(
		[switch] $DelegatedPermissions,
		[switch] $ApplicationPermissions,
		[string[]] $UserProperties = @("DisplayName"),
		[string[]] $ServicePrincipalProperties = @("DisplayName"),
		[switch] $ShowProgress = $true,
		[int] $PrecacheSize = 999,
		[string] $OutputDir,
		[string]$Encoding
	)
		
	try {
        $tenant_details = Get-AzureADTenantDetail -ErrorAction stop
    } catch {
		write-logFile -Message "[WARNING] You must call Connect-Azure before running this script" -Color "Red"
		break
	}

	if ($Encoding -eq "" ){
		$Encoding = "UTF8"
	}
	
	write-logFile -Message "[INFO] Running Get-OAuthPermissions" -Color "Green"
    $date = Get-Date -Format "ddMMyyyyHHmmss" 
	
	if ($OutputDir -eq "" ){
		$OutputDir = "Output\OAuthPermissions\"
		if (!(test-path $OutputDir)) {
			write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
			New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
		}
	}

	else{
		write-LogFile -Message "[INFO] OAuth applications are collected and writen to: $OutputDir" -Color "Green"
	}

	$report = @(
	Write-Verbose ("TenantId: {0}, InitialDomain: {1}" -f `
					$tenant_details.ObjectId, `
					($tenant_details.VerifiedDomains | Where-Object { $_.Initial }).Name)

	# An in-memory cache of objects by {object ID} andy by {object class, object ID}
	$script:ObjectByObjectId = @{}
	$script:ObjectByObjectClassId = @{}

	$empty = @{} # Used later to avoid null checks

	# Get all ServicePrincipal objects and add to the cache
	Write-Verbose "Retrieving all ServicePrincipal objects..."
	Get-AzureADServicePrincipal -All $true | ForEach-Object {
		CacheObject -Object $_
	}
	$servicePrincipalCount = $script:ObjectByObjectClassId['ServicePrincipal'].Count

	if ($DelegatedPermissions -or (-not ($DelegatedPermissions -or $ApplicationPermissions))) {

		# Get one page of User objects and add to the cache
		Write-Verbose ("Retrieving up to {0} User objects..." -f $PrecacheSize)
		Get-AzureADUser -Top $PrecacheSize | Where-Object {
			CacheObject -Object $_
		}

		Write-Verbose "Testing for OAuth2PermissionGrants bug before querying..."
		$fastQueryMode = $false
		try {
			# There's a bug in Azure AD Graph which does not allow for directly listing
			# oauth2PermissionGrants if there are more than 999 of them. The following line will
			# trigger this bug (if it still exists) and throw an exception.
			$null = Get-AzureADOAuth2PermissionGrant -Top 999
			$fastQueryMode = $true
		} catch {
			if ($_.Exception.Message -and $_.Exception.Message.StartsWith("Unexpected end when deserializing array.")) {
				Write-Verbose ("Fast query for delegated permissions failed, using slow method...")
			} else {
				throw $_
			}
		}

		# Get all existing OAuth2 permission grants, get the client, resource and scope details
		Write-Verbose "Retrieving OAuth2PermissionGrants..."
		GetOAuth2PermissionGrants -FastMode:$fastQueryMode | ForEach-Object {
			$grant = $_
			GetAzureADServicePrincipal($grant.ClientId)
			if ($grant.Scope) {

				$grant.Scope.Split(" ") | Where-Object { $_ } | ForEach-Object {

					$grantDetails =  [ordered]@{
						"PermissionType" = "Delegated"
						"AppId" = $script:AppId
						"ClientObjectId" = $grant.ClientId
						"ResourceObjectId" = $grant.ResourceId
						"Permission" = $scope
						"ConsentType" = $grant.ConsentType
						"PrincipalObjectId" = $grant.PrincipalId
						"Homepage" = $script:homepage
						"PublisherName" = $script:PublisherName
						"ReplyUrls" = $null
						"ExpiryTime" = $grant.ExpiryTime
					}

					if ($null -ne $ReplyUrls) {
						$grantDetails["ReplyUrls"] = $script:ReplyUrls -join ', '
					}

					# Add properties for client and resource service principals
					if ($ServicePrincipalProperties.Count -gt 0) {

						$client = GetObjectByObjectId -ObjectId $grant.ClientId
						$resource = GetObjectByObjectId -ObjectId $grant.ResourceId

						$insertAtClient = 2
						$insertAtResource = 3
						foreach ($propertyName in $ServicePrincipalProperties) {
							$grantDetails.Insert($insertAtClient++, "Client$propertyName", $client.$propertyName)
							$insertAtResource++
							$grantDetails.Insert($insertAtResource, "Resource$propertyName", $resource.$propertyName)
							$insertAtResource ++
						}
					}

					# Add properties for principal (will all be null if there's no principal)
					if ($UserProperties.Count -gt 0) {

						$principal = $empty
						if ($grant.PrincipalId) {
							$principal = GetObjectByObjectId -ObjectId $grant.PrincipalId
						}

						foreach ($propertyName in $UserProperties) {
							$grantDetails["Principal$propertyName"] = $principal.$propertyName
						}
					}

					New-Object PSObject -Property $grantDetails
				}
			}
		}
	}

	if ($ApplicationPermissions -or (-not ($DelegatedPermissions -or $ApplicationPermissions))) {

		# Iterate over all ServicePrincipal objects and get app permissions
		Write-Verbose "Retrieving AppRoleAssignments..."
		$script:ObjectByObjectClassId['ServicePrincipal'].GetEnumerator() | ForEach-Object { $i = 0 } {

			if ($ShowProgress) {
				Write-Progress -Activity "Retrieving application permissions..." `
							-Status ("Checked {0}/{1} apps" -f $i++, $servicePrincipalCount) `
							-PercentComplete (($i / $servicePrincipalCount) * 100)
			}

			$sp = $_.Value

			GetAzureADServicePrincipal($sp.ObjectId)

			Get-AzureADServiceAppRoleAssignedTo -ObjectId $sp.ObjectId -All $true `
			| Where-Object { $_.PrincipalType -eq "ServicePrincipal" } | ForEach-Object {
				$assignment = $_

				$resource = GetObjectByObjectId -ObjectId $assignment.ResourceId
				$appRole = $resource.AppRoles | Where-Object { $_.Id -eq $assignment.Id }

				$grantDetails =  [ordered]@{
					"PermissionType" = "Application"
					"AppId" = $null
					"ClientObjectId" = $assignment.PrincipalId
					"ResourceObjectId" = $assignment.ResourceId
					"Permission" = $appRole.Value
					"IsEnabled" = $null
					"Description" = $null
					"CreationTimestamp" = $null
					"Homepage" = $script:homepage
					"PublisherName" = $script:PublisherName
					"ReplyUrls" = $null
				}

				 # Add the properties if they are available and not null or empty
				if ($null -ne $sp -and $sp.AppId) {
					$grantDetails["AppId"] = $sp.AppId
				}

				if ($null -ne $ReplyUrls) {
					$grantDetails["ReplyUrls"] = $script:ReplyUrls -join ', '
				}
			
				if ($null -ne $appRole -and $appRole.IsEnabled) {
					$grantDetails["IsEnabled"] = $appRole.IsEnabled
				}
			
				if ($null -ne $appRole -and $appRole.Description) {
					$grantDetails["Description"] = $appRole.Description
				}
			
				if ($null -ne $assignment -and $assignment.CreationTimestamp) {
					$grantDetails["CreationTimestamp"] = $assignment.CreationTimestamp
				}

				# Add properties for client and resource service principals
				if ($ServicePrincipalProperties.Count -gt 0) {

					$client = GetObjectByObjectId -ObjectId $assignment.PrincipalId         		

					$insertAtClient = 2
					$insertAtResource = 3
					foreach ($propertyName in $ServicePrincipalProperties) {
						$grantDetails.Insert($insertAtClient++, "Client$propertyName", $client.$propertyName)
						$insertAtResource++
						$grantDetails.Insert($insertAtResource, "Resource$propertyName", $resource.$propertyName)
						$insertAtResource ++
					}
				}
				
				New-Object PSObject -Property $grantDetails
			}
		}
	}
	)
   

	$report | ConvertTo-Csv | Format-Table | out-null
	$prop = $report.ForEach{ $_.PSObject.Properties.Name } | Select-Object -Unique
	$report | Select-Object $prop | Export-CSV -NoTypeInformation -Path "$OutputDir\OAuthPermissions1-$date.csv" -Encoding $Encoding

	Write-LogFile -Message "Done saving output to: $OutputDir\OAuthPermissions.csv" -Color "Green"
}