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

function Get-OAuthPermissions {
<#
.SYNOPSIS
Lists delegated permissions (OAuth2PermissionGrants) and application permissions (AppRoleAssignments).
Script inspired by: https://gist.github.com/psignoret/41793f8c6211d2df5051d77ca3728c09

.DESCRIPTION
Script to list all delegated permissions and application permissions in Azure AD
The output will be written to a CSV file.

.PARAMETER OutputDir
outputDir is the parameter specifying the output directory.
Default: Output\OAuthPermissions

.PARAMETER ShowProgress
Switch parameter to show progress bars during processing.
Default: $true

.PARAMETER Encoding
Encoding is the parameter specifying the encoding of the CSV output file.
Default: UTF8

.PARAMETER LogLevel
Specifies the level of logging:
None: No logging
Minimal: Critical errors only
Standard: Normal operational logging
Debug: Verbose logging for debugging purposes
Default: Standard

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
		[string] $OutputDir = "Output\OAuthPermissions",
		[string] $Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
	)

	Set-LogLevel -Level ([LogLevel]::$LogLevel)
	$isDebugEnabled = $script:LogLevel -eq [LogLevel]::Debug

	if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] PowerShell Version: $($PSVersionTable.PSVersion)" -Level Debug
        Write-LogFile -Message "[DEBUG] Input parameters:" -Level Debug
        Write-LogFile -Message "[DEBUG]   DelegatedPermissions: $DelegatedPermissions" -Level Debug
        Write-LogFile -Message "[DEBUG]   ApplicationPermissions: $ApplicationPermissions" -Level Debug
        Write-LogFile -Message "[DEBUG]   UserProperties: $($UserProperties -join ', ')" -Level Debug
        Write-LogFile -Message "[DEBUG]   ServicePrincipalProperties: $($ServicePrincipalProperties -join ', ')" -Level Debug
        Write-LogFile -Message "[DEBUG]   ShowProgress: $ShowProgress" -Level Debug
        Write-LogFile -Message "[DEBUG]   PrecacheSize: $PrecacheSize" -Level Debug
        Write-LogFile -Message "[DEBUG]   OutputDir: '$OutputDir'" -Level Debug
        Write-LogFile -Message "[DEBUG]   Encoding: '$Encoding'" -Level Debug
        Write-LogFile -Message "[DEBUG]   LogLevel: '$LogLevel'" -Level Debug
        
        $azureADModule = Get-Module -Name AzureAD -ErrorAction SilentlyContinue
        if ($azureADModule) {
            Write-LogFile -Message "[DEBUG] AzureAD Module Version: $($azureADModule.Version)" -Level Debug
        } else {
            Write-LogFile -Message "[DEBUG] AzureAD Module not loaded" -Level Debug
        }
    }

	$date = Get-Date -Format "ddMMyyyyHHmmss" 
	$summary = @{
        TotalPermissions = 0
        DelegatedCount = 0
        ApplicationCount = 0
        ServicePrincipalsProcessed = 0
        StartTime = Get-Date
        ProcessingTime = $null
    }
		
	try {
        $tenant_details = Get-AzureADTenantDetail -ErrorAction stop
		if ($isDebugEnabled) {
			Write-LogFile -Message "[DEBUG] Tenant details retrieved successfully:" -Level Debug
			Write-LogFile -Message "[DEBUG]   Tenant ID: $($tenant_details.ObjectId)" -Level Debug
			Write-LogFile -Message "[DEBUG]   Initial Domain: $(($tenant_details.VerifiedDomains | Where-Object { $_.Initial }).Name)" -Level Debug
			Write-LogFile -Message "[DEBUG]   Display Name: $($tenant_details.DisplayName)" -Level Debug
		}
    } catch {
		write-logFile -Message "[INFO] Ensure you are connected to Azure by running the Connect-Azure command before executing this script" -Color "Yellow" -Level Minimal
		Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
		if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Connection error details:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
        }
		throw
	}

	Write-LogFile -Message "=== Starting OAuth Permissions Collection ===" -Color "Cyan" -Level Standard
    
	if (!(test-path $OutputDir)) {
		New-Item -ItemType Directory -Force -Name $OutputDir > $null
	}
	else {
        if (!(Test-Path -Path $OutputDir)) {
            Write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
            Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script" -Level Minimal
        }
    }
	
	$report = @(
	Write-Verbose ("TenantId: {0}, InitialDomain: {1}" -f `
					$tenant_details.ObjectId, `
					($tenant_details.VerifiedDomains | Where-Object { $_.Initial }).Name)

	$script:ObjectByObjectId = @{}
	$script:ObjectByObjectClassId = @{}
	$empty = @{} # 

	Write-LogFile -Message "[INFO] Retrieving all ServicePrincipal objects..." -Level Standard
	Get-AzureADServicePrincipal -All $true | ForEach-Object {
		CacheObject -Object $_
		$summary.ServicePrincipalsProcessed++
	}
	$servicePrincipalCount = $script:ObjectByObjectClassId['ServicePrincipal'].Count

	if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] ServicePrincipal retrieval completed:" -Level Debug
        Write-LogFile -Message "[DEBUG]   Total ServicePrincipals cached: $servicePrincipalCount" -Level Debug
        Write-LogFile -Message "[DEBUG]   Cache structure initialized with $($script:ObjectByObjectClassId.Keys.Count) object types" -Level Debug
    }

	if ($DelegatedPermissions -or (-not ($DelegatedPermissions -or $ApplicationPermissions))) {
		if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Processing delegated permissions..." -Level Debug
            Write-LogFile -Message "[DEBUG]   Pre-caching $PrecacheSize users..." -Level Debug
        }
		
		Get-AzureADUser -Top $PrecacheSize | Where-Object {
			CacheObject -Object $_
		}

		$fastQueryMode = $false
		try {
			$null = Get-AzureADOAuth2PermissionGrant -Top 999
			$fastQueryMode = $true
		} catch {
			if ($_.Exception.Message -and $_.Exception.Message.StartsWith("Unexpected end when deserializing array.")) {
				Write-LogFile -Message "[ERROR] Fast query for delegated permissions failed, using slow method" -Level Minimal -Color "Red"
			} else {
				throw $_
			}
		}

		$delegatedGrantCount = 0
		GetOAuth2PermissionGrants -FastMode:$fastQueryMode | ForEach-Object {
			$grant = $_
			GetAzureADServicePrincipal($grant.ClientId)
			if ($grant.Scope) {
				$grant.Scope.Split(" ") | Where-Object { $_ } | ForEach-Object {
					$summary.DelegatedCount++
					if ($isDebugEnabled) {
                        Write-LogFile -Message "[DEBUG]     Processing permission: '$_' for app '$($script:AppDisplayName)'" -Level Debug
                    }
					$grantDetails =  [ordered]@{
						"PermissionType" = "Delegated"
						"AppId" = $script:AppId
						"ClientObjectId" = $grant.ClientId
						"ResourceObjectId" = $grant.ResourceId
						"Permission" = $_
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
		if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Delegated permissions processing completed:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Total grants processed: $delegatedGrantCount" -Level Debug
            Write-LogFile -Message "[DEBUG]   Total delegated permissions: $($summary.DelegatedCount)" -Level Debug
        }
	}

	if ($ApplicationPermissions -or (-not ($DelegatedPermissions -or $ApplicationPermissions))) {
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
				$summary.ApplicationCount++
				$assignment = $_

				$resource = GetObjectByObjectId -ObjectId $assignment.ResourceId
				$appRole = $resource.AppRoles | Where-Object { $_.Id -eq $assignment.Id }

				if ($isDebugEnabled -and $null -eq $appRole) {
                    Write-LogFile -Message "[DEBUG]     WARNING: Could not find app role with ID $($assignment.Id) for resource $($assignment.ResourceId)" -Level Debug
                }

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
	$summary.TotalPermissions = $summary.DelegatedCount + $summary.ApplicationCount
	$summary.ProcessingTime = (Get-Date) - $summary.StartTime
	$report | ConvertTo-Csv | Format-Table > $null
	$prop = $report.ForEach{ $_.PSObject.Properties.Name } | Select-Object -Unique
	$report | Select-Object $prop | Export-CSV -NoTypeInformation -Path "$OutputDir\$($date)-OAuthPermissions.csv" -Encoding $Encoding

	Write-LogFile -Message "`n=== OAuth Permissions Analysis Summary ===" -Color "Cyan" -Level Standard
	Write-LogFile -Message "Service Principals Processed: $($summary.ServicePrincipalsProcessed)" -Level Standard
	Write-LogFile -Message "Total Permissions Found: $($summary.TotalPermissions)" -Level Standard
	Write-LogFile -Message "  - Delegated Permissions: $($summary.DelegatedCount)" -Level Standard
	Write-LogFile -Message "  - Application Permissions: $($summary.ApplicationCount)" -Level Standard
	Write-LogFile -Message "`nOutput File: $OutputDir\$($date)-OAuthPermissions.csv" -Level Standard
	Write-LogFile -Message "Processing Time: $($summary.ProcessingTime.ToString('mm\:ss'))" -Color "Green" -Level Standard
	Write-LogFile -Message "===================================" -Color "Cyan" -Level Standard
}

function Get-OAuthPermissionsGraph {
	<#
	.SYNOPSIS
	Lists delegated permissions (OAuth2PermissionGrants) and application permissions (AppRoleAssignments) using Microsoft Graph API.
	
	.DESCRIPTION
	Script to list all delegated permissions and application permissions in Azure AD using Microsoft Graph API
	The output will be written to a CSV file.
	
	.PARAMETER OutputDir
	outputDir is the parameter specifying the output directory.
	Default: Output\OAuthPermissions
	
	.PARAMETER Encoding
	Encoding is the parameter specifying the encoding of the CSV output file.
	Default: UTF8
	
	.PARAMETER LogLevel
	Specifies the level of logging:
	None: No logging
	Minimal: Critical errors only
	Standard: Normal operational logging
	Debug: Verbose logging for debugging purposes
	Default: Standard
	#>
	
	[CmdletBinding()]
	param(
		[switch] $DelegatedPermissions,
		[switch] $ApplicationPermissions,
		[string] $OutputDir = "Output\OAuthPermissions",
		[string] $Encoding = "UTF8",
		[ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
		[string]$LogLevel = 'Standard'
	)

	Set-LogLevel -Level ([LogLevel]::$LogLevel)
	$isDebugEnabled = $script:LogLevel -eq [LogLevel]::Debug

	if ($isDebugEnabled) {
		Write-LogFile -Message "[DEBUG] PowerShell Version: $($PSVersionTable.PSVersion)" -Level Debug
		Write-LogFile -Message "[DEBUG] Input parameters:" -Level Debug
		Write-LogFile -Message "[DEBUG]   DelegatedPermissions: $DelegatedPermissions" -Level Debug
		Write-LogFile -Message "[DEBUG]   ApplicationPermissions: $ApplicationPermissions" -Level Debug
		Write-LogFile -Message "[DEBUG]   OutputDir: '$OutputDir'" -Level Debug
		Write-LogFile -Message "[DEBUG]   Encoding: '$Encoding'" -Level Debug
		Write-LogFile -Message "[DEBUG]   LogLevel: '$LogLevel'" -Level Debug
		
		$graphModules = Get-Module -Name Microsoft.Graph* -ErrorAction SilentlyContinue
		if ($graphModules) {
			Write-LogFile -Message "[DEBUG] Microsoft Graph Modules loaded:" -Level Debug
			foreach ($module in $graphModules) {
				Write-LogFile -Message "[DEBUG]   - $($module.Name) v$($module.Version)" -Level Debug
			}
		} else {
			Write-LogFile -Message "[DEBUG] No Microsoft Graph modules loaded" -Level Debug
		}
	}

	$date = Get-Date -Format "ddMMyyyyHHmmss"
	$summary = @{
		TotalPermissions = 0
		DelegatedCount = 0
		ApplicationCount = 0
		ServicePrincipalsProcessed = 0
		DelegatedGrantsProcessed = 0
		StartTime = Get-Date
		ProcessingTime = $null
	}

	$requiredScopes = @("Directory.Read.All", "Application.Read.All")
	$graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes

	if ($isDebugEnabled) {
		Write-LogFile -Message "[DEBUG] Graph authentication details:" -Level Debug
		Write-LogFile -Message "[DEBUG]   Required scopes: $($requiredScopes -join ', ')" -Level Debug
		Write-LogFile -Message "[DEBUG]   Authentication type: $($graphAuth.AuthType)" -Level Debug
		Write-LogFile -Message "[DEBUG]   Current scopes: $($graphAuth.Scopes -join ', ')" -Level Debug
		if ($graphAuth.MissingScopes.Count -gt 0) {
			Write-LogFile -Message "[DEBUG]   Missing scopes: $($graphAuth.MissingScopes -join ', ')" -Level Debug
		} else {
			Write-LogFile -Message "[DEBUG]   Missing scopes: None" -Level Debug
		}
	}

	Write-LogFile -Message "=== Starting OAuth Permissions Collection ===" -Color "Cyan" -Level Standard

	if (!(Test-Path $OutputDir)) {
		New-Item -ItemType Directory -Force -Path $OutputDir > $null
		if ($isDebugEnabled) {
			Write-LogFile -Message "[DEBUG] Created output directory: $OutputDir" -Level Debug
		}
	}
	else {
		if (!(Test-Path -Path $OutputDir)) {
			Write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
			Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script" -Level Minimal
		} else {
			if ($isDebugEnabled) {
				Write-LogFile -Message "[DEBUG] Using existing output directory: $OutputDir" -Level Debug
			}
		}
	}

	$script:ObjectCache = @{}
	function Get-CachedObject {
		param($Id, $Type)
		
		if (-not $script:ObjectCache.ContainsKey($Id)) {
			try {
				if ($isDebugEnabled) {
					Write-LogFile -Message "[DEBUG]     Fetching $Type with ID: $Id" -Level Debug
				}
				$object = switch ($Type) {
					'ServicePrincipal' { Get-MgServicePrincipal -ServicePrincipalId $Id }
					'User' { Get-MgUser -UserId $Id }
					'Application' { Get-MgApplication -ApplicationId $Id }
				}
				$script:ObjectCache[$Id] = $object
				if ($isDebugEnabled) {
					Write-LogFile -Message "[DEBUG]     Successfully cached $Type : $($object.DisplayName)" -Level Debug
				}
			}
			catch {
				Write-Verbose "Could not retrieve object $Id : $_"
				if ($isDebugEnabled) {
					Write-LogFile -Message "[DEBUG]     Failed to retrieve $Type $Id : $($_.Exception.Message)" -Level Debug
				}
				return $null
			}
		} else {
			if ($isDebugEnabled) {
				Write-LogFile -Message "[DEBUG]     Using cached $Type with ID: $Id" -Level Debug
			}
		}
		return $script:ObjectCache[$Id]
	}

	$report = @()
	Write-LogFile -Message "[INFO] Retrieving all ServicePrincipal objects..." -Level Standard
	if ($isDebugEnabled) {
		Write-LogFile -Message "[DEBUG] Starting ServicePrincipal retrieval via Microsoft Graph..." -Level Debug
	}

	$allServicePrincipals = Get-MgServicePrincipal -All
	$servicePrincipalCount = $allServicePrincipals.Count
	$summary.ServicePrincipalsProcessed = $servicePrincipalCount

	Write-LogFile -Message "[INFO] Successfully retrieved $servicePrincipalCount ServicePrincipal objects" -Level Standard
	if ($isDebugEnabled) {
		Write-LogFile -Message "[DEBUG] ServicePrincipal retrieval completed:" -Level Debug
		Write-LogFile -Message "[DEBUG]   Total ServicePrincipals retrieved: $servicePrincipalCount" -Level Debug
		Write-LogFile -Message "[DEBUG]   Pre-caching all service principals..." -Level Debug
	}

	Write-LogFile -Message "[INFO] Caching all ServicePrincipal objects..." -Level Standard
	$cachingCounter = 0
	foreach ($sp in $allServicePrincipals) {
		$script:ObjectCache[$sp.Id] = $sp
		$cachingCounter++
		
		# Log progress every 100 service principals
		if ($cachingCounter % 100 -eq 0) {
			Write-LogFile -Message "[INFO] Cached $cachingCounter of $servicePrincipalCount service principals..." -Level Standard
		}
		
		if ($isDebugEnabled -and ($cachingCounter % 50 -eq 0)) {
			Write-LogFile -Message "[DEBUG]   Cached ServicePrincipal: $($sp.DisplayName) (Total: $cachingCounter)" -Level Debug
		}
	}

	Write-LogFile -Message "[INFO] All ServicePrincipal objects cached successfully" -Level Standard -Color "Green"

	if ($DelegatedPermissions -or (-not ($DelegatedPermissions -or $ApplicationPermissions))) {
		Write-LogFile -Message "[INFO] Processing delegated permissions..." -Level Standard
		
		if ($isDebugEnabled) {
			Write-LogFile -Message "[DEBUG] Retrieving OAuth2PermissionGrants via Microsoft Graph..." -Level Debug
		}

		$allDelegatedGrants = Get-MgOauth2PermissionGrant -All
		Write-LogFile -Message "[INFO] Found $($allDelegatedGrants.Count) OAuth2PermissionGrants to process" -Level Standard

		$grantCounter = 0
		foreach ($grant in $allDelegatedGrants) {
			$grantCounter++
			$summary.DelegatedGrantsProcessed++
			
			$clientSp = Get-CachedObject -Id $grant.ClientId -Type 'ServicePrincipal'
			$resourceSp = Get-CachedObject -Id $grant.ResourceId -Type 'ServicePrincipal'

			# Log progress every 25 grants
			if ($grantCounter % 25 -eq 0) {
				Write-LogFile -Message "[INFO] Processing delegated grant $grantCounter of $($allDelegatedGrants.Count) - App: '$($clientSp.DisplayName)'" -Level Standard
			}
			
			if ($isDebugEnabled -and ($grantCounter % 10 -eq 0)) {
				Write-LogFile -Message "[DEBUG]   Processing grant $grantCounter of $($allDelegatedGrants.Count) for app '$($clientSp.DisplayName)'" -Level Debug
			}

			if ($grant.Scope) {
				$scopes = $grant.Scope.Split(' ')
				if ($isDebugEnabled) {
					Write-LogFile -Message "[INFO] Grant for '$($clientSp.DisplayName)' has $($scopes.Count) permissions: $($scopes -join ', ')" -Level Debug
				}
				if ($isDebugEnabled -and $scopes.Count -gt 5) {
					Write-LogFile -Message "[DEBUG]     Grant has $($scopes.Count) scopes: $($scopes -join ', ')" -Level Debug
				}

				foreach ($scope in $scopes) {
					if ($scope) {
						$summary.DelegatedCount++

						if ($isDebugEnabled -and ($summary.DelegatedCount % 25 -eq 0)) {
							Write-LogFile -Message "[DEBUG]       Processing permission: '$scope' for app '$($clientSp.DisplayName)' (Permission $($summary.DelegatedCount))" -Level Debug
						}
						
						$principalDisplayName = if ($grant.PrincipalId) {
							$principal = Get-CachedObject -Id $grant.PrincipalId -Type 'User'
							$principal.DisplayName
						} else { "" }

						$publisherName = if ($clientSp.PublisherName) {
							$clientSp.PublisherName
						} else {
							if ($clientSp.DisplayName -like "Microsoft*") { "Microsoft" } else { "" }
						}

						$AccountEnabled = $clientSp.AccountEnabled
						if ($AccountEnabled -eq $true) {
						$ApplicationStatus = "Enabled"
						}
						else {
							$ApplicationStatus = "Disabled"
						}

						$Tags = $clientSp.Tags
						if ($Tags -Contains "HideApp") {
							$ApplicationVisibility = "Hidden"
						}
						else {
							$ApplicationVisibility = "Visible"
						}

						if ($Tags -Contains "WindowsAzureActiveDirectoryOnPremApp") {
							$IsAppProxy = "Yes"
						}
						else {
							$IsAppProxy = "No"
						}

						if ($clientSp.AppRoleAssignmentRequired -eq $false) {
							$AssignmentRequired = "No"
						}
						else {
							$AssignmentRequired = "Yes"
						}

						$ServicePrincipalTypes = @()
						if ($clientSp.AppOwnerOrganizationId -eq "f8cdef31-a31e-4b4a-93e4-5f571e91255a" -or $clientSp.AppOwnerOrganizationId -eq "72f988bf-86f1-41af-91ab-2d7cd011db47") { $ServicePrincipalTypes += "Microsoft Application" }
						if ($clientSp.ServicePrincipalType -eq "ManagedIdentity") { $ServicePrincipalTypes += "Managed Identity" }
						if ($clientSp.Tags -contains "WindowsAzureActiveDirectoryIntegratedApp") { $ServicePrincipalTypes += "Enterprise Application" }
						$ApplicationType = $ServicePrincipalTypes -join " & "
						
						$grantDetails = [ordered]@{
							"PermissionType"         = "Delegated"
							"AppId"                  = $clientSp.AppId
							"ClientObjectId"         = $grant.ClientId
							"AppDisplayName"      	 = $clientSp.DisplayName
							"ResourceObjectId"       = $grant.ResourceId
							"ResourceDisplayName"    = $resourceSp.DisplayName
							"Permission"             = $scope
							"ConsentType"            = $grant.ConsentType
							"PrincipalObjectId"      = $grant.PrincipalId
							"PrincipalDisplayName"   = $principalDisplayName
							"Homepage"               = $clientSp.Homepage
							"PublisherName"          = $publisherName
							"ReplyUrls"              = ($clientSp.ReplyUrls -join ', ')
							"ExpiryTime"             = $grant.ExpiryTime
							"CreatedDateTime" = if ($clientSp.AdditionalProperties.ContainsKey('createdDateTime')) {
								$clientSp.AdditionalProperties['createdDateTime']
							} else {
								$null
							}
							"AppOwnerOrganizationId" = $clientSp.AppOwnerOrganizationId
							"ApplicationStatus"      = $ApplicationStatus
							"ApplicationVisibility"  = $ApplicationVisibility 
							"AssignmentRequired"     = $AssignmentRequired 
							"IsAppProxy"             = $IsAppProxy 
							"PublisherDisplayName"   = $clientSp.VerifiedPublisher.DisplayName
							"VerifiedPublisherId"    = $clientSp.VerifiedPublisher.VerifiedPublisherId
							"AddedDateTime"          = $clientSp.VerifiedPublisher.AddedDateTime 
							"SignInAudience"         = $clientSp.SignInAudience 
							"ApplicationType"        = $ApplicationType 
						}

						$report += [PSCustomObject]$grantDetails
					}
				}
			}
		}

		Write-LogFile -Message "[INFO] Delegated permissions processing completed - Found $($summary.DelegatedCount) delegated permissions from $($summary.DelegatedGrantsProcessed) grants" -Level Standard -Color "Green"
		if ($isDebugEnabled) {
			Write-LogFile -Message "[DEBUG] Delegated permissions processing completed:" -Level Debug
			Write-LogFile -Message "[DEBUG]   Total grants processed: $($summary.DelegatedGrantsProcessed)" -Level Debug
			Write-LogFile -Message "[DEBUG]   Total delegated permissions: $($summary.DelegatedCount)" -Level Debug
		}
	}

	if ($ApplicationPermissions -or (-not ($DelegatedPermissions -or $ApplicationPermissions))) {
		Write-LogFile -Message "[INFO] Processing application permissions..." -Level Standard
		if ($isDebugEnabled) {
			Write-LogFile -Message "[DEBUG] Processing application permissions..." -Level Debug
		}
		
		$appCounter = 0
		foreach ($sp in $allServicePrincipals) {
			$appCounter++
			
			# Log progress every 25 apps
			if ($appCounter % 25 -eq 0) {
				Write-LogFile -Message "[INFO] Processing application permissions for app $appCounter of $servicePrincipalCount - '$($sp.DisplayName)'" -Level Standard
			}
			
			if ($ShowProgress) {
				Write-Progress -Activity "Retrieving application permissions..." `
					-Status ("Checked {0}/{1} apps" -f $appCounter, $servicePrincipalCount) `
					-PercentComplete (($appCounter / $servicePrincipalCount) * 100)
			}

			if ($isDebugEnabled -and ($appCounter % 50 -eq 0)) {
				Write-LogFile -Message "[DEBUG]   Processing application permissions for app $appCounter of $servicePrincipalCount - '$($sp.DisplayName)'" -Level Debug
			}

			$appRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All
			
			if ($isDebugEnabled -and $appRoleAssignments.Count -gt 0) {
				Write-LogFile -Message "[DEBUG]     Found $($appRoleAssignments.Count) app role assignments for $($sp.DisplayName)" -Level Debug
			}

			foreach ($assignment in $appRoleAssignments) {
				$summary.ApplicationCount++
				
				$resourceSp = Get-CachedObject -Id $assignment.ResourceId -Type 'ServicePrincipal'
				$appRole = $resourceSp.AppRoles | Where-Object { $_.Id -eq $assignment.AppRoleId }
				if ($isDebugEnabled) {
					Write-LogFile -Message "[INFO] Application permission: '$($appRole.Value)' for app '$($sp.DisplayName)' on resource '$($resourceSp.DisplayName)'" -Level Debug
				}

				if ($isDebugEnabled -and $null -eq $appRole) {
					Write-LogFile -Message "[DEBUG]     WARNING: Could not find app role with ID $($assignment.AppRoleId) for resource $($assignment.ResourceId)" -Level Debug
				}

				$publisherName = if ($sp.PublisherName) {
					$sp.PublisherName
				} else {
					if ($sp.DisplayName -like "Microsoft*") { "Microsoft" } else { "" }
				}

				$AccountEnabled = $sp.AccountEnabled
				if ($AccountEnabled -eq "True") {
					$ApplicationStatus = "Enabled"
				}
				else {
					$ApplicationStatus = "Disabled"
				}

				$Tags = $sp.Tags
				if ($Tags -Contains "HideApp") {
					$ApplicationVisibility = "Hidden"
				}
				else {
					$ApplicationVisibility = "Visible"
				}

				if ($Tags -Contains "WindowsAzureActiveDirectoryOnPremApp") {
					$IsAppProxy = "Yes"
				}
				else {
					$IsAppProxy = "No"
				}

				if ($sp.AppRoleAssignmentRequired -eq $false) {
					$AssignmentRequired = "No"
				}
				else {
					$AssignmentRequired = "Yes"
				}

				$ServicePrincipalTypes = @()
				if ($sp.AppOwnerOrganizationId -eq "f8cdef31-a31e-4b4a-93e4-5f571e91255a" -or $sp.AppOwnerOrganizationId -eq "72f988bf-86f1-41af-91ab-2d7cd011db47") { $ServicePrincipalTypes += "Microsoft Application" }
				if ($sp.ServicePrincipalType -eq "ManagedIdentity") { $ServicePrincipalTypes += "Managed Identity" }
				if ($sp.Tags -contains "WindowsAzureActiveDirectoryIntegratedApp") { $ServicePrincipalTypes += "Enterprise Application" }
				$ApplicationType = $ServicePrincipalTypes -join " & "

				$grantDetails = [ordered]@{
					"PermissionType"         = "Application"
					"AppId"                  = $sp.AppId
					"ClientObjectId"         = $assignment.PrincipalId
					"AppDisplayName"      	 = $sp.DisplayName
					"ResourceObjectId"       = $assignment.ResourceId
					"ResourceDisplayName"    = $resourceSp.DisplayName
					"Permission"             = $appRole.Value
					"ConsentType"            = "AllPrincipals"
					"PrincipalObjectId"      = $null
					"PrincipalDisplayName"   = ""
					"Homepage"               = $sp.Homepage
					"PublisherName"          = $publisherName
					"ReplyUrls"              = ($sp.ReplyUrls -join ', ')
					"IsEnabled"              = $appRole.IsEnabled
					"Description"            = $appRole.Description
					"CreationTimestamp"      = $assignment.CreatedDateTime
					"CreatedDateTime"        = $sp.AdditionalProperties.createdDateTime
					"AppOwnerOrganizationId" = $sp.AppOwnerOrganizationId
					"ApplicationStatus"      = $ApplicationStatus
					"ApplicationVisibility"  = $ApplicationVisibility 
					"AssignmentRequired"     = $AssignmentRequired
					"IsAppProxy"             = $IsAppProxy
					"PublisherDisplayName"   = $sp.VerifiedPublisher.DisplayName
					"VerifiedPublisherId"    = $sp.VerifiedPublisher.VerifiedPublisherId
					"AddedDateTime"          = $sp.VerifiedPublisher.AddedDateTime
					"SignInAudience"         = $sp.SignInAudience 
					"ApplicationType"        = $ApplicationType
				}

				$report += [PSCustomObject]$grantDetails
			}
		}

		Write-LogFile -Message "[INFO] Application permissions processing completed - Found $($summary.ApplicationCount) application permissions" -Level Standard -Color "Green"
		if ($isDebugEnabled) {
			Write-LogFile -Message "[DEBUG] Application permissions processing completed:" -Level Debug
			Write-LogFile -Message "[DEBUG]   Total application permissions: $($summary.ApplicationCount)" -Level Debug
		}
	}

	# Export results
	$summary.TotalPermissions = $summary.DelegatedCount + $summary.ApplicationCount
	$summary.ProcessingTime = (Get-Date) - $summary.StartTime

	Write-LogFile -Message "[INFO] Exporting results to CSV..." -Level Standard
	if ($isDebugEnabled) {
		Write-LogFile -Message "[DEBUG] Exporting results to CSV..." -Level Debug
		Write-LogFile -Message "[DEBUG]   Total records to export: $($report.Count)" -Level Debug
	}

	$outputPath = Join-Path $OutputDir "$($date)-OAuthPermissions.csv"
	$report | Export-CSV -NoTypeInformation -Path $outputPath -Encoding $Encoding

	Write-LogFile -Message "[INFO] Export completed successfully" -Level Standard -Color "Green"
	if ($isDebugEnabled) {
		Write-LogFile -Message "[DEBUG] Export completed successfully" -Level Debug
		Write-LogFile -Message "[DEBUG]   Output file: $outputPath" -Level Debug
		Write-LogFile -Message "[DEBUG]   File size: $(if (Test-Path $outputPath) { (Get-Item $outputPath).Length } else { 'File not found' }) bytes" -Level Debug
		Write-LogFile -Message "[DEBUG] Performance metrics:" -Level Debug
		Write-LogFile -Message "[DEBUG]   Processing time: $($summary.ProcessingTime.ToString('mm\:ss\.fff'))" -Level Debug
		Write-LogFile -Message "[DEBUG]   Records per second: $([math]::Round($summary.TotalPermissions / $summary.ProcessingTime.TotalSeconds, 2))" -Level Debug
	}

	Write-LogFile -Message "`n=== OAuth Permissions Analysis Summary ===" -Color "Cyan" -Level Standard
	Write-LogFile -Message "Service Principals Processed: $($summary.ServicePrincipalsProcessed)" -Level Standard
	Write-LogFile -Message "Delegated Grants Processed: $($summary.DelegatedGrantsProcessed)" -Level Standard
	Write-LogFile -Message "Total Permissions Found: $($summary.TotalPermissions)" -Level Standard
	Write-LogFile -Message "  - Delegated Permissions: $($summary.DelegatedCount)" -Level Standard
	Write-LogFile -Message "  - Application Permissions: $($summary.ApplicationCount)" -Level Standard
	Write-LogFile -Message "`nOutput File: $outputPath" -Level Standard
	Write-LogFile -Message "Processing Time: $($summary.ProcessingTime.ToString('mm\:ss'))" -Color "Green" -Level Standard
	Write-LogFile -Message "===================================" -Color "Cyan" -Level Standard
}