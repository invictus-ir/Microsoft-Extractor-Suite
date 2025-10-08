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
		[string] $OutputDir,
		[string] $Encoding = "UTF8",
		[ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
		[string]$LogLevel = 'Standard'
	)

    Init-Logging
	Write-LogFile -Message "=== Starting OAuth Permissions Collection ===" -Color "Cyan" -Level Standard
    
	if ($OutputDir) {
       Init-OutputDir -Component "EntraID" -SubComponent "OAuthPermissions" -FilePostfix "OAuthPermissions" -CustomOutputDir $OutputDir
    } else {
       Init-OutputDir -Component "EntraID" -SubComponent "OAuthPermissions" -FilePostfix "OAuthPermissions"
    }

	$requiredScopes = @("Application.Read.All")
    Check-GraphContext -RequiredScopes $requiredScopes

	$summary = [ordered]@{
		ServicePrincipalsProcessed = 0
		DelegatedGrantsProcessed = 0
		TotalPermissions = 0
		DelegatedCount = 0
		ApplicationCount = 0

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
	Write-LogFile -Message "[INFO] Exporting results to CSV..." -Level Standard
	$report | Export-Csv -Path $script:outputFile -NoTypeInformation -Encoding $Encoding
	$oauthPermissionsFile = $script:outputFile

	Write-LogFile -Message "[INFO] Exporting service principals to CSV..." -Level Standard
	if ($OutputDir) {
       Init-OutputDir -Component "EntraID" -SubComponent "ServicePrincipals" -FilePostfix "ServicePrincipals" -CustomOutputDir $OutputDir
    } else {
       Init-OutputDir -Component "EntraID" -SubComponent "ServicePrincipals" -FilePostfix "ServicePrincipals"
    }
	$allServicePrincipals | Select-Object AppId, AppDisplayName, AppDescription, AccountEnabled, AppOwnerOrganizationId | Export-Csv -Path $script:outputFile -NoTypeInformation -Encoding $Encoding
	$servicePrincipalsFile = $script:outputFile

	Write-LogFile -Message "[INFO] Exporting App Registrations to CSV..." -Level Standard
	if ($OutputDir) {
       Init-OutputDir -Component "EntraID" -SubComponent "AppRegistrations" -FilePostfix "AppRegistrations" -CustomOutputDir $OutputDir
    } else {
       Init-OutputDir -Component "EntraID" -SubComponent "AppRegistrations" -FilePostfix "AppRegistrations"
    }

 	Get-MgApplication -All | Select-Object Id, DisplayName, AppId, CreatedDateTime | Export-Csv -Path $script:outputFile -NoTypeInformation -Encoding $Encoding
	$appRegistrationsFile = $script:outputFile

	$summary.TotalPermissions = $summary.DelegatedCount + $summary.ApplicationCount
	$summaryOutput = [ordered]@{
		"Processing Summary" = [ordered]@{
			"Service Principals Processed" = $summary.ServicePrincipalsProcessed
			"Delegated Grants Processed" = $summary.DelegatedGrantsProcessed
		}
		"Permissions Found" = [ordered]@{
			"Total Permissions" = $summary.TotalPermissions
			"Delegated Permissions" = $summary.DelegatedCount
			"Application Permissions" = $summary.ApplicationCount
		}
		"Output Files" = [ordered]@{
			"OAuth Permissions" = $oauthPermissionsFile
			"Service Principals" = $servicePrincipalsFile
			"App Registrations" = $appRegistrationsFile
		}
	}

	Write-Summary -Summary $summaryOutput -Title "OAuth Permissions Summary" -SkipExportDetails
}