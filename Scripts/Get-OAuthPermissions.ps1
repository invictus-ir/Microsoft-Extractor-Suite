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
        [ValidateSet('None', 'Minimal', 'Standard')]
        [string]$LogLevel = 'Standard'
	)

	Set-LogLevel -Level ([LogLevel]::$LogLevel)
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
    } catch {
		write-logFile -Message "[INFO] Ensure you are connected to Azure by running the Connect-Azure command before executing this script" -Color "Yellow" -Level Minimal
		Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
		throw
	}

	Write-LogFile -Message "=== Starting OAuth Permissions Collection ===" -Color "Cyan" -Level Minimal
    
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

	if ($DelegatedPermissions -or (-not ($DelegatedPermissions -or $ApplicationPermissions))) {
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

		GetOAuth2PermissionGrants -FastMode:$fastQueryMode | ForEach-Object {
			$grant = $_
			GetAzureADServicePrincipal($grant.ClientId)
			if ($grant.Scope) {
				$grant.Scope.Split(" ") | Where-Object { $_ } | ForEach-Object {
					$summary.DelegatedCount++
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

function Get-OAuthPermissionGraph {
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
Default: Standard
#>

    [CmdletBinding()]
    param(
        [switch] $DelegatedPermissions,
        [switch] $ApplicationPermissions,
        [string] $OutputDir = "Output\OAuthPermissions",
        [string] $Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard')]
        [string]$LogLevel = 'Standard'
    )

	Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $date = Get-Date -Format "ddMMyyyyHHmmss"
    $summary = @{
        TotalPermissions = 0
        DelegatedCount = 0
        ApplicationCount = 0
        ServicePrincipalsProcessed = 0
        StartTime = Get-Date
        ProcessingTime = $null
    }

	$requiredScopes = @("Directory.Read.All", "Application.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes

	Write-LogFile -Message "=== Starting OAuth Permissions Collection ===" -Color "Cyan" -Level Minimal

	if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir > $null
    }
    else {
        if (!(Test-Path -Path $OutputDir)) {
            Write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
            Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script" -Level Minimal
        }
    }

	$script:ObjectCache = @{}
	function Get-CachedObject {
		param($Id, $Type)
		
		if (-not $script:ObjectCache.ContainsKey($Id)) {
			try {
				$object = switch ($Type) {
					'ServicePrincipal' { Get-MgServicePrincipal -ServicePrincipalId $Id }
					'User' { Get-MgUser -UserId $Id }
					'Application' { Get-MgApplication -ApplicationId $Id }
				}
				$script:ObjectCache[$Id] = $object
			}
			catch {
				Write-Verbose "Could not retrieve object $Id : $_"
				return $null
			}
		}
		return $script:ObjectCache[$Id]
	}

	$report = @()
	Write-LogFile -Message "[INFO] Retrieving all ServicePrincipal objects..." -Level Standard
	$allServicePrincipals = Get-MgServicePrincipal -All
	$servicePrincipalCount = $allServicePrincipals.Count
	$summary.ServicePrincipalsProcessed = $servicePrincipalCount

	foreach ($sp in $allServicePrincipals) {
		$script:ObjectCache[$sp.Id] = $sp
	}

	if ($DelegatedPermissions -or (-not ($DelegatedPermissions -or $ApplicationPermissions))) {
		Write-LogFile -Message "[INFO] Processing delegated permissions..." -Level Standard
		$allDelegatedGrants = Get-MgOauth2PermissionGrant -All

		foreach ($grant in $allDelegatedGrants) {
			$clientSp = Get-CachedObject -Id $grant.ClientId -Type 'ServicePrincipal'
			$resourceSp = Get-CachedObject -Id $grant.ResourceId -Type 'ServicePrincipal'

			if ($grant.Scope) {
				foreach ($scope in $grant.Scope.Split(' ')) {
					if ($scope) {
						$summary.DelegatedCount++
						
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
                            #"CreatedDateTime"        = $clientSp.AdditionalProperties.CreatedDateTime
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
                            "PublisherDisplayName"   = $clientSp.VerifiedPublisher.DisplayName #
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
	}

	if ($ApplicationPermissions -or (-not ($DelegatedPermissions -or $ApplicationPermissions))) {
		Write-LogFile -Message "[INFO] Processing application permissions..." -Level Standard
		
		$i = 0
		foreach ($sp in $allServicePrincipals) {
			if ($ShowProgress) {
				Write-Progress -Activity "Retrieving application permissions..." `
					-Status ("Checked {0}/{1} apps" -f $i++, $servicePrincipalCount) `
					-PercentComplete (($i / $servicePrincipalCount) * 100)
			}

			$appRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All
			foreach ($assignment in $appRoleAssignments) {
				$summary.ApplicationCount++
				
				$resourceSp = Get-CachedObject -Id $assignment.ResourceId -Type 'ServicePrincipal'
				$appRole = $resourceSp.AppRoles | Where-Object { $_.Id -eq $assignment.AppRoleId }

				$publisherName = if ($sp.PublisherName) {
					$sp.PublisherName
				} else {
					if ($sp.DisplayName -like "Microsoft*") { "Microsoft" } else { "" }
				}

				$AccountEnabled = $sp.AccountEnabled # true if the service principal account is enabled; otherwise, false. If set to false, then no users are able to sign in to this app, even if they're assigned to it.
                if ($Tags -eq "True") {
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
	}

	# Export results
	$summary.TotalPermissions = $summary.DelegatedCount + $summary.ApplicationCount
	$summary.ProcessingTime = (Get-Date) - $summary.StartTime

	$outputPath = Join-Path $OutputDir "$($date)-OAuthPermissions.csv"
	$report | Export-CSV -NoTypeInformation -Path $outputPath -Encoding $Encoding

	Write-LogFile -Message "`n=== OAuth Permissions Analysis Summary ===" -Color "Cyan" -Level Standard
	Write-LogFile -Message "Service Principals Processed: $($summary.ServicePrincipalsProcessed)" -Level Standard
	Write-LogFile -Message "Total Permissions Found: $($summary.TotalPermissions)" -Level Standard
	Write-LogFile -Message "  - Delegated Permissions: $($summary.DelegatedCount)" -Level Standard
	Write-LogFile -Message "  - Application Permissions: $($summary.ApplicationCount)" -Level Standard
	Write-LogFile -Message "`nOutput File: $outputPath" -Level Standard
	Write-LogFile -Message "Processing Time: $($summary.ProcessingTime.ToString('mm\:ss'))" -Color "Green" -Level Standard
	Write-LogFile -Message "===================================" -Color "Cyan" -Level Standard
}