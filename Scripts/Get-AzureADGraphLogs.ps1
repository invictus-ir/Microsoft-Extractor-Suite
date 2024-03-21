function Get-ADSignInLogsGraph {
    <#
    .SYNOPSIS
    Gets of sign ins logs.

    .DESCRIPTION
    The Get-ADSignInLogsGraph GraphAPI cmdlet collects the contents of the Azure Active Directory sign-in logs.
    The output will be written to: Output\AzureAD\SignInLogsGraph.json

    .PARAMETER startDate
	The startDate parameter specifies the date from which all logs need to be collected.

	.PARAMETER endDate
    The Before parameter specifies the date endDate which all logs need to be collected.

    .PARAMETER OutputDir
    outputDir is the parameter specifying the output directory.
    Default: Output\AzureAD

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the JSON output file.
    Default: UTF8

    .PARAMETER Application
    Application is the parameter specifying App-only access (access without a user) for authentication and authorization.
    Default: Delegated access (access on behalf a user)

    .PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

    .EXAMPLE
    Get-ADSignInLogsGraph
    Get all audit logs of sign ins.

    .EXAMPLE
    Get-ADSignInLogsGraph -Application
    Get all audit logs of sign ins via application authentication.

    .EXAMPLE
    Get-ADSignInLogsGraph -endDate 2023-04-12
    Get audit logs before 2023-04-12.

    .EXAMPLE
    Get-ADSignInLogsGraph -startDate 2023-04-12
    Get audit logs after 2023-04-12.
    #>
    [CmdletBinding()]
    param(
        [string]$startDate,
		[string]$endDate,
        [string]$OutputDir,
        [string]$UserIds,
        [string]$Encoding = "UTF8",
        [switch]$Application
    )

    if (!($Application.IsPresent)) {
        Connect-MgGraph -Scopes AuditLog.Read.All, Directory.Read.All -NoWelcome
    }

    try {
        $areYouConnected = Get-MgBetaAuditLogSignIn -ErrorAction stop
    }
    catch {
        Write-LogFile -Message "[WARNING] You must call Connect-MgGraph before running this script" -Color "Red"
        break
    }

    if ($Encoding -eq "" ){
		$Encoding = "UTF8"
	}

	write-logFile -Message "[INFO] Running Get-ADSignInLogsGraph" -Color "Green"

	if ($outputDir -eq "" ){
		$outputDir = "Output\AzureAD"
		if (!(test-path $outputDir)) {
			write-logFile -Message "[INFO] Creating the following directory: $outputDir"
			New-Item -ItemType Directory -Force -Name $outputDir | Out-Null
		}
	}

	else {
		if (Test-Path -Path $OutputDir) {
			write-LogFile -Message "[INFO] Custom directory set to: $OutputDir"
		}
	
		else {
			write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
			write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script"
		}
	}

    $date = Get-Date -Format 'yyyyMMddHHmmss'
    $filePath = Join-Path -Path $outputDir -ChildPath "$($date)-SignInLogsGraph.json"

	if ($Before -and $After) {
		write-logFile -Message "[WARNING] Please provide only one of either a start date or end date" -Color "Red"
		return
	}
	
	$filter = ""
	if ($endDate) {
		$filter = "createdDateTime lt $endDate"
	}
	if ($startDate) {
		$filter = "createdDateTime gt $startDate"
	}

	if ($UserIds) {
		if ($filter) {
			$filter = " and $filter"
		}
		Get-MgBetaAuditLogSignIn -ExpandProperty * -All -Filter "userPrincipalName eq '$UserIds' $filter" |  Select-Object AppDisplayName,AppId,AppTokenProtectionStatus,AppliedConditionalAccessPolicies,ConditionsNotSatisfied,ConditionsSatisfied,AppliedConditionalAccessPoliciesDisplayName,EnforcedGrantControls,EnforcedSessionControls,AppliedConditionalAccessPoliciesId,AppliedConditionalAccessPoliciesResult,AppliedConditionalAccessPolicies2,AppliedEventListeners,AuthenticationAppDeviceDetails,AppVersion,ClientApp,DeviceId,OperatingSystem,AuthenticationAppPolicyEvaluationDetails,AdminConfiguration,AuthenticationEvaluation,AuthenticationAppPolicyEvaluationDetailsPolicyName,AuthenticationAppPolicyEvaluationDetailsStatus,AuthenticationContextClassReferences,AuthenticationDetails,AuthenticationMethodsUsed,AuthenticationProcessingDetails,AuthenticationProtocol,AuthenticationRequirement,AuthenticationRequirementPolicies,Detail,RequirementProvider,AutonomousSystemNumber,AzureResourceId,ClientAppUsed,ClientCredentialType,ConditionalAccessStatus,CorrelationId,@{N='CreatedDateTime';E={$_.CreatedDateTime.ToString()}},CrossTenantAccessType,DeviceDetail,Browser,DeviceDetailDeviceId,DisplayName,IsCompliant,IsManaged,DeviceDetailOperatingSystem,TrustType,FederatedCredentialId,FlaggedForReview,HomeTenantId,HomeTenantName,IPAddress,IPAddressFromResourceProvider,Id,IncomingTokenType,IsInteractive,IsTenantRestricted,Location,City,CountryOrRegion,State,ManagedServiceIdentity,AssociatedResourceId,FederatedTokenId,FederatedTokenIssuer,MsiType,MfaDetail,AuthDetail,AuthMethod,NetworkLocationDetails,OriginalRequestId,OriginalTransferMethod,PrivateLinkDetails,PolicyId,PolicyName,PolicyTenantId,PrivateLinkDetailsResourceId,ProcessingTimeInMilliseconds,ResourceDisplayName,ResourceId,ResourceServicePrincipalId,ResourceTenantId,RiskDetail,RiskEventTypesV2,RiskLevelAggregated,RiskLevelDuringSignIn,RiskState,ServicePrincipalCredentialKeyId,ServicePrincipalCredentialThumbprint,ServicePrincipalId,ServicePrincipalName,SessionLifetimePolicies,SignInEventTypes,SignInIdentifier,SignInIdentifierType,SignInTokenProtectionStatus,Status,StatusAdditionalDetails,TokenIssuerName,TokenIssuerType,UniqueTokenIdentifier,UserAgent,UserDisplayName,UserId,UserPrincipalName,UserType,AdditionalProperties |
			ForEach-Object {
				$_ | ConvertTo-Json -Depth 100
			} |
			Out-File -FilePath $filePath -Encoding UTF8
	} 
	else {
		Get-MgBetaAuditLogSignIn -ExpandProperty * -All -Filter $filter | Select-Object AppDisplayName,AppId,AppTokenProtectionStatus,AppliedConditionalAccessPolicies,ConditionsNotSatisfied,ConditionsSatisfied,AppliedConditionalAccessPoliciesDisplayName,EnforcedGrantControls,EnforcedSessionControls,AppliedConditionalAccessPoliciesId,AppliedConditionalAccessPoliciesResult,AppliedConditionalAccessPolicies2,AppliedEventListeners,AuthenticationAppDeviceDetails,AppVersion,ClientApp,DeviceId,OperatingSystem,AuthenticationAppPolicyEvaluationDetails,AdminConfiguration,AuthenticationEvaluation,AuthenticationAppPolicyEvaluationDetailsPolicyName,AuthenticationAppPolicyEvaluationDetailsStatus,AuthenticationContextClassReferences,AuthenticationDetails,AuthenticationMethodsUsed,AuthenticationProcessingDetails,AuthenticationProtocol,AuthenticationRequirement,AuthenticationRequirementPolicies,Detail,RequirementProvider,AutonomousSystemNumber,AzureResourceId,ClientAppUsed,ClientCredentialType,ConditionalAccessStatus,CorrelationId,@{N='CreatedDateTime';E={$_.CreatedDateTime.ToString()}},CrossTenantAccessType,DeviceDetail,Browser,DeviceDetailDeviceId,DisplayName,IsCompliant,IsManaged,DeviceDetailOperatingSystem,TrustType,FederatedCredentialId,FlaggedForReview,HomeTenantId,HomeTenantName,IPAddress,IPAddressFromResourceProvider,Id,IncomingTokenType,IsInteractive,IsTenantRestricted,Location,City,CountryOrRegion,State,ManagedServiceIdentity,AssociatedResourceId,FederatedTokenId,FederatedTokenIssuer,MsiType,MfaDetail,AuthDetail,AuthMethod,NetworkLocationDetails,OriginalRequestId,OriginalTransferMethod,PrivateLinkDetails,PolicyId,PolicyName,PolicyTenantId,PrivateLinkDetailsResourceId,ProcessingTimeInMilliseconds,ResourceDisplayName,ResourceId,ResourceServicePrincipalId,ResourceTenantId,RiskDetail,RiskEventTypesV2,RiskLevelAggregated,RiskLevelDuringSignIn,RiskState,ServicePrincipalCredentialKeyId,ServicePrincipalCredentialThumbprint,ServicePrincipalId,ServicePrincipalName,SessionLifetimePolicies,SignInEventTypes,SignInIdentifier,SignInIdentifierType,SignInTokenProtectionStatus,Status,StatusAdditionalDetails,TokenIssuerName,TokenIssuerType,UniqueTokenIdentifier,UserAgent,UserDisplayName,UserId,UserPrincipalName,UserType,AdditionalProperties |
			ForEach-Object {
				$_ | ConvertTo-Json -Depth 100
			} |
			Out-File -FilePath $filePath -Encoding UTF8
	}

	write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
}

function Get-ADAuditLogsGraph {
	<#
	.SYNOPSIS
	Get directory audit logs.

	.DESCRIPTION
	The Get-ADAuditLogsGraph GraphAPI cmdlet to collect the contents of the Azure Active Directory Audit logs.
	The output will be written to: "Output\AzureAD\AuditlogsGraph.json

	.PARAMETER startDate
	The startDate parameter specifies the date from which all logs need to be collected.
	.PARAMETER endDate
    The Before parameter specifies the date endDate which all logs need to be collected.

	.PARAMETER OutputDir
	outputDir is the parameter specifying the output directory.
	Default: Output\AzureAD

	.PARAMETER UserIds
	UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

	.PARAMETER Encoding
	Encoding is the parameter specifying the encoding of the JSON output file.
	Default: UTF8

	.PARAMETER Application
	Application is the parameter specifying App-only access (access without a user) for authentication and authorization.
	Default: Delegated access (access on behalf a user)
	
	.EXAMPLE
	Get-ADAuditLogsGraph
	Get directory audit logs.

	.EXAMPLE
	Get-ADAuditLogsGraph -Application
	Get directory audit logs via application authentication.

	.EXAMPLE
	Get-ADAuditLogsGraph -Before 2023-04-12
	Get directory audit logs before 2023-04-12.

	.EXAMPLE
	Get-ADAuditLogsGraph -After 2023-04-12
	Get directory audit logs after 2023-04-12.
	#>
		[CmdletBinding()]
		param(
			[string]$startDate,
			[string]$endDate,
			[string]$OutputDir,
			[string]$Encoding,
			[string]$UserIds,
			[switch]$Application
		)
	
		try {
			$areYouConnected = Get-MgAuditLogDirectoryAudit -ErrorAction stop
		}
		catch {
			Write-logFile -Message "[WARNING] You must call Connect-MgGraph before running this script" -Color "Red"
			break
		}
	
		if ($Encoding -eq "" ){
			$Encoding = "UTF8"
		}
		
		if (!($Application.IsPresent)) {
			Connect-MgGraph -Scopes AuditLog.Read.All, Directory.Read.All -NoWelcome
		}
	
		Write-logFile -Message "[INFO] Running Get-ADAuditLogsGraph" -Color "Green"
		
		if ($OutputDir -eq "" ){
			$OutputDir = "Output\AzureAD"
			if (!(test-path $OutputDir)) {
				New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
				write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
			}
		}
	
		else {
			if (Test-Path -Path $OutputDir) {
				write-LogFile -Message "[INFO] Custom directory set to: $OutputDir"
			}
		
			else {
				write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
				write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script"
			}
		}
	
		$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
		$filePath = "$OutputDir\$($date)-AuditlogsGraph.json"

		if ($Before -and $After) {
			write-logFile -Message "[WARNING] Please provide only one of either a start date or end date" -Color "Red"
			return
		}

		$filter = ""
		if ($endDate) {
			$filter = "activityDateTime lt $endDate"
		}
		if ($startDate) {
			$filter = "activityDateTime gt $startDate"
		}

		if ($UserIds) {
			if ($filter) {
				$filter = " and $filter"
			}
			Get-MgAuditLogDirectoryAudit -ExpandProperty * -All -Filter "initiatedBy/user/userPrincipalName eq '$Userids' $filter" | Select-Object @{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},ActivityDisplayName,AdditionalDetails,Category,CorrelationId,Id,InitiatedBy,LoggedByService,OperationType,Result,ResultReason,TargetResources,AdditionalProperties | 
				ForEach-Object {
					$_ | ConvertTo-Json -Depth 100
				} |
				Out-File -FilePath $filePath -Encoding $Encoding
		} 
		else {
			Get-MgAuditLogDirectoryAudit -ExpandProperty * -All -Filter $filter | Select-Object @{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},ActivityDisplayName,AdditionalDetails,Category,CorrelationId,Id,InitiatedBy,LoggedByService,OperationType,Result,ResultReason,TargetResources,AdditionalProperties |
				ForEach-Object {
					$_ | ConvertTo-Json -Depth 100
				} |
				Out-File -FilePath $filePath -Encoding $Encoding
		}	
		
		write-logFile -Message "[INFO] Audit logs written to $filePath" -Color "Green"
	}
	