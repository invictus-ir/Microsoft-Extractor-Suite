function Get-ADSignInLogsGraph {
<#
    .SYNOPSIS
	Gets of sign ins logs.

	.DESCRIPTION
	The Get-ADSignInLogsGraph GraphAPI cmdlet collects the contents of the Azure Active Directory sign-in logs.
	The output will be written to: Output\AzureAD\SignInLogsGraph.json

	.PARAMETER After
	The After parameter specifies the date from which all logs need to be collected.

	.PARAMETER Before
	The Before parameter specifies the date before which all logs need to be collected.

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
	Get-ADSignInLogsGraph -Before 2023-04-12
	Get audit logs before 2023-04-12.

	.EXAMPLE
	Get-ADSignInLogsGraph -After 2023-04-12
	Get audit logs after 2023-04-12.
#>
	[CmdletBinding()]
	param(
		[string]$After,
		[string]$Before,
		[string]$outputDir,
		[string]$UserIds,
		[string]$Encoding,
		[switch]$Application
	)

	if (!($Application.IsPresent)) {
		Connect-MgGraph -Scopes AuditLog.Read.All, Directory.Read.All -NoWelcome
	}

	try {
		$areYouConnected = Get-MgBetaAuditLogSignIn -ErrorAction stop
	}
	catch {
		write-logFile -Message "[WARNING] You must call Connect-GraphAPI -Scopes AuditLog.Read.All, Directory.Read.All before running this script" -Color "Red"
		break
	}

	if ($Encoding -eq "" ){
		$Encoding = "UTF8"
	}

	write-logFile -Message "[INFO] Running Get-ADSignInLogsGraph" -Color "Green"

	$date = [datetime]::Now.ToString('yyyyMMddHHmmss')

	if ($outputDir -eq "" ){
		$outputDir = "Output\AzureAD\$date"
		if (!(test-path $outputDir)) {
			write-logFile -Message "[INFO] Creating the following directory: $outputDir"
			New-Item -ItemType Directory -Force -Name $outputDir | Out-Null
		}
	}

	$filePath = "$outputDir\SignInLogsGraph.json"

	if (($After -eq "") -and ($Before -eq "")) {
		write-logFile -Message "[INFO] Collecting the Azure Active Directory sign in logs"

		if ($Userids){
			$signInLogs = Get-MgBetaAuditLogSignIn -ExpandProperty * -All -Filter "userPrincipalName eq '$Userids'" | Select-Object AppDisplayName,AppId,AppTokenProtectionStatus,AppliedConditionalAccessPolicies,ConditionsNotSatisfied,ConditionsSatisfied,AppliedConditionalAccessPoliciesDisplayName,EnforcedGrantControls,EnforcedSessionControls,AppliedConditionalAccessPoliciesId,AppliedConditionalAccessPoliciesResult,AppliedConditionalAccessPolicies2,AppliedEventListeners,AuthenticationAppDeviceDetails,AppVersion,ClientApp,DeviceId,OperatingSystem,AuthenticationAppPolicyEvaluationDetails,AdminConfiguration,AuthenticationEvaluation,AuthenticationAppPolicyEvaluationDetailsPolicyName,AuthenticationAppPolicyEvaluationDetailsStatus,AuthenticationContextClassReferences,AuthenticationDetails,AuthenticationMethodsUsed,AuthenticationProcessingDetails,AuthenticationProtocol,AuthenticationRequirement,AuthenticationRequirementPolicies,Detail,RequirementProvider,AutonomousSystemNumber,AzureResourceId,ClientAppUsed,ClientCredentialType,ConditionalAccessStatus,CorrelationId,@{N='CreatedDateTime';E={$_.CreatedDateTime.ToString()}},CrossTenantAccessType,DeviceDetail,Browser,DeviceDetailDeviceId,DisplayName,IsCompliant,IsManaged,DeviceDetailOperatingSystem,TrustType,FederatedCredentialId,FlaggedForReview,HomeTenantId,HomeTenantName,IPAddress,IPAddressFromResourceProvider,Id,IncomingTokenType,IsInteractive,IsTenantRestricted,Location,City,CountryOrRegion,State,ManagedServiceIdentity,AssociatedResourceId,FederatedTokenId,FederatedTokenIssuer,MsiType,MfaDetail,AuthDetail,AuthMethod,NetworkLocationDetails,OriginalRequestId,OriginalTransferMethod,PrivateLinkDetails,PolicyId,PolicyName,PolicyTenantId,PrivateLinkDetailsResourceId,ProcessingTimeInMilliseconds,ResourceDisplayName,ResourceId,ResourceServicePrincipalId,ResourceTenantId,RiskDetail,RiskEventTypesV2,RiskLevelAggregated,RiskLevelDuringSignIn,RiskState,ServicePrincipalCredentialKeyId,ServicePrincipalCredentialThumbprint,ServicePrincipalId,ServicePrincipalName,SessionLifetimePolicies,SignInEventTypes,SignInIdentifier,SignInIdentifierType,SignInTokenProtectionStatus,Status,StatusAdditionalDetails,TokenIssuerName,TokenIssuerType,UniqueTokenIdentifier,UserAgent,UserDisplayName,UserId,UserPrincipalName,UserType,AdditionalProperties
			$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

			write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
		}
		else{
			$signInLogs = Get-MgBetaAuditLogSignIn -ExpandProperty * -All | Select-Object AppDisplayName,AppId,AppTokenProtectionStatus,AppliedConditionalAccessPolicies,ConditionsNotSatisfied,ConditionsSatisfied,AppliedConditionalAccessPoliciesDisplayName,EnforcedGrantControls,EnforcedSessionControls,AppliedConditionalAccessPoliciesId,AppliedConditionalAccessPoliciesResult,AppliedConditionalAccessPolicies2,AppliedEventListeners,AuthenticationAppDeviceDetails,AppVersion,ClientApp,DeviceId,OperatingSystem,AuthenticationAppPolicyEvaluationDetails,AdminConfiguration,AuthenticationEvaluation,AuthenticationAppPolicyEvaluationDetailsPolicyName,AuthenticationAppPolicyEvaluationDetailsStatus,AuthenticationContextClassReferences,AuthenticationDetails,AuthenticationMethodsUsed,AuthenticationProcessingDetails,AuthenticationProtocol,AuthenticationRequirement,AuthenticationRequirementPolicies,Detail,RequirementProvider,AutonomousSystemNumber,AzureResourceId,ClientAppUsed,ClientCredentialType,ConditionalAccessStatus,CorrelationId,@{N='CreatedDateTime';E={$_.CreatedDateTime.ToString()}},CrossTenantAccessType,DeviceDetail,Browser,DeviceDetailDeviceId,DisplayName,IsCompliant,IsManaged,DeviceDetailOperatingSystem,TrustType,FederatedCredentialId,FlaggedForReview,HomeTenantId,HomeTenantName,IPAddress,IPAddressFromResourceProvider,Id,IncomingTokenType,IsInteractive,IsTenantRestricted,Location,City,CountryOrRegion,State,ManagedServiceIdentity,AssociatedResourceId,FederatedTokenId,FederatedTokenIssuer,MsiType,MfaDetail,AuthDetail,AuthMethod,NetworkLocationDetails,OriginalRequestId,OriginalTransferMethod,PrivateLinkDetails,PolicyId,PolicyName,PolicyTenantId,PrivateLinkDetailsResourceId,ProcessingTimeInMilliseconds,ResourceDisplayName,ResourceId,ResourceServicePrincipalId,ResourceTenantId,RiskDetail,RiskEventTypesV2,RiskLevelAggregated,RiskLevelDuringSignIn,RiskState,ServicePrincipalCredentialKeyId,ServicePrincipalCredentialThumbprint,ServicePrincipalId,ServicePrincipalName,SessionLifetimePolicies,SignInEventTypes,SignInIdentifier,SignInIdentifierType,SignInTokenProtectionStatus,Status,StatusAdditionalDetails,TokenIssuerName,TokenIssuerType,UniqueTokenIdentifier,UserAgent,UserDisplayName,UserId,UserPrincipalName,UserType,AdditionalProperties
			$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

			write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
		}
	}

	elseif (($After -ne "") -and ($Before -eq "")) {
		if ($Userids){
			write-logFile -Message "[INFO] Collecting the Azure Active Directory sign in logs on or after $After"

			$signInLogs = Get-MgBetaAuditLogSignIn -ExpandProperty * -All -Filter "userPrincipalName eq '$Userids' and createdDateTime gt $After" | Select-Object AppDisplayName,AppId,AppTokenProtectionStatus,AppliedConditionalAccessPolicies,ConditionsNotSatisfied,ConditionsSatisfied,AppliedConditionalAccessPoliciesDisplayName,EnforcedGrantControls,EnforcedSessionControls,AppliedConditionalAccessPoliciesId,AppliedConditionalAccessPoliciesResult,AppliedConditionalAccessPolicies2,AppliedEventListeners,AuthenticationAppDeviceDetails,AppVersion,ClientApp,DeviceId,OperatingSystem,AuthenticationAppPolicyEvaluationDetails,AdminConfiguration,AuthenticationEvaluation,AuthenticationAppPolicyEvaluationDetailsPolicyName,AuthenticationAppPolicyEvaluationDetailsStatus,AuthenticationContextClassReferences,AuthenticationDetails,AuthenticationMethodsUsed,AuthenticationProcessingDetails,AuthenticationProtocol,AuthenticationRequirement,AuthenticationRequirementPolicies,Detail,RequirementProvider,AutonomousSystemNumber,AzureResourceId,ClientAppUsed,ClientCredentialType,ConditionalAccessStatus,CorrelationId,@{N='CreatedDateTime';E={$_.CreatedDateTime.ToString()}},CrossTenantAccessType,DeviceDetail,Browser,DeviceDetailDeviceId,DisplayName,IsCompliant,IsManaged,DeviceDetailOperatingSystem,TrustType,FederatedCredentialId,FlaggedForReview,HomeTenantId,HomeTenantName,IPAddress,IPAddressFromResourceProvider,Id,IncomingTokenType,IsInteractive,IsTenantRestricted,Location,City,CountryOrRegion,State,ManagedServiceIdentity,AssociatedResourceId,FederatedTokenId,FederatedTokenIssuer,MsiType,MfaDetail,AuthDetail,AuthMethod,NetworkLocationDetails,OriginalRequestId,OriginalTransferMethod,PrivateLinkDetails,PolicyId,PolicyName,PolicyTenantId,PrivateLinkDetailsResourceId,ProcessingTimeInMilliseconds,ResourceDisplayName,ResourceId,ResourceServicePrincipalId,ResourceTenantId,RiskDetail,RiskEventTypesV2,RiskLevelAggregated,RiskLevelDuringSignIn,RiskState,ServicePrincipalCredentialKeyId,ServicePrincipalCredentialThumbprint,ServicePrincipalId,ServicePrincipalName,SessionLifetimePolicies,SignInEventTypes,SignInIdentifier,SignInIdentifierType,SignInTokenProtectionStatus,Status,StatusAdditionalDetails,TokenIssuerName,TokenIssuerType,UniqueTokenIdentifier,UserAgent,UserDisplayName,UserId,UserPrincipalName,UserType,AdditionalProperties
			$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

			write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
		}
		else{
			write-logFile -Message "[INFO] Collecting the Azure Active Directory sign in logs on or after $After"

			$signInLogs = Get-MgBetaAuditLogSignIn -ExpandProperty * -All -Filter "createdDateTime gt $After" | Select-Object AppDisplayName,AppId,AppTokenProtectionStatus,AppliedConditionalAccessPolicies,ConditionsNotSatisfied,ConditionsSatisfied,AppliedConditionalAccessPoliciesDisplayName,EnforcedGrantControls,EnforcedSessionControls,AppliedConditionalAccessPoliciesId,AppliedConditionalAccessPoliciesResult,AppliedConditionalAccessPolicies2,AppliedEventListeners,AuthenticationAppDeviceDetails,AppVersion,ClientApp,DeviceId,OperatingSystem,AuthenticationAppPolicyEvaluationDetails,AdminConfiguration,AuthenticationEvaluation,AuthenticationAppPolicyEvaluationDetailsPolicyName,AuthenticationAppPolicyEvaluationDetailsStatus,AuthenticationContextClassReferences,AuthenticationDetails,AuthenticationMethodsUsed,AuthenticationProcessingDetails,AuthenticationProtocol,AuthenticationRequirement,AuthenticationRequirementPolicies,Detail,RequirementProvider,AutonomousSystemNumber,AzureResourceId,ClientAppUsed,ClientCredentialType,ConditionalAccessStatus,CorrelationId,@{N='CreatedDateTime';E={$_.CreatedDateTime.ToString()}},CrossTenantAccessType,DeviceDetail,Browser,DeviceDetailDeviceId,DisplayName,IsCompliant,IsManaged,DeviceDetailOperatingSystem,TrustType,FederatedCredentialId,FlaggedForReview,HomeTenantId,HomeTenantName,IPAddress,IPAddressFromResourceProvider,Id,IncomingTokenType,IsInteractive,IsTenantRestricted,Location,City,CountryOrRegion,State,ManagedServiceIdentity,AssociatedResourceId,FederatedTokenId,FederatedTokenIssuer,MsiType,MfaDetail,AuthDetail,AuthMethod,NetworkLocationDetails,OriginalRequestId,OriginalTransferMethod,PrivateLinkDetails,PolicyId,PolicyName,PolicyTenantId,PrivateLinkDetailsResourceId,ProcessingTimeInMilliseconds,ResourceDisplayName,ResourceId,ResourceServicePrincipalId,ResourceTenantId,RiskDetail,RiskEventTypesV2,RiskLevelAggregated,RiskLevelDuringSignIn,RiskState,ServicePrincipalCredentialKeyId,ServicePrincipalCredentialThumbprint,ServicePrincipalId,ServicePrincipalName,SessionLifetimePolicies,SignInEventTypes,SignInIdentifier,SignInIdentifierType,SignInTokenProtectionStatus,Status,StatusAdditionalDetails,TokenIssuerName,TokenIssuerType,UniqueTokenIdentifier,UserAgent,UserDisplayName,UserId,UserPrincipalName,UserType,AdditionalProperties
			$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

			write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
		}
	}

	elseif (($Before -ne "") -and ($After -eq "")) {
		if ($Userids){
			write-logFile -Message "[INFO] Collecting the Azure Active Directory sign in logs on or before $Before"

			$signInLogs = Get-MgBetaAuditLogSignIn -ExpandProperty * -All -Filter "userPrincipalName eq '$Userids' and createdDateTime lt $Before" | Select-Object AppDisplayName,AppId,AppTokenProtectionStatus,AppliedConditionalAccessPolicies,ConditionsNotSatisfied,ConditionsSatisfied,AppliedConditionalAccessPoliciesDisplayName,EnforcedGrantControls,EnforcedSessionControls,AppliedConditionalAccessPoliciesId,AppliedConditionalAccessPoliciesResult,AppliedConditionalAccessPolicies2,AppliedEventListeners,AuthenticationAppDeviceDetails,AppVersion,ClientApp,DeviceId,OperatingSystem,AuthenticationAppPolicyEvaluationDetails,AdminConfiguration,AuthenticationEvaluation,AuthenticationAppPolicyEvaluationDetailsPolicyName,AuthenticationAppPolicyEvaluationDetailsStatus,AuthenticationContextClassReferences,AuthenticationDetails,AuthenticationMethodsUsed,AuthenticationProcessingDetails,AuthenticationProtocol,AuthenticationRequirement,AuthenticationRequirementPolicies,Detail,RequirementProvider,AutonomousSystemNumber,AzureResourceId,ClientAppUsed,ClientCredentialType,ConditionalAccessStatus,CorrelationId,@{N='CreatedDateTime';E={$_.CreatedDateTime.ToString()}},CrossTenantAccessType,DeviceDetail,Browser,DeviceDetailDeviceId,DisplayName,IsCompliant,IsManaged,DeviceDetailOperatingSystem,TrustType,FederatedCredentialId,FlaggedForReview,HomeTenantId,HomeTenantName,IPAddress,IPAddressFromResourceProvider,Id,IncomingTokenType,IsInteractive,IsTenantRestricted,Location,City,CountryOrRegion,State,ManagedServiceIdentity,AssociatedResourceId,FederatedTokenId,FederatedTokenIssuer,MsiType,MfaDetail,AuthDetail,AuthMethod,NetworkLocationDetails,OriginalRequestId,OriginalTransferMethod,PrivateLinkDetails,PolicyId,PolicyName,PolicyTenantId,PrivateLinkDetailsResourceId,ProcessingTimeInMilliseconds,ResourceDisplayName,ResourceId,ResourceServicePrincipalId,ResourceTenantId,RiskDetail,RiskEventTypesV2,RiskLevelAggregated,RiskLevelDuringSignIn,RiskState,ServicePrincipalCredentialKeyId,ServicePrincipalCredentialThumbprint,ServicePrincipalId,ServicePrincipalName,SessionLifetimePolicies,SignInEventTypes,SignInIdentifier,SignInIdentifierType,SignInTokenProtectionStatus,Status,StatusAdditionalDetails,TokenIssuerName,TokenIssuerType,UniqueTokenIdentifier,UserAgent,UserDisplayName,UserId,UserPrincipalName,UserType,AdditionalProperties
			$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

			write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
		}
		else{
			write-logFile -Message "[INFO] Collecting the Azure Active Directory sign in logs on or before $Before"

			$signInLogs = Get-MgBetaAuditLogSignIn -ExpandProperty * -All -Filter "createdDateTime lt $Before" | Select-Object AppDisplayName,AppId,AppTokenProtectionStatus,AppliedConditionalAccessPolicies,ConditionsNotSatisfied,ConditionsSatisfied,AppliedConditionalAccessPoliciesDisplayName,EnforcedGrantControls,EnforcedSessionControls,AppliedConditionalAccessPoliciesId,AppliedConditionalAccessPoliciesResult,AppliedConditionalAccessPolicies2,AppliedEventListeners,AuthenticationAppDeviceDetails,AppVersion,ClientApp,DeviceId,OperatingSystem,AuthenticationAppPolicyEvaluationDetails,AdminConfiguration,AuthenticationEvaluation,AuthenticationAppPolicyEvaluationDetailsPolicyName,AuthenticationAppPolicyEvaluationDetailsStatus,AuthenticationContextClassReferences,AuthenticationDetails,AuthenticationMethodsUsed,AuthenticationProcessingDetails,AuthenticationProtocol,AuthenticationRequirement,AuthenticationRequirementPolicies,Detail,RequirementProvider,AutonomousSystemNumber,AzureResourceId,ClientAppUsed,ClientCredentialType,ConditionalAccessStatus,CorrelationId,@{N='CreatedDateTime';E={$_.CreatedDateTime.ToString()}},CrossTenantAccessType,DeviceDetail,Browser,DeviceDetailDeviceId,DisplayName,IsCompliant,IsManaged,DeviceDetailOperatingSystem,TrustType,FederatedCredentialId,FlaggedForReview,HomeTenantId,HomeTenantName,IPAddress,IPAddressFromResourceProvider,Id,IncomingTokenType,IsInteractive,IsTenantRestricted,Location,City,CountryOrRegion,State,ManagedServiceIdentity,AssociatedResourceId,FederatedTokenId,FederatedTokenIssuer,MsiType,MfaDetail,AuthDetail,AuthMethod,NetworkLocationDetails,OriginalRequestId,OriginalTransferMethod,PrivateLinkDetails,PolicyId,PolicyName,PolicyTenantId,PrivateLinkDetailsResourceId,ProcessingTimeInMilliseconds,ResourceDisplayName,ResourceId,ResourceServicePrincipalId,ResourceTenantId,RiskDetail,RiskEventTypesV2,RiskLevelAggregated,RiskLevelDuringSignIn,RiskState,ServicePrincipalCredentialKeyId,ServicePrincipalCredentialThumbprint,ServicePrincipalId,ServicePrincipalName,SessionLifetimePolicies,SignInEventTypes,SignInIdentifier,SignInIdentifierType,SignInTokenProtectionStatus,Status,StatusAdditionalDetails,TokenIssuerName,TokenIssuerType,UniqueTokenIdentifier,UserAgent,UserDisplayName,UserId,UserPrincipalName,UserType,AdditionalProperties
			$signInLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding

			write-logFile -Message "[INFO] Sign-in logs written to $filePath" -Color "Green"
		}
	}

	else {
		write-logFile -Message "[WARNING] Please only provide a start date or end date" -Color "Red"
	}

}

function Get-ADAuditLogsGraph {
<#
	.SYNOPSIS
	Get directory audit logs.

	.DESCRIPTION
	The Get-ADAuditLogsGraph GraphAPI cmdlet to collect the contents of the Azure Active Directory Audit logs.
	The output will be written to: "Output\AzureAD\AuditlogsGraph.json

	.PARAMETER After
	The After parameter specifies the date from which all logs need to be collected.

	.PARAMETER Before
	The Before parameter specifies the date before which all logs need to be collected.

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
		[string]$After,
		[string]$Before,
		[string]$OutputDir,
		[string]$Encoding,
		[string]$UserIds,
		[switch]$Application
	)

	try {
		$areYouConnected = Get-MgAuditLogDirectoryAudit -ErrorAction stop
	}
	catch {
		Write-logFile -Message "[WARNING] You must call Connect-GraphAPI before running this script" -Color "Red"
		break
	}

	if ($Encoding -eq "" ){
		$Encoding = "UTF8"
	}
	
	if (!($Application.IsPresent)) {
		Connect-MgGraph -Scopes AuditLog.Read.All, Directory.Read.All -NoWelcome
	}

	Write-logFile -Message "[INFO] Running Get-ADAuditLogsGraph" -Color "Green"
	
	$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 

	if ($OutputDir -eq "" ){
		$OutputDir = "Output\AzureAD\$date"
		if (!(test-path $OutputDir)) {
			write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
			New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
		}
	}

	$filePath = "$OutputDir\AuditlogsGraph.json"

	if (($After -eq "") -and ($Before -eq "")) {
		Write-logFile -Message "[INFO] Collecting the Directory audit logs"

		if ($Userids){
			$auditLogs = Get-MgAuditLogDirectoryAudit -All -Filter "initiatedBy/user/userPrincipalName eq '$Userids'" | Select-Object @{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},ActivityDisplayName,AdditionalDetails,Category,CorrelationId,Id,InitiatedBy,LoggedByService,OperationType,Result,ResultReason,TargetResources,AdditionalProperties
			$auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding
			
			Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
		}
		else {
			$auditLogs = Get-MgAuditLogDirectoryAudit -All | Select-Object @{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},ActivityDisplayName,AdditionalDetails,Category,CorrelationId,Id,InitiatedBy,LoggedByService,OperationType,Result,ResultReason,TargetResources,AdditionalProperties
			$auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding
			
			Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
		}
	}

	elseif (($After -ne "") -and ($Before -eq "")) {
		Write-logFile -Message "[INFO] Collecting the Directory audit logs on or after $After"

		if ($Userids){
			$auditLogs = Get-MgAuditLogDirectoryAudit -All -Filter "initiatedBy/user/userPrincipalName eq '$Userids' and activityDateTime gt $After" | Select-Object @{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},ActivityDisplayName,AdditionalDetails,Category,CorrelationId,Id,InitiatedBy,LoggedByService,OperationType,Result,ResultReason,TargetResources,AdditionalProperties
			$auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding
			
			Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
		}
		else {
			$auditLogs = Get-MgAuditLogDirectoryAudit -All -Filter "activityDateTime gt $After" | Select-Object @{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},ActivityDisplayName,AdditionalDetails,Category,CorrelationId,Id,InitiatedBy,LoggedByService,OperationType,Result,ResultReason,TargetResources,AdditionalProperties
			$auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding
			
			Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
		}
	}

	elseif (($Before -ne "") -and ($After -eq "")) {
		Write-logFile -Message "[INFO] Collecting the Directory audit logs logs on or before $Before"

		if ($Userids){
			$auditLogs = Get-MgAuditLogDirectoryAudit -All -Filter "initiatedBy/user/userPrincipalName eq '$Userids' and activityDateTime lt $Before" | Select-Object @{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},ActivityDisplayName,AdditionalDetails,Category,CorrelationId,Id,InitiatedBy,LoggedByService,OperationType,Result,ResultReason,TargetResources,AdditionalProperties
			$auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding
			
			Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
		}
		else {
			$auditLogs = Get-MgAuditLogDirectoryAudit -All -Filter "activityDateTime lt $Before" | Select-Object @{N='ActivityDateTime';E={$_.ActivityDateTime.ToString()}},ActivityDisplayName,AdditionalDetails,Category,CorrelationId,Id,InitiatedBy,LoggedByService,OperationType,Result,ResultReason,TargetResources,AdditionalProperties
			$auditLogs | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Encoding $Encoding
			
			Write-logFile -Message "[INFO] Directory audit logs written to $filePath" -Color "Green"
		}
	}

	else {
		Write-logFile -Message "[WARNING] Please only provide a start date or end date" -Color "Red"
	}
}
