function Get-ADSignInLogsGraph {
    <#
    .SYNOPSIS
    Gets of sign-ins logs.

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

	.PARAMETER MergeOutput
    MergeOutput is the parameter specifying if you wish to merge outputs to a single file
    Default: No

    .PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

    .EXAMPLE
    Get-ADSignInLogsGraph
    Get all audit logs of sign-ins.

    .EXAMPLE
    Get-ADSignInLogsGraph -Application
    Get all audit logs of sign-ins via application authentication.

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
		[switch]$MergeOutput,
        [string]$OutputDir,
        [string]$UserIds,
        [string]$Encoding = "UTF8",
        [switch]$Application,
		[string]$Interval
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
	
	if ($Interval -eq "") {
		$Interval = 1440
		Write-LogFile -Message "[INFO] Setting the Interval to the default value of 1440"
	}

	write-logFile -Message "[INFO] Running Get-ADSignInLogsGraph" -Color "Green"

	$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
	if ($OutputDir -eq "" ){
		$OutputDir = "Output\AzureAD\$date"
		if (!(test-path $OutputDir)) {
			write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
			New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
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

		if ($UserIds){
		Write-LogFile -Message "[INFO] UserID's eq $($UserIds)"
	}

	StartDateAz
	EndDate

    $date = Get-Date -Format 'yyyyMMddHHmmss'
    $filePath = Join-Path -Path $outputDir -ChildPath "$($date)-SignInLogsGraph.json"

	[DateTime]$currentStart = $script:StartDate
	[DateTime]$currentEnd = $script:EndDate
	[DateTime]$lastLog = $script:EndDate
	$currentDay = 0  

	Write-LogFile -Message "[INFO] Extracting all available Directory Sign-in Logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-dd")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-dd"))" -Color "Green"
	if($currentStart -gt $script:EndDate){
		Write-LogFile -Message "[ERROR] $($currentStart.ToString("yyyy-MM-dd")) is greather than $($script:EndDate.ToString("yyyy-MM-dd")) - are you sure you put in the correct year? Exiting!" -Color "Red"
		return
	}

	while ($currentStart -lt $script:EndDate) {			
		$currentEnd = $currentStart.AddMinutes($Interval)       
		if ($UserIds){
			Write-LogFile -Message "[INFO] Collecting Directory Sign-in logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-dd")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-dd"))."
			try{
				[Array]$results =  Get-MgBetaAuditLogSignIn -ExpandProperty * -All -Filter "UserPrincipalName eq '$($Userids)' and createdDateTime lt $($currentEnd.ToString("yyyy-MM-dd")) and createdDateTime gt $($currentStart.ToString("yyyy-MM-dd"))" |  Select-Object AppDisplayName,AppId,AppTokenProtectionStatus,AppliedConditionalAccessPolicies,ConditionsNotSatisfied,ConditionsSatisfied,AppliedConditionalAccessPoliciesDisplayName,EnforcedGrantControls,EnforcedSessionControls,AppliedConditionalAccessPoliciesId,AppliedConditionalAccessPoliciesResult,AppliedConditionalAccessPolicies2,AppliedEventListeners,AuthenticationAppDeviceDetails,AppVersion,ClientApp,DeviceId,OperatingSystem,AuthenticationAppPolicyEvaluationDetails,AdminConfiguration,AuthenticationEvaluation,AuthenticationAppPolicyEvaluationDetailsPolicyName,AuthenticationAppPolicyEvaluationDetailsStatus,AuthenticationContextClassReferences,@{N='AuthDetailsAuthenticationMethod';E={$_.AuthenticationDetails.AuthenticationMethod.ToString()}},@{N='AuthDetailsAuthenticationMethodDetail';E={$_.AuthenticationDetails.AuthenticationMethodDetail.ToString()}},@{N='AuthDetailsAuthenticationStepDateTime';E={$_.AuthenticationDetails.AuthenticationStepDateTime.ToString()}},@{N='AuthDetailsAuthenticationStepRequirement';E={$_.AuthenticationDetails.AuthenticationStepRequirement.ToString()}},@{N='AuthDetailsAuthenticationStepResultDetail';E={$_.AuthenticationDetails.AuthenticationStepResultDetail.ToString()}},@{N='AuthDetailsSucceeded';E={$_.AuthenticationDetails.Succeeded.ToString()}},AuthenticationMethodsUsed,AuthenticationProcessingDetails,AuthenticationProtocol,AuthenticationRequirement,AuthenticationRequirementPolicies,Detail,RequirementProvider,AutonomousSystemNumber,AzureResourceId,ClientAppUsed,ClientCredentialType,ConditionalAccessStatus,CorrelationId,@{N='CreatedDateTime';E={$_.CreatedDateTime.ToString()}},CrossTenantAccessType,DeviceDetail,Browser,DeviceDetailDeviceId,DisplayName,IsCompliant,IsManaged,DeviceDetailOperatingSystem,TrustType,FederatedCredentialId,FlaggedForReview,HomeTenantId,HomeTenantName,IPAddress,IPAddressFromResourceProvider,Id,IncomingTokenType,IsInteractive,IsTenantRestricted,Location,City,CountryOrRegion,State,ManagedServiceIdentity,AssociatedResourceId,FederatedTokenId,FederatedTokenIssuer,MsiType,MfaDetail,AuthDetail,AuthMethod,NetworkLocationDetails,OriginalRequestId,OriginalTransferMethod,PrivateLinkDetails,PolicyId,PolicyName,PolicyTenantId,PrivateLinkDetailsResourceId,ProcessingTimeInMilliseconds,ResourceDisplayName,ResourceId,ResourceServicePrincipalId,ResourceTenantId,RiskDetail,RiskEventTypesV2,RiskLevelAggregated,RiskLevelDuringSignIn,RiskState,ServicePrincipalCredentialKeyId,ServicePrincipalCredentialThumbprint,ServicePrincipalId,ServicePrincipalName,SessionLifetimePolicies,SignInEventTypes,SignInIdentifier,SignInIdentifierType,SignInTokenProtectionStatus,Status,StatusAdditionalDetails,TokenIssuerName,TokenIssuerType,UniqueTokenIdentifier,UserAgent,UserDisplayName,UserId,UserPrincipalName,UserType,AdditionalProperties
			}
			catch{
				Start-Sleep -Seconds 20
				[Array]$results =  Get-MgBetaAuditLogSignIn -ExpandProperty * -All -Filter "UserPrincipalName eq '$($Userids)' and createdDateTime lt $($currentEnd.ToString("yyyy-MM-dd")) and createdDateTime gt $($currentStart.ToString("yyyy-MM-dd"))" |  Select-Object AppDisplayName,AppId,AppTokenProtectionStatus,AppliedConditionalAccessPolicies,ConditionsNotSatisfied,ConditionsSatisfied,AppliedConditionalAccessPoliciesDisplayName,EnforcedGrantControls,EnforcedSessionControls,AppliedConditionalAccessPoliciesId,AppliedConditionalAccessPoliciesResult,AppliedConditionalAccessPolicies2,AppliedEventListeners,AuthenticationAppDeviceDetails,AppVersion,ClientApp,DeviceId,OperatingSystem,AuthenticationAppPolicyEvaluationDetails,AdminConfiguration,AuthenticationEvaluation,AuthenticationAppPolicyEvaluationDetailsPolicyName,AuthenticationAppPolicyEvaluationDetailsStatus,AuthenticationContextClassReferences,@{N='AuthDetailsAuthenticationMethod';E={$_.AuthenticationDetails.AuthenticationMethod.ToString()}},@{N='AuthDetailsAuthenticationMethodDetail';E={$_.AuthenticationDetails.AuthenticationMethodDetail.ToString()}},@{N='AuthDetailsAuthenticationStepDateTime';E={$_.AuthenticationDetails.AuthenticationStepDateTime.ToString()}},@{N='AuthDetailsAuthenticationStepRequirement';E={$_.AuthenticationDetails.AuthenticationStepRequirement.ToString()}},@{N='AuthDetailsAuthenticationStepResultDetail';E={$_.AuthenticationDetails.AuthenticationStepResultDetail.ToString()}},@{N='AuthDetailsSucceeded';E={$_.AuthenticationDetails.Succeeded.ToString()}},AuthenticationMethodsUsed,AuthenticationProcessingDetails,AuthenticationProtocol,AuthenticationRequirement,AuthenticationRequirementPolicies,Detail,RequirementProvider,AutonomousSystemNumber,AzureResourceId,ClientAppUsed,ClientCredentialType,ConditionalAccessStatus,CorrelationId,@{N='CreatedDateTime';E={$_.CreatedDateTime.ToString()}},CrossTenantAccessType,DeviceDetail,Browser,DeviceDetailDeviceId,DisplayName,IsCompliant,IsManaged,DeviceDetailOperatingSystem,TrustType,FederatedCredentialId,FlaggedForReview,HomeTenantId,HomeTenantName,IPAddress,IPAddressFromResourceProvider,Id,IncomingTokenType,IsInteractive,IsTenantRestricted,Location,City,CountryOrRegion,State,ManagedServiceIdentity,AssociatedResourceId,FederatedTokenId,FederatedTokenIssuer,MsiType,MfaDetail,AuthDetail,AuthMethod,NetworkLocationDetails,OriginalRequestId,OriginalTransferMethod,PrivateLinkDetails,PolicyId,PolicyName,PolicyTenantId,PrivateLinkDetailsResourceId,ProcessingTimeInMilliseconds,ResourceDisplayName,ResourceId,ResourceServicePrincipalId,ResourceTenantId,RiskDetail,RiskEventTypesV2,RiskLevelAggregated,RiskLevelDuringSignIn,RiskState,ServicePrincipalCredentialKeyId,ServicePrincipalCredentialThumbprint,ServicePrincipalId,ServicePrincipalName,SessionLifetimePolicies,SignInEventTypes,SignInIdentifier,SignInIdentifierType,SignInTokenProtectionStatus,Status,StatusAdditionalDetails,TokenIssuerName,TokenIssuerType,UniqueTokenIdentifier,UserAgent,UserDisplayName,UserId,UserPrincipalName,UserType,AdditionalProperties
			}
		}
		else {
			try{
				[Array]$results =  Get-MgBetaAuditLogSignIn -ExpandProperty * -All -Filter "createdDateTime lt $($currentEnd.ToString("yyyy-MM-dd")) and createdDateTime gt $($currentStart.ToString("yyyy-MM-dd"))" |  Select-Object AppDisplayName,AppId,AppTokenProtectionStatus,AppliedConditionalAccessPolicies,ConditionsNotSatisfied,ConditionsSatisfied,AppliedConditionalAccessPoliciesDisplayName,EnforcedGrantControls,EnforcedSessionControls,AppliedConditionalAccessPoliciesId,AppliedConditionalAccessPoliciesResult,AppliedConditionalAccessPolicies2,AppliedEventListeners,AuthenticationAppDeviceDetails,AppVersion,ClientApp,DeviceId,OperatingSystem,AuthenticationAppPolicyEvaluationDetails,AdminConfiguration,AuthenticationEvaluation,AuthenticationAppPolicyEvaluationDetailsPolicyName,AuthenticationAppPolicyEvaluationDetailsStatus,AuthenticationContextClassReferences,@{N='AuthDetailsAuthenticationMethod';E={$_.AuthenticationDetails.AuthenticationMethod.ToString()}},@{N='AuthDetailsAuthenticationMethodDetail';E={$_.AuthenticationDetails.AuthenticationMethodDetail.ToString()}},@{N='AuthDetailsAuthenticationStepDateTime';E={$_.AuthenticationDetails.AuthenticationStepDateTime.ToString()}},@{N='AuthDetailsAuthenticationStepRequirement';E={$_.AuthenticationDetails.AuthenticationStepRequirement.ToString()}},@{N='AuthDetailsAuthenticationStepResultDetail';E={$_.AuthenticationDetails.AuthenticationStepResultDetail.ToString()}},@{N='AuthDetailsSucceeded';E={$_.AuthenticationDetails.Succeeded.ToString()}},AuthenticationMethodsUsed,AuthenticationProcessingDetails,AuthenticationProtocol,AuthenticationRequirement,AuthenticationRequirementPolicies,Detail,RequirementProvider,AutonomousSystemNumber,AzureResourceId,ClientAppUsed,ClientCredentialType,ConditionalAccessStatus,CorrelationId,@{N='CreatedDateTime';E={$_.CreatedDateTime.ToString()}},CrossTenantAccessType,DeviceDetail,Browser,DeviceDetailDeviceId,DisplayName,IsCompliant,IsManaged,DeviceDetailOperatingSystem,TrustType,FederatedCredentialId,FlaggedForReview,HomeTenantId,HomeTenantName,IPAddress,IPAddressFromResourceProvider,Id,IncomingTokenType,IsInteractive,IsTenantRestricted,Location,City,CountryOrRegion,State,ManagedServiceIdentity,AssociatedResourceId,FederatedTokenId,FederatedTokenIssuer,MsiType,MfaDetail,AuthDetail,AuthMethod,NetworkLocationDetails,OriginalRequestId,OriginalTransferMethod,PrivateLinkDetails,PolicyId,PolicyName,PolicyTenantId,PrivateLinkDetailsResourceId,ProcessingTimeInMilliseconds,ResourceDisplayName,ResourceId,ResourceServicePrincipalId,ResourceTenantId,RiskDetail,RiskEventTypesV2,RiskLevelAggregated,RiskLevelDuringSignIn,RiskState,ServicePrincipalCredentialKeyId,ServicePrincipalCredentialThumbprint,ServicePrincipalId,ServicePrincipalName,SessionLifetimePolicies,SignInEventTypes,SignInIdentifier,SignInIdentifierType,SignInTokenProtectionStatus,Status,StatusAdditionalDetails,TokenIssuerName,TokenIssuerType,UniqueTokenIdentifier,UserAgent,UserDisplayName,UserId,UserPrincipalName,UserType,AdditionalProperties
			}
			catch{
				Start-Sleep -Seconds 20
				[Array]$results =  Get-MgBetaAuditLogSignIn -ExpandProperty * -All -Filter "createdDateTime lt $($currentEnd.ToString("yyyy-MM-dd")) and createdDateTime gt $($currentStart.ToString("yyyy-MM-dd"))" |  Select-Object AppDisplayName,AppId,AppTokenProtectionStatus,AppliedConditionalAccessPolicies,ConditionsNotSatisfied,ConditionsSatisfied,AppliedConditionalAccessPoliciesDisplayName,EnforcedGrantControls,EnforcedSessionControls,AppliedConditionalAccessPoliciesId,AppliedConditionalAccessPoliciesResult,AppliedConditionalAccessPolicies2,AppliedEventListeners,AuthenticationAppDeviceDetails,AppVersion,ClientApp,DeviceId,OperatingSystem,AuthenticationAppPolicyEvaluationDetails,AdminConfiguration,AuthenticationEvaluation,AuthenticationAppPolicyEvaluationDetailsPolicyName,AuthenticationAppPolicyEvaluationDetailsStatus,AuthenticationContextClassReferences,@{N='AuthDetailsAuthenticationMethod';E={$_.AuthenticationDetails.AuthenticationMethod.ToString()}},@{N='AuthDetailsAuthenticationMethodDetail';E={$_.AuthenticationDetails.AuthenticationMethodDetail.ToString()}},@{N='AuthDetailsAuthenticationStepDateTime';E={$_.AuthenticationDetails.AuthenticationStepDateTime.ToString()}},@{N='AuthDetailsAuthenticationStepRequirement';E={$_.AuthenticationDetails.AuthenticationStepRequirement.ToString()}},@{N='AuthDetailsAuthenticationStepResultDetail';E={$_.AuthenticationDetails.AuthenticationStepResultDetail.ToString()}},@{N='AuthDetailsSucceeded';E={$_.AuthenticationDetails.Succeeded.ToString()}},AuthenticationMethodsUsed,AuthenticationProcessingDetails,AuthenticationProtocol,AuthenticationRequirement,AuthenticationRequirementPolicies,Detail,RequirementProvider,AutonomousSystemNumber,AzureResourceId,ClientAppUsed,ClientCredentialType,ConditionalAccessStatus,CorrelationId,@{N='CreatedDateTime';E={$_.CreatedDateTime.ToString()}},CrossTenantAccessType,DeviceDetail,Browser,DeviceDetailDeviceId,DisplayName,IsCompliant,IsManaged,DeviceDetailOperatingSystem,TrustType,FederatedCredentialId,FlaggedForReview,HomeTenantId,HomeTenantName,IPAddress,IPAddressFromResourceProvider,Id,IncomingTokenType,IsInteractive,IsTenantRestricted,Location,City,CountryOrRegion,State,ManagedServiceIdentity,AssociatedResourceId,FederatedTokenId,FederatedTokenIssuer,MsiType,MfaDetail,AuthDetail,AuthMethod,NetworkLocationDetails,OriginalRequestId,OriginalTransferMethod,PrivateLinkDetails,PolicyId,PolicyName,PolicyTenantId,PrivateLinkDetailsResourceId,ProcessingTimeInMilliseconds,ResourceDisplayName,ResourceId,ResourceServicePrincipalId,ResourceTenantId,RiskDetail,RiskEventTypesV2,RiskLevelAggregated,RiskLevelDuringSignIn,RiskState,ServicePrincipalCredentialKeyId,ServicePrincipalCredentialThumbprint,ServicePrincipalId,ServicePrincipalName,SessionLifetimePolicies,SignInEventTypes,SignInIdentifier,SignInIdentifierType,SignInTokenProtectionStatus,Status,StatusAdditionalDetails,TokenIssuerName,TokenIssuerType,UniqueTokenIdentifier,UserAgent,UserDisplayName,UserId,UserPrincipalName,UserType,AdditionalProperties
			}
		}
		if ($null -eq $results -or $results.Count -eq 0) {
			Write-LogFile -Message "[WARNING] Empty data set returned between $($currentStart.ToUniversalTime().ToString("yyyy-MM-dd")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-dd")). Moving On!"				
		}
		else {					
			$currentCount = $results.Count
			if ($currentDay -ne 0){
				$currentTotal = $currentCount + $results.Count
			}
			else {
				$currentTotal = $currentCount 
			}
			
			Write-LogFile -Message "[INFO] Found $currentCount Directory Sign-in Logs between $($currentStart.ToUniversalTime().ToString("yyyy-MM-dd")) and $($currentEnd.ToUniversalTime().ToString("yyyy-MM-dd"))" -Color "Green"
				
			$filePath = "$OutputDir\SignInLogsGraph-$($CurrentStart.ToString("yyyyMMdd"))-$($CurrentEnd.ToString("yyyyMMdd")).json"	
			$results | ConvertTo-Json -Depth 100 | Out-File -Append $filePath -Encoding $Encoding

			Write-LogFile -Message "[INFO] Successfully retrieved $($currentCount) records out of total $($currentTotal) for the current time range."							
		}
		[Array]$results = @()
		$CurrentStart = $CurrentEnd
  		$currentDay++
	}

	if ($MergeOutput.IsPresent)
	{
		Write-LogFile -Message "[INFO] Merging output files into one file"
	  	$outputDirMerged = "$OutputDir\Merged\"
	  	If (!(test-path $outputDirMerged)) {
			Write-LogFile -Message "[INFO] Creating the following directory: $outputDirMerged"
		  	New-Item -ItemType Directory -Force -Path $outputDirMerged | Out-Null
	  	}

		$allJsonObjects = @()

		Get-ChildItem $OutputDir -Filter *.json | ForEach-Object {
			$content = Get-Content -Path $_.FullName -Raw
			$jsonObjects = $content | ConvertFrom-Json
			$allJsonObjects += $jsonObjects
		}
	
		$allJsonObjects | ConvertTo-Json -Depth 100 | Set-Content "$outputDirMerged\SignInLogs-Combined.json"
	}

	Write-LogFile -Message "[INFO] Acquisition complete, check the $($OutputDir) directory for your files.." -Color "Green"		
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
	
