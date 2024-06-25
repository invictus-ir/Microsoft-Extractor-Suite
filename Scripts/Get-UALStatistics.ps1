function Get-UALStatistics
{
<#
    .SYNOPSIS
    Displays the total number of logs within the unified audit log.

    .DESCRIPTION
    A search is executed and the total number of logs within the set timeframe will be displayed.
	The output will be written to a CSV file called "Amount_Of_Audit_Logs.csv".

	.PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

	.PARAMETER StartDate
    startDate is the parameter specifying the start date of the date range.

	.PARAMETER EndDate
    endDate is the parameter specifying the end date of the date range.

	.PARAMETER OutputDir
	OutputDir is the parameter specifying the output directory.
	Default: Output\
    
    .EXAMPLE
    Get-UALStatistics
	Displays the total number of logs within the unified audit log.

	.EXAMPLE
	Get-UALStatistics -UserIds Test@invictus-ir.com -StartDate 1/4/2023 -EndDate 5/4/2023
	Displays the total number of logs within the unified audit log between 1/4/2023 and 5/4/2023 for the user Test@invictus-ir.com.
#>
	[CmdletBinding()]
	param(
		[string]$UserIds = "*",
		[string]$StartDate,
		[string]$EndDate,
		[string]$OutputDir = "Output\"
	)

	write-logFile -Message "[INFO] Running Get-UALStatistics" -Color "Green"

	StartDate
	EndDate
		
	$recordTypes = "ExchangeAdmin","ExchangeItem","ExchangeItemGroup","SharePoint","SyntheticProbe","SharePointFileOperation","OneDrive","AzureActiveDirectory","AzureActiveDirectoryAccountLogon","DataCenterSecurityCmdlet","ComplianceDLPSharePoint","Sway","ComplianceDLPExchange","SharePointSharingOperation","AzureActiveDirectoryStsLogon","SkypeForBusinessPSTNUsage","SkypeForBusinessUsersBlocked","SecurityComplianceCenterEOPCmdlet","ExchangeAggregatedOperation","PowerBIAudit","CRM","Yammer","SkypeForBusinessCmdlets","Discovery","MicrosoftTeams","ThreatIntelligence","MailSubmission","MicrosoftFlow","AeD","MicrosoftStream","ComplianceDLPSharePointClassification","ThreatFinder","Project","SharePointListOperation","SharePointCommentOperation","DataGovernance","Kaizala","SecurityComplianceAlerts","ThreatIntelligenceUrl","SecurityComplianceInsights","MIPLabel","WorkplaceAnalytics","PowerAppsApp","PowerAppsPlan","ThreatIntelligenceAtpContent","LabelContentExplorer","TeamsHealthcare","ExchangeItemAggregated","HygieneEvent","DataInsightsRestApiAudit","InformationBarrierPolicyApplication","SharePointListItemOperation","SharePointContentTypeOperation","SharePointFieldOperation","MicrosoftTeamsAdmin","HRSignal","MicrosoftTeamsDevice","MicrosoftTeamsAnalytics","InformationWorkerProtection","Campaign","DLPEndpoint","AirInvestigation","Quarantine","MicrosoftForms","ApplicationAudit","ComplianceSupervisionExchange","CustomerKeyServiceEncryption","OfficeNative","MipAutoLabelSharePointItem","MipAutoLabelSharePointPolicyLocation","MicrosoftTeamsShifts","SecureScore","MipAutoLabelExchangeItem","CortanaBriefing","Search","WDATPAlerts","PowerPlatformAdminDlp","PowerPlatformAdminEnvironment","MDATPAudit","SensitivityLabelPolicyMatch","SensitivityLabelAction","SensitivityLabeledFileAction","AttackSim","AirManualInvestigation","SecurityComplianceRBAC","UserTraining","AirAdminActionInvestigation","MSTIC","PhysicalBadgingSignal","TeamsEasyApprovals","AipDiscover","AipSensitivityLabelAction","AipProtectionAction","AipFileDeleted","AipHeartBeat","MCASAlerts","OnPremisesFileShareScannerDlp","OnPremisesSharePointScannerDlp","ExchangeSearch","SharePointSearch","PrivacyDataMinimization","LabelAnalyticsAggregate","MyAnalyticsSettings","SecurityComplianceUserChange","ComplianceDLPExchangeClassification","ComplianceDLPEndpoint","MipExactDataMatch","MSDEResponseActions","MSDEGeneralSettings","MSDEIndicatorsSettings","MS365DCustomDetection","MSDERolesSettings","MAPGAlerts","MAPGPolicy","MAPGRemediation","PrivacyRemediationAction","PrivacyDigestEmail","MipAutoLabelSimulationProgress","MipAutoLabelSimulationCompletion","MipAutoLabelProgressFeedback","DlpSensitiveInformationType","MipAutoLabelSimulationStatistics","LargeContentMetadata","Microsoft365Group","CDPMlInferencingResult","FilteringMailMetadata","CDPClassificationMailItem","CDPClassificationDocument","OfficeScriptsRunAction","FilteringPostMailDeliveryAction","CDPUnifiedFeedback","TenantAllowBlockList","ConsumptionResource","HealthcareSignal","DlpImportResult","CDPCompliancePolicyExecution","MultiStageDisposition","PrivacyDataMatch","FilteringDocMetadata","FilteringEmailFeatures","PowerBIDlp","FilteringUrlInfo","FilteringAttachmentInfo","CoreReportingSettings","ComplianceConnector","PowerPlatformLockboxResourceAccessRequest","PowerPlatformLockboxResourceCommand","CDPPredictiveCodingLabel","CDPCompliancePolicyUserFeedback","WebpageActivityEndpoint","OMEPortal","CMImprovementActionChange","FilteringUrlClick","MipLabelAnalyticsAuditRecord","FilteringEntityEvent","FilteringRuleHits","FilteringMailSubmission","LabelExplorer","MicrosoftManagedServicePlatform","PowerPlatformServiceActivity","ScorePlatformGenericAuditRecord","FilteringTimeTravelDocMetadata","Alert","AlertStatus","AlertIncident","IncidentStatus","Case","CaseInvestigation","RecordsManagement","PrivacyRemediation","DataShareOperation","CdpDlpSensitive","EHRConnector","FilteringMailGradingResult","PublicFolder","PrivacyTenantAuditHistoryRecord","AipScannerDiscoverEvent","EduDataLakeDownloadOperation","M365ComplianceConnector","MicrosoftGraphDataConnectOperation","MicrosoftPurview","FilteringEmailContentFeatures","PowerPagesSite","PowerAppsResource","PlannerPlan","PlannerCopyPlan","PlannerTask","PlannerRoster","PlannerPlanList","PlannerTaskList","PlannerTenantSettings","ProjectForTheWebProject","ProjectForTheWebTask","ProjectForTheWebRoadmap","ProjectForTheWebRoadmapItem","ProjectForTheWebProjectSettings","ProjectForTheWebRoadmapSettings","QuarantineMetadata","MicrosoftTodoAudit","TimeTravelFilteringDocMetadata","TeamsQuarantineMetadata","SharePointAppPermissionOperation","MicrosoftTeamsSensitivityLabelAction","FilteringTeamsMetadata","FilteringTeamsUrlInfo","FilteringTeamsPostDeliveryAction","MDCAssessments","MDCRegulatoryComplianceStandards","MDCRegulatoryComplianceControls","MDCRegulatoryComplianceAssessments","MDCSecurityConnectors","MDADataSecuritySignal","VivaGoals","FilteringRuntimeInfo","AttackSimAdmin","MicrosoftGraphDataConnectConsent","FilteringAtpDetonationInfo","PrivacyPortal","ManagedTenants","UnifiedSimulationMatchedItem","UnifiedSimulationSummary","UpdateQuarantineMetadata","MS365DSuppressionRule","PurviewDataMapOperation","FilteringUrlPostClickAction","IrmUserDefinedDetectionSignal","TeamsUpdates","PlannerRosterSensitivityLabel","MS365DIncident","FilteringDelistingMetadata","ComplianceDLPSharePointClassificationExtended","MicrosoftDefenderForIdentityAudit","SupervisoryReviewDayXInsight","DefenderExpertsforXDRAdmin","CDPEdgeBlockedMessage","HostedRpa"
	
	$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
	$outputFile = "$($date)-Amount_Of_Audit_Logs.csv"
	if (!(test-path $OutputDir)) {
		New-Item -ItemType Directory -Force -Name $outputDir > $null
		Write-LogFile -Message "Creating the following directory: $OutputDir"
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

	$outputDirectory = Join-Path $OutputDir $outputFile
	
	Set-Content $outputDirectory -Value "RecordType,Amount of log entries"
	Write-LogFile -Message "[INFO] Calculating the number of audit logs for each of the 236 Record Types between $($script:StartDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")) and $($script:EndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Green"
	
	try {
		$totalCount = Search-UnifiedAuditLog -Userids $UserIds -StartDate $script:StartDate -EndDate $script:EndDate -ResultSize 1 |  Format-List -Property ResultCount| out-string -Stream | select-string ResultCount
	}
	catch {
		write-logFile -Message "[WARNING] You must call Connect-M365 before running this script" -Color "Red"
		Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red"
		break
	}
	
	Foreach ($record in $recordTypes) {
		$specificResult = Search-UnifiedAuditLog -Userids $UserIds -StartDate $script:StartDate -EndDate $script:EndDate -RecordType $record -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount
		if ($specificResult) {
			Write-LogFile -Message "$($record):$($specificResult)"
			Write-Output "$record,$specificResult" | Out-File $outputDirectory -Append
		}
		else {
		}
	}

	if ($totalCount) {
		$numbertotal = $totalCount.tostring().split(":")[1]
		Write-LogFile -Message "--------------------------------------"
		Write-LogFile -Message "Total count:$($numbertotal)" -Color "Green"
		Write-LogFile -Message "[INFO] Count complete file is written to $outputFile" -Color "Green"
		$stringTotalCount = "Total Count:"
		Write-Output "$stringTotalCount : $numbertotal" | Out-File $outputDirectory -Append
	}
	
	else {
		Write-LogFile -Message "[INFO] No records found for $UserIds"
	}
}