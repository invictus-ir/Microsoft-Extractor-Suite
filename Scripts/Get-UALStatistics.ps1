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

	.PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Default: Standard
    
    .EXAMPLE
    Get-UALStatistics
	Displays the total number of logs within the unified audit log.

	.EXAMPLE
	Get-UALStatistics -UserIds Test@invictus-ir.com -StartDate 1/4/2024 -EndDate 5/4/2024
	Displays the total number of logs within the unified audit log between 1/4/2024 and 5/4/2024 for the user Test@invictus-ir.com.
#>
	[CmdletBinding()]
	param(
		[string]$UserIds = "*",
		[string]$StartDate,
		[string]$EndDate,
		[string]$OutputDir = "Output\",
        [ValidateSet('None', 'Minimal', 'Standard')]
        [string]$LogLevel = 'Standard'
	)

	Set-LogLevel -Level ([LogLevel]::$LogLevel)
	$date = Get-Date -Format "yyyyMMddHHmm"
    $results = @()
    $summary = @{
        TotalCount = 0
        RecordsWithData = 0
        RecordsWithoutData = 0
        StartTime = Get-Date
        ProcessingTime = $null
    }

	Write-LogFile -Message "=== Analyzing audit log distribution across record types ===" -Color "Cyan" -Level Minimal
	Write-LogFile -Message "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level Standard

	StartDate -Quiet
	EndDate -Quiet	

	$dateRange = "$($script:StartDate.ToString('yyyy-MM-dd HH:mm:ss')) to $($script:EndDate.ToString('yyyy-MM-dd HH:mm:ss'))"
	$recordTypes = "ExchangeAdmin","ExchangeItem","ExchangeItemGroup","SharePoint","SyntheticProbe","SharePointFileOperation","OneDrive","AzureActiveDirectory","AzureActiveDirectoryAccountLogon","DataCenterSecurityCmdlet","ComplianceDLPSharePoint","Sway","ComplianceDLPExchange","SharePointSharingOperation","AzureActiveDirectoryStsLogon","SkypeForBusinessPSTNUsage","SkypeForBusinessUsersBlocked","SecurityComplianceCenterEOPCmdlet","ExchangeAggregatedOperation","PowerBIAudit","CRM","Yammer","SkypeForBusinessCmdlets","Discovery","MicrosoftTeams","ThreatIntelligence","MailSubmission","MicrosoftFlow","AeD","MicrosoftStream","ComplianceDLPSharePointClassification","ThreatFinder","Project","SharePointListOperation","SharePointCommentOperation","DataGovernance","Kaizala","SecurityComplianceAlerts","ThreatIntelligenceUrl","SecurityComplianceInsights","MIPLabel","WorkplaceAnalytics","PowerAppsApp","PowerAppsPlan","ThreatIntelligenceAtpContent","LabelContentExplorer","TeamsHealthcare","ExchangeItemAggregated","HygieneEvent","DataInsightsRestApiAudit","InformationBarrierPolicyApplication","SharePointListItemOperation","SharePointContentTypeOperation","SharePointFieldOperation","MicrosoftTeamsAdmin","HRSignal","MicrosoftTeamsDevice","MicrosoftTeamsAnalytics","InformationWorkerProtection","Campaign","DLPEndpoint","AirInvestigation","Quarantine","MicrosoftForms","ApplicationAudit","ComplianceSupervisionExchange","CustomerKeyServiceEncryption","OfficeNative","MipAutoLabelSharePointItem","MipAutoLabelSharePointPolicyLocation","MicrosoftTeamsShifts","SecureScore","MipAutoLabelExchangeItem","CortanaBriefing","Search","WDATPAlerts","PowerPlatformAdminDlp","PowerPlatformAdminEnvironment","MDATPAudit","SensitivityLabelPolicyMatch","SensitivityLabelAction","SensitivityLabeledFileAction","AttackSim","AirManualInvestigation","SecurityComplianceRBAC","UserTraining","AirAdminActionInvestigation","MSTIC","PhysicalBadgingSignal","TeamsEasyApprovals","AipDiscover","AipSensitivityLabelAction","AipProtectionAction","AipFileDeleted","AipHeartBeat","MCASAlerts","OnPremisesFileShareScannerDlp","OnPremisesSharePointScannerDlp","ExchangeSearch","SharePointSearch","PrivacyDataMinimization","LabelAnalyticsAggregate","MyAnalyticsSettings","SecurityComplianceUserChange","ComplianceDLPExchangeClassification","ComplianceDLPEndpoint","MipExactDataMatch","MSDEResponseActions","MSDEGeneralSettings","MSDEIndicatorsSettings","MS365DCustomDetection","MSDERolesSettings","MAPGAlerts","MAPGPolicy","MAPGRemediation","PrivacyRemediationAction","PrivacyDigestEmail","MipAutoLabelSimulationProgress","MipAutoLabelSimulationCompletion","MipAutoLabelProgressFeedback","DlpSensitiveInformationType","MipAutoLabelSimulationStatistics","LargeContentMetadata","Microsoft365Group","CDPMlInferencingResult","FilteringMailMetadata","CDPClassificationMailItem","CDPClassificationDocument","OfficeScriptsRunAction","FilteringPostMailDeliveryAction","CDPUnifiedFeedback","TenantAllowBlockList","ConsumptionResource","HealthcareSignal","DlpImportResult","CDPCompliancePolicyExecution","MultiStageDisposition","PrivacyDataMatch","FilteringDocMetadata","FilteringEmailFeatures","PowerBIDlp","FilteringUrlInfo","FilteringAttachmentInfo","CoreReportingSettings","ComplianceConnector","PowerPlatformLockboxResourceAccessRequest","PowerPlatformLockboxResourceCommand","CDPPredictiveCodingLabel","CDPCompliancePolicyUserFeedback","WebpageActivityEndpoint","OMEPortal","CMImprovementActionChange","FilteringUrlClick","MipLabelAnalyticsAuditRecord","FilteringEntityEvent","FilteringRuleHits","FilteringMailSubmission","LabelExplorer","MicrosoftManagedServicePlatform","PowerPlatformServiceActivity","ScorePlatformGenericAuditRecord","FilteringTimeTravelDocMetadata","Alert","AlertStatus","AlertIncident","IncidentStatus","Case","CaseInvestigation","RecordsManagement","PrivacyRemediation","DataShareOperation","CdpDlpSensitive","EHRConnector","FilteringMailGradingResult","PublicFolder","PrivacyTenantAuditHistoryRecord","AipScannerDiscoverEvent","EduDataLakeDownloadOperation","M365ComplianceConnector","MicrosoftGraphDataConnectOperation","MicrosoftPurview","FilteringEmailContentFeatures","PowerPagesSite","PowerAppsResource","PlannerPlan","PlannerCopyPlan","PlannerTask","PlannerRoster","PlannerPlanList","PlannerTaskList","PlannerTenantSettings","ProjectForTheWebProject","ProjectForTheWebTask","ProjectForTheWebRoadmap","ProjectForTheWebRoadmapItem","ProjectForTheWebProjectSettings","ProjectForTheWebRoadmapSettings","QuarantineMetadata","MicrosoftTodoAudit","TimeTravelFilteringDocMetadata","TeamsQuarantineMetadata","SharePointAppPermissionOperation","MicrosoftTeamsSensitivityLabelAction","FilteringTeamsMetadata","FilteringTeamsUrlInfo","FilteringTeamsPostDeliveryAction","MDCAssessments","MDCRegulatoryComplianceStandards","MDCRegulatoryComplianceControls","MDCRegulatoryComplianceAssessments","MDCSecurityConnectors","MDADataSecuritySignal","VivaGoals","FilteringRuntimeInfo","AttackSimAdmin","MicrosoftGraphDataConnectConsent","FilteringAtpDetonationInfo","PrivacyPortal","ManagedTenants","UnifiedSimulationMatchedItem","UnifiedSimulationSummary","UpdateQuarantineMetadata","MS365DSuppressionRule","PurviewDataMapOperation","FilteringUrlPostClickAction","IrmUserDefinedDetectionSignal","TeamsUpdates","PlannerRosterSensitivityLabel","MS365DIncident","FilteringDelistingMetadata","ComplianceDLPSharePointClassificationExtended","MicrosoftDefenderForIdentityAudit","SupervisoryReviewDayXInsight","DefenderExpertsforXDRAdmin","CDPEdgeBlockedMessage","HostedRpa"	

	Write-LogFile -Message "Analysis Period: $dateRange" -Level Standard
	Write-LogFile -Message "Record Types to Process: $($recordTypes.Count)" -Level Standard
	Write-LogFile -Message "Output Directory: $OutputDir" -Level Standard
	Write-LogFile -Message "----------------------------------------`n" -Level Standard

	$date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
	$outputFile = "$($date)-Amount_Of_Audit_Logs.csv"

	if (!(Test-Path $OutputDir)) {
		New-Item -ItemType Directory -Force -Path $OutputDir > $null
	} 
	else {
		if (!(Test-Path -Path $OutputDir)) {
			Write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
			Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script" -Level Minimal
		}
	}

	$outputDirectory = Join-Path $OutputDir $outputFile
	Set-Content $outputDirectory -Value "RecordType,Amount,Percentage"

	try {
		$totalCount = Search-UnifiedAuditLog -Userids $UserIds -StartDate $script:StartDate -EndDate $script:EndDate -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount
		if ($null -eq $totalCount) {
            Write-LogFile -Message "[WARNING] No Unified Audit Log found for the specified period" -Color "Yellow" -Level Standard
            return
        }

		$summary.TotalCount = $totalCount
        Write-LogFile -Message "[INFO] Found a total of $totalCount Unified Audit Log entries" -Level Standard
	}
	catch {
		write-logFile -Message "[INFO] Ensure you are connected to M365 by running the Connect-M365 command before executing this script" -Color "Yellow" -Level Minimal
		Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
		throw
	}

	$totalRecords = $recordTypes.Count
	$processedCount = 0
	Write-LogFile -Message "[INFO] Processing record types..." -Level Standard

	Foreach ($record in $recordTypes) {
		$processedCount++

		if ($processedCount % 25 -eq 0) {			
			Write-LogFile -Message "[INFO] Processed $processedCount of $totalRecords record types" -Level Standard
		}

		$specificResult = Search-UnifiedAuditLog -Userids $UserIds -StartDate $script:StartDate -EndDate $script:EndDate -RecordType $record -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount
		if ($specificResult) {
			$summary.RecordsWithData++
			$percentage = [math]::Round(($specificResult / $totalCount) * 100, 2)

			$results += [PSCustomObject]@{
				RecordType = $record
				Count = $specificResult
				Percentage = $percentage
			}

			#Write-LogFile -Message "$($record):$($specificResult)" -Level Standard
			Write-Output "$record,$specificResult,$percentage" | Out-File $outputDirectory -Append
		}
		else {
			$summary.RecordsWithoutData++
		}
	}

	if ($totalCount) {
		Write-LogFile -Message "[INFO] Processed $processedCount of $totalRecords record types" -Level Standard
		Write-LogFile -Message "`n=== Record Type Analysis ===" -Color "Cyan" -Level Standard
        Write-LogFile -Message "----------------------------------------" -Level Standard

        $results | Sort-Object Count -Descending | Export-Csv -Path $outputDirectory -NoTypeInformation
		$summary.ProcessingTime = (Get-Date) - $summary.StartTime

		$results | Sort-Object Count -Descending | ForEach-Object {
			$formattedCount = "{0,15:N0}" -f $_.Count
			$formattedPercentage = "{0,4:f1}" -f $_.Percentage
			Write-LogFile -Message ("{0,-40} {1} ({2,4}%)" -f $_.RecordType, $formattedCount, $formattedPercentage) -Level Standard
		}

		Write-LogFile -Message "----------------------------------------" -Level Standard

		Write-LogFile -Message "`n=== Analysis Summary ===" -Color "Cyan" -Level Standard
        Write-LogFile -Message "Time Period: $dateRange" -Level Standard
        Write-LogFile -Message "Total Log Entries: $($summary.TotalCount.ToString('N0'))" -Level Standard
        Write-LogFile -Message "Record Types:" -Level Standard
        Write-LogFile -Message "  With Data: $($summary.RecordsWithData)" -Level Standard
        Write-LogFile -Message "  Without Data: $($summary.RecordsWithoutData)" -Level Standard
        Write-LogFile -Message "`nOutput File: $outputDirectory" -Level Standard
        
		$summary.ProcessingTime = (Get-Date) - $summary.StartTime
        Write-LogFile -Message "Processing Time: $($summary.ProcessingTime.ToString('mm\:ss'))" -Color "Green" -Level Standard
        Write-LogFile -Message "===================================" -Color "Cyan" -Level Standard
	}
	
	else {
		Write-LogFile -Message "[INFO] No records found in the Unified Audit Log." -Level Minimal
	}
}
