$menupart1=@"

  __  __  _                                 __  _     ____     __  _____   ______        _                      _               
 |  \/  |(_)                               / _|| |   |___ \   / / | ____| |  ____|      | |                    | |              
 | \  / | _   ___  _ __  ___   ___   ___  | |_ | |_    __) | / /_ | |__   | |__   __  __| |_  _ __  __ _   ___ | |_  ___   _ __ 
 | |\/| || | / __|| '__|/ _ \ / __| / _ \ |  _|| __|  |__ < | '_ \|___ \  |  __|  \ \/ /| __|| '__|/ _` | / __|| __|/ _ \ | '__|
 | |  | || || (__ | |  | (_) |\__ \| (_) || |  | |_   ___) || (_) |___) | | |____  >  < | |_ | |  | (_| || (__ | |_| (_) || |   
 |_|  |_||_| \___||_|   \___/ |___/ \___/ |_|   \__| |____/  \___/|____/  |______|/_/\_\ \__||_|   \__,_| \___| \__|\___/ |_|   
                                                                                                                                
                                                                                                                                
Copyright (c) 2022 Invictus Incident Response
New version of the Office 365 Extractor script, originally created by Joey Rentenaar & Korstiaan Stam formerly PwC Incident Response Netherlands.
Documentation available on https://github.com/invictus-ir/Microsoft-365-Extractor-Suite


"@

Clear-Host
$menupart1


function Get-startDate{
    Do {    
	    $DateStart= read-host "Please enter start date (format: yyyy-MM-dd) or ENTER for maximum 90 days"
        if ([string]::IsNullOrWhiteSpace($DateStart)) { $DateStart = [datetime]::Now.ToUniversalTime().AddDays(-90) }
		$StartDate = $DateStart -as [datetime]
		if (!$StartDate) { write-host "Not A valid date and time"}
	} while ($StartDate -isnot [datetime])
	   
    return Get-Date $startDate -Format "yyyy-MM-dd HH:mm:ss"
	
}

function Get-endDate{
    Do {    
        $DateEnd= read-host "Please enter end date (format: yyyy-MM-dd) or ENTER for today"
        if ([string]::IsNullOrWhiteSpace($DateEnd)) { $DateEnd =  [datetime]::Now.ToUniversalTime() }
		$EndDate = $DateEnd -as [datetime]
		if (!$EndDate) { write-host "Not A valid date and time"}
    } while ($EndDate -isnot [datetime])

    return Get-Date $EndDate -Format "yyyy-MM-dd HH:mm:ss"
}

function Users{
	write-host "Would you like to extract log events for [1]All users or [2]Specific users"
	$AllorSingleUse = read-host ">"
	
	if($AllorSingleUse -eq "1"){
		write-host "Extracting the Unified Audit Log for all users..."
		$script:Userstoextract = "*"}
	
	elseif($AllorSingleUse -eq "2"){
		write-host "Provide accounts that you wish to acquire, use comma separated values for multiple accounts, example (bob@acmecorp.onmicrosoft.com,alice@acmecorp.onmicrosoft.com)"
		$script:Userstoextract = read-host ">"}
		
	else{
		write-host "Please pick between option 1 or 2"
		Users}}


function Main{
	####################Configuration settings####################
	$OutputFileNumberAuditlogs = "\Log_Directory\Amount_Of_Audit_Logs.csv"
	$AuditLog = "\Log_Directory\AuditLog.txt"
	$LogDirectory = "\Log_Directory"
	$CSVoutput = "\Log_Directory\AuditRecords.csv"
	$LogDirectoryPath = Join-Path $PSScriptRoot $LogDirectory
	$LogFile = Join-Path $PSScriptRoot $AuditLog
	$OutputDirectory = Join-Path $PSScriptRoot $OutputFileNumberAuditlogs
	$OutputFile = Join-Path $PSScriptRoot $CSVoutput	
  
	#The maximum number of results Microsoft allows is 5000 for each PowerShell session.
	$ResultSize = 5000
	$RetryCount = 3
	$CurrentTries = 0

	If(!(test-path $LogDirectoryPath)){
		New-Item -ItemType Directory -Force -Path $LogDirectoryPath}

	Function Write-LogFile ([String]$Message){
		$final = [DateTime]::Now.ToString() + ":" + $Message
		$final | Out-File $LogFile -Append} 
    
	Switch ($script:input){
	#Show available log sources and amount of logs
	"1" {
		Users
		write-host ""
		
		$StartDate = Get-StartDate
		$EndDate = Get-EndDate
		
		Connect-ExchangeOnline 
		
		
		$RecordTypes = "ExchangeAdmin","ExchangeItem","ExchangeItemGroup","SharePoint","SyntheticProbe","SharePointFileOperation","OneDrive","AzureActiveDirectory","AzureActiveDirectoryAccountLogon","DataCenterSecurityCmdlet","ComplianceDLPSharePoint","Sway","ComplianceDLPExchange","SharePointSharingOperation","AzureActiveDirectoryStsLogon","SkypeForBusinessPSTNUsage","SkypeForBusinessUsersBlocked","SecurityComplianceCenterEOPCmdlet","ExchangeAggregatedOperation","PowerBIAudit","CRM","Yammer","SkypeForBusinessCmdlets","Discovery","MicrosoftTeams","ThreatIntelligence","MailSubmission","MicrosoftFlow","AeD","MicrosoftStream","ComplianceDLPSharePointClassification","ThreatFinder","Project","SharePointListOperation","SharePointCommentOperation","DataGovernance","Kaizala","SecurityComplianceAlerts","ThreatIntelligenceUrl","SecurityComplianceInsights","MIPLabel","WorkplaceAnalytics","PowerAppsApp","PowerAppsPlan","ThreatIntelligenceAtpContent","LabelContentExplorer","TeamsHealthcare","ExchangeItemAggregated","HygieneEvent","DataInsightsRestApiAudit","InformationBarrierPolicyApplication","SharePointListItemOperation","SharePointContentTypeOperation","SharePointFieldOperation","MicrosoftTeamsAdmin","HRSignal","MicrosoftTeamsDevice","MicrosoftTeamsAnalytics","InformationWorkerProtection","Campaign","DLPEndpoint","AirInvestigation","Quarantine","MicrosoftForms","ApplicationAudit","ComplianceSupervisionExchange","CustomerKeyServiceEncryption","OfficeNative","MipAutoLabelSharePointItem","MipAutoLabelSharePointPolicyLocation","MicrosoftTeamsShifts","MipAutoLabelExchangeItem","CortanaBriefing","Search","WDATPAlerts","MDATPAudit","LabelContentExplorer","SensitivityLabelPolicyMatch","SensitivityLabelAction","SensitivityLabeledFileAction","AttackSim","AirManualInvestigation","SecurityComplianceRBAC","UserTraining","AirAdminActionInvestigation","MSTIC","PhysicalBadgingSignal","AipDiscover","AipSensitivityLabelAction","AipProtectionAction","AipFileDeleted","AipHeartBeat","MCASAlerts","OnPremisesFileShareScannerDlp","OnPremisesSharePointScannerDlp","ExchangeSearch","SharePointSearch","MyAnalyticsSettings","SecurityComplianceUserChange","ComplianceDLPExchangeClassification","MipExactDataMatch","MS365DCustomDetection","CoreReportingSettings","ComplianceConnector","PrivacyDataMinimization"
		
		If(!(test-path $OutputDirectory)){
			Write-host "Creating the following file:" $OutputDirectory}
		else{
			$OutputFile = "Amount_Of_Audit_Logs.csv"
			$date = [datetime]::Now.ToString('HHmm') 
			$OutputFile = "\Log_Directory\"+$date+"_"+$OutputFile
			$OutputDirectory = Join-Path $PSScriptRoot $OutputFile}
		
		echo ""
		Write-Host "---------------------------------------------------------------------------"
		Write-Host "|The number of logs between"$StartDate" and "$EndDate" is|"
		Write-Host "---------------------------------------------------------------------------" 
		echo ""
		Write-Host "Calculating the number of audit logs" -ForegroundColor Green
		$TotalCount = Search-UnifiedAuditLog -UserIds $script:Userstoextract -StartDate $StartDate -EndDate $EndDate -ResultSize 1 |  Format-List -Property ResultCount| out-string -Stream | select-string ResultCount
		Foreach ($record in $RecordTypes){	
			$SpecificResult = Search-UnifiedAuditLog -UserIds $script:Userstoextract -StartDate $StartDate -EndDate $EndDate -RecordType $record -ResultSize 1 | Format-List -Property ResultCount| out-string -Stream | select-string ResultCount
			if($SpecificResult){
				$number = $SpecificResult.tostring().split(":")[1]
				Write-Output $record":"$number
				Write-Output "$record - $number" | Out-File $OutputDirectory -Append}
			else {}}
		if($TotalCount){
			$numbertotal =$TotalCount.tostring().split(":")[1]
			Write-Host "--------------------------------------"
			Write-Host "Total count:"$numbertotal
			Write-host "Count complete file is written to $outputDirectory"
			$StringTotalCount = "Total Count:"
			Write-Output "$StringTotalCount : $numbertotal" | Out-File $outputDirectory -Append}
		else{
			Write-host "No records found."}
			
		echo ""
		Menu}
	
	#2 Extract all audit logs
	"2" {
		Users
		write-host ""
	
		If(!(test-path $OutputFile)){
			Write-host "Creating the following file:" $OutputFile}
		else{
			$date = [datetime]::Now.ToString('HHmm') 
			$OutputFile = "Log_Directory\"+$date+"AuditRecords.csv"
			$OutputDirectory = Join-Path $PSScriptRoot $OutputFile}
		echo ""
		
		[DateTime]$StartDate = Get-StartDate
		[DateTime]$EndDate = Get-EndDate
		
		# Interval in minutes determines the timeframe the script will use to search for a set of logs. The reason is that there's a maximum of 5000 records per session. 
        # The script will automatically lower this value if there are more than 5000 records for the given interval. If the value is low the scripts takes a lot of time to run.
        $IntervalMinutes = read-host "Please enter a time interval or ENTER for the default value 480"
	    if ([string]::IsNullOrWhiteSpace($IntervalMinutes)) { $IntervalMinutes = "480" 
	    $ResetInterval = $IntervalMinutes
	
		
		
		
		Write-LogFile "Start date provided by user: $StartDate"
		Write-LogFile "End date provided by user: $EndDate"
		Write-Logfile "Time interval provided by user: $IntervalMinutes"
		[DateTime]$CurrentStart = $StartDate
		[DateTime]$CurrentEnd = $EndDate
		
		#Establish connection to the client environment
		Connect-ExchangeOnline 
		
		echo ""
		Write-Host "------------------------------------------------------------------------------------------"
		Write-Host "|Extracting all available audit logs between "$StartDate" and "$EndDate                "|"
		write-host "|Time interval: $IntervalMinutes                                                                        |"
		Write-Host "------------------------------------------------------------------------------------------" 
		echo ""
		 
		while ($true){
			$CurrentEnd = $CurrentStart.AddMinutes($IntervalMinutes)
			
			$AmountResults = Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $CurrentEnd -UserIds $script:Userstoextract -ResultSize 1 |  out-string -Stream | select-string ResultCount
			if($AmountResults){
				$number = $AmountResults.tostring().split(":")[1]
				$script:integer = [int]$number
				
				while ($script:integer -gt 5000){
					$AmountResults = Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $CurrentEnd -UserIds $script:Userstoextract -ResultSize 1 |out-string -Stream | select-string ResultCount
					if($AmountResults){
						$number = $AmountResults.tostring().split(":")[1]
						$script:integer = [int]$number
						if ($script:integer -lt 5000){
							if ($IntervalMinutes -eq 0){
								Exit
								}
							else{
								write-host "INFO: Temporary lowering time interval to $IntervalMinutes minutes" -ForegroundColor Yellow
								}}
						else{
							$IntervalMinutes = $IntervalMinutes / 2
							$CurrentEnd = $CurrentStart.AddMinutes($IntervalMinutes)}}
							
					else{
						Write-LogFile "INFO: Retrieving audit logs between $($CurrentStart) and $($CurrentEnd)"
						Write-Host "INFO: Retrieving audit logs between $($CurrentStart) and $($CurrentEnd)" -ForegroundColor green
						$Intervalmin = $IntervalMinutes
						$CurrentStart = $CurrentStart.AddMinutes($Intervalmin)
						$CurrentEnd = $CurrentStart.AddMinutes($Intervalmin)
						$AmountResults = Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $CurrentEnd -UserIds $script:Userstoextract -ResultSize 1 |out-string -Stream | select-string ResultCount
						if($AmountResults){
							$number = $AmountResults.tostring().split(":")[1]
							$script:integer = [int]$number}}}
					}
							
			ELSE{
				$IntervalMinutes = $ResetInterval}
				
			
			if ($CurrentEnd -gt $EndDate){				
				$DURATION = $EndDate - $Backupdate
				$durmin = $DURATION.TotalMinutes
				
				$CurrentEnd = $Backupdate
				$CurrentStart = $Backupdate
				
				$IntervalMinutes = $durmin /2
				if ($IntervalMinutes -eq 0){
					Exit}
				else{
					write-host "INFO: Temporary lowering time interval to $IntervalMinutes minutes" -ForegroundColor Yellow
					$CurrentEnd = $CurrentEnd.AddMinutes($IntervalMinutes)}
					}
			
			ELSEIF($CurrentEnd -eq $EndDate){
				Write-LogFile "INFO: Retrieving audit logs between $($CurrentStart) and $($CurrentEnd)"
				Write-Host "INFO: Retrieving audit logs between $($CurrentStart) and $($CurrentEnd)" -ForegroundColor green
				
				[Array]$results = Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $CurrentEnd -SessionID $SessionID -UserIds $script:Userstoextract -SessionCommand ReturnNextPreviewPage -ResultSize $ResultSize
				if($results){
					$results | epcsv $OutputFile -NoTypeInformation -Append
				}
				write-host "Acquisition complete, check the Log Directory for your files.." -ForegroundColor Red
				break
				Menu
			}
				
			$CurrentTries = 0
			$SessionID = [DateTime]::Now.ToString().Replace('/', '_')
			Write-LogFile "INFO: Retrieving audit logs between $($CurrentStart) and $($CurrentEnd)"
			Write-Host "INFO: Retrieving audit logs between $($CurrentStart) and $($CurrentEnd)" -ForegroundColor green
			
			 
			while ($true){		
				$CurrentEnd = $CurrentEnd.AddSeconds(-1)				
				[Array]$results = Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $CurrentEnd -SessionID $SessionID -UserIds $script:Userstoextract -SessionCommand ReturnNextPreviewPage -ResultSize $ResultSize
				$CurrentEnd = $CurrentEnd.AddSeconds(1)
				$CurrentCount = 0
				
				if ($results -eq $null -or $results.Count -eq 0){
					if ($CurrentTries -lt $RetryCount){
						$CurrentTries = $CurrentTries + 1
						continue}
					else{
						Write-LogFile "WARNING: Empty data set returned between $($CurrentStart) and $($CurrentEnd). Retry count reached. Moving forward!"
						break}}
						
				$CurrentTotal = $results[0].ResultCount
				$CurrentCount = $CurrentCount + $results.Count
				
				if ($CurrentTotal -eq $results[$results.Count - 1].ResultIndex){
					$message = "INFO: Successfully retrieved $($CurrentCount) records out of total $($CurrentTotal) for the current time range. Moving on!"
					$results | epcsv $OutputFile -NoTypeInformation -Append
					write-host $message
					Write-LogFile $message
					break}}
			
			$CurrentStart = $CurrentEnd
			[DateTime]$Backupdate = $CurrentEnd}
		
		#SHA256 hash calculation for the output files
		$HASHValues = Join-Path $PSScriptRoot "\Log_Directory\Hashes.csv"
		Get-ChildItem $LogDirectoryPath -Filter *AuditRecords.csv | Get-FileHash -Algorithm SHA256 | epcsv $HASHValues
		echo ""
		Menu}}
	 
	#3Extract group of logs
	"3" {
	
		Write-host "1: Extract all Exchange logging"
		Write-host "2: Extract all Azure logging"
		Write-host "3: Extract all Sharepoint logging"
		Write-host "4: Extract all Skype logging"
		write-host "5: Back to menu"
		
		$inputgroup = Read-Host "Select an action"
		
		IF($inputgroup -eq "1"){
			$RecordTypes = "ExchangeAdmin","ExchangeAggregatedOperation","ExchangeItem","ExchangeItemGroup","ExchangeItemAggregated","ComplianceDLPExchange","ComplianceSupervisionExchange","MipAutoLabelExchangeItem"
			$RecordFile = "AllExchange"}
		ELSEIF($inputgroup -eq "2"){
			$RecordTypes = "AzureActiveDirectory","AzureActiveDirectoryAccountLogon","AzureActiveDirectoryStsLogon"
			$RecordFile = "AllAzure"}
		ELSEIF($inputgroup -eq "3"){
			$RecordTypes = "ComplianceDLPSharePoint","SharePoint","SharePointFileOperation","SharePointSharingOperation","SharepointListOperation", "ComplianceDLPSharePointClassification","SharePointCommentOperation", "SharePointListItemOperation", "SharePointContentTypeOperation", "SharePointFieldOperation","MipAutoLabelSharePointItem","MipAutoLabelSharePointPolicyLocation"
			$RecordFile = "AllSharepoint"}
		ELSEIF($inputgroup -eq "4"){
			$RecordTypes = "SkypeForBusinessCmdlets","SkypeForBusinessPSTNUsage","SkypeForBusinessUsersBlocked"
			$RecordFile = "AllSkype"}
		ELSE{
			Menu}
		
		write-host ""
		Users
		Write-host ""
		
		[DateTime]$StartDate = Get-StartDate
		[DateTime]$EndDate = Get-EndDate
		
		echo ""
		write-host "Recommended interval is 480"
		Write-host "Lower the time interval for environments with a high log volume"
		echo ""
		
		$IntervalMinutes = read-host "Please enter a time interval or ENTER for 480"
		if ([string]::IsNullOrWhiteSpace($IntervalMinutes)) { $IntervalMinutes = "480" }
		
		$ResetInterval = $IntervalMinutes
		
		Write-LogFile "Start date provided by user: $StartDate"
		Write-LogFile "End date provided by user: $EndDate"
		Write-Logfile "Time interval provided by user: $IntervalMinutes"
		
		
		Connect-ExchangeOnline 
		
		echo ""
		Write-Host "----------------------------------------------------------------------------"
		Write-Host "|Extracting audit logs between "$StartDate" and "$EndDate"|"
		write-host "|Time interval: $IntervalMinutes                                                                       |"
		Write-Host "----------------------------------------------------------------------------" 
		Write-Host "The following RecordTypes are configured to be extracted:" -ForegroundColor Green
		Foreach ($record in $RecordTypes){
			Write-Host "-$record"}
		echo ""
		
		Foreach ($record in $RecordTypes){
			$SpecificResult = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType $record -UserIds $script:Userstoextract -ResultSize 1|out-string -Stream | select-string ResultCount
	
			if($SpecificResult){
				$NumberOfLogs = $SpecificResult.tostring().split(":")[1]
				$CSVOutputFile = "\Log_Directory\"+$RecordFile+"_AuditRecords.csv"
				$OutputFile = Join-Path $PSScriptRoot $CSVOutputFile
				
				If(!(test-path $OutputFile)){
						Write-host "Creating the following file:" $OutputFile}
					
				[DateTime]$CurrentStart = $StartDate
				[DateTime]$CurrentEnd = $EndDate
				Write-Host "Extracting:  $record"
				echo ""
				
				while ($true){
					$CurrentEnd = $CurrentStart.AddMinutes($IntervalMinutes)
					$AmountResults = Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $CurrentEnd -RecordType $record -UserIds $script:Userstoextract -ResultSize 1 | out-string -Stream | select-string ResultCount
					
					if($AmountResults){
						$number = $AmountResults.tostring().split(":")[1]
						$script:integer = [int]$number
					
						while ($script:integer -gt 5000){
							$AmountResults = Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $CurrentEnd -RecordType $record -UserIds $script:Userstoextract -ResultSize 1 | out-string -Stream | select-string ResultCount
							if($AmountResults){
									$number = $AmountResults.tostring().split(":")[1]
									$script:integer = [int]$number
									if ($script:integer -lt 5000){
										if ($IntervalMinutes -eq 0){
											Exit}
										else{
											write-host "INFO: Temporary lowering time interval to $IntervalMinutes minutes" -ForegroundColor Yellow}}
									else{
										$IntervalMinutes = $IntervalMinutes / 2
										$CurrentEnd = $CurrentStart.AddMinutes($IntervalMinutes)}}
									
							else{
								Write-LogFile "INFO: Retrieving audit logs between $($CurrentStart) and $($CurrentEnd)"
								Write-Host "INFO: Retrieving audit logs between $($CurrentStart) and $($CurrentEnd)" -ForegroundColor green
								$Intervalmin = $IntervalMinutes
								$CurrentStart = $CurrentStart.AddMinutes($Intervalmin)
								$CurrentEnd = $CurrentStart.AddMinutes($Intervalmin)
								$AmountResults = Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $CurrentEnd -RecordType $record -UserIds $script:Userstoextract -ResultSize 1 | out-string -Stream | select-string ResultCount
								if($AmountResults){
									write-host $AmountResults
									$number = $AmountResults.tostring().split(":")[1]
									$script:integer = [int]$number}}}}
							
						ELSE{
							$IntervalMinutes = $ResetInterval}
						if ($CurrentEnd -gt $EndDate){				
							$DURATION = $EndDate - $Backupdate
							$durmin = $DURATION.TotalMinutes
							
							$CurrentEnd = $Backupdate
							$CurrentStart = $Backupdate
							
							$IntervalMinutes = $durmin /2
							if ($IntervalMinutes -eq 0){
								Exit
								}
							else{
								write-host "INFO: Temporary lowering time interval to $IntervalMinutes minutes" -ForegroundColor Yellow
								}
							$CurrentEnd = $CurrentEnd.AddMinutes($IntervalMinutes)}
						
						ELSEIF($CurrentEnd -eq $EndDate){
							Write-LogFile "INFO: Retrieving audit logs between $($CurrentStart) and $($CurrentEnd)"
							Write-Host "INFO: Retrieving audit logs between $($CurrentStart) and $($CurrentEnd)" -ForegroundColor green
							
							[Array]$results = Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $CurrentEnd -SessionID $SessionID -UserIds $script:Userstoextract -SessionCommand ReturnNextPreviewPage -ResultSize $ResultSize
							if($results){
								$results | epcsv $OutputFile -NoTypeInformation -Append
							}
							write-host "Acquisition complete, check the Log Directory for your files.." -ForegroundColor Red
							break
							Menu
						}
							
						$CurrentTries = 0
						$SessionID = [DateTime]::Now.ToString().Replace('/', '_')
						Write-LogFile "INFO: Retrieving audit logs between $($CurrentStart) and $($CurrentEnd)"
						Write-Host "INFO: Retrieving audit logs between $($CurrentStart) and $($CurrentEnd)" -ForegroundColor green
						$CurrentCount = 0
						
						while ($true){
							$CurrentEnd = $CurrentEnd.AddSeconds(-1)
							[Array]$results = Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $CurrentEnd -RecordType $record -UserIds $script:Userstoextract -SessionID $SessionID -SessionCommand ReturnNextPreviewPage -ResultSize $ResultSize
							$CurrentEnd = $CurrentEnd.AddSeconds(1)
							
							if ($results -eq $null -or $results.Count -eq 0){
								if ($CurrentTries -lt $RetryCount){
									$CurrentTries = $CurrentTries + 1
									continue}
								else{
									Write-LogFile "WARNING: Empty data set returned between $($CurrentStart) and $($CurrentEnd). Retry count reached. Moving forward!"
									break}}
									
							$CurrentTotal = $results[0].ResultCount
							$CurrentCount = $CurrentCount + $results.Count
							
							if ($CurrentTotal -eq $results[$results.Count - 1].ResultIndex){
								$message = "INFO: Successfully retrieved $($CurrentCount) records out of total $($CurrentTotal) for the current time range. Moving on!"
								$results | epcsv $OutputFile -NoTypeInformation -Append
								Write-LogFile $message
								Write-host $message
								break}}
							
						$CurrentStart = $CurrentEnd
						[DateTime]$Backupdate = $CurrentEnd}}
						
						else{
							Write-Host "No logs available for $record"  -ForegroundColor red
							echo ""}}
							
					#SHA256 hash calculation for the output files
					$HASHValues = Join-Path $PSScriptRoot "\Log_Directory\Hashes.csv"
					Get-ChildItem $LogDirectoryPath -Filter *_AuditRecords.csv | Get-FileHash -Algorithm SHA256 | epcsv $HASHValues
					
					echo ""
					Menu}
				
	#4 Extract specific audit logs
	"4" {		
		#All RecordTypes can be found at:
		#https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#enum-auditlogrecordtype---type-edmint32
		#https://docs.microsoft.com/en-us/powershell/module/exchange/policy-and-compliance-audit/search-unifiedauditlog?view=exchange-ps		
		write-host "Enter the RecordType(s) that need to be extracted, multiple recordtypes can be entered using comma separated values" -ForegroundColor Green
		write-host "The different RecordTypes can be found on our Github page (https://github.com/PwC-IR/Office-365-Extractor)"
		write-host "Example: SecurityComplianceCenterEOPCmdlet,SecurityComplianceAlerts,SharepointListOperation"
		$RecordTypes = read-host ">"
		echo ""
		
		[DateTime]$StartDate = Get-StartDate
		[DateTime]$EndDate = Get-EndDate
		
		echo ""
		write-host "Recommended interval is 480"
		Write-host "Lower the time interval for environments with a high log volume"
		echo ""
		
		$IntervalMinutes = read-host "Please enter a time interval or ENTER for 480"
		if ([string]::IsNullOrWhiteSpace($IntervalMinutes)) { $IntervalMinutes = "480" }
		
		$ResetInterval = $IntervalMinutes
		
		Write-LogFile "Start date provided by user: $StartDate"
		Write-LogFile "End date provided by user: $EndDate"
		Write-Logfile "Time Interval provided by user: $IntervalMinutes"
		

		Connect-ExchangeOnline
		echo ""
		Write-Host "----------------------------------------------------------------------------"
		Write-Host "|Extracting audit logs between "$StartDate" and "$EndDate"|"
		write-host "|Time interval: $IntervalMinutes                                                                       |"
		Write-Host "----------------------------------------------------------------------------" 
		Write-Host "The following RecordTypes are configured to be extracted:" -ForegroundColor Green
		
		Foreach ($record in $RecordTypes.Split(",")){
			Write-Host "-$record"}
		echo ""
		Foreach ($record in $RecordTypes.Split(",")){
			$SpecificResult = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType $record -UserIds $script:Userstoextract -ResultSize 1 |out-string -Stream | select-string ResultCount
			if($SpecificResult) {
				$NumberOfLogs = $SpecificResult.tostring().split(":")[1]
				$CSVOutputFile = "\Log_Directory\"+$record+"_AuditRecords.csv"
				$LogFile = Join-Path $PSScriptRoot $AuditLog
				$OutputFile = Join-Path $PSScriptRoot $CSVOutputFile
				
				If(!(test-path $OutputFile)){
						Write-host "Creating the following file:" $OutputFile}
				else{
					$date = [datetime]::Now.ToString('HHmm') 
					$CSVOutputFile = "Log_Directory\"+$date+$record+"_AuditRecords.csv"
					$OutputFile = Join-Path $PSScriptRoot $CSVOutputFile}
					
				[DateTime]$CurrentStart = $StartDate
				[DateTime]$CurrentEnd = $EndDate
				Write-Host "Extracting:  $record"
				Write-LogFile "Extracting:  $record"
				
				while ($true){
				$CurrentEnd = $CurrentStart.AddMinutes($IntervalMinutes)
				
				echo Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $CurrentEnd -RecordType $record -UserIds $script:Userstoextract -ResultSize 1 |out-string -Stream | select-string ResultCount
				$AmountResults = Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $CurrentEnd -RecordType $record -UserIds $script:Userstoextract -ResultSize 1 | out-string -Stream | select-string ResultCount
				if($AmountResults){
					$number = $AmountResults.tostring().split(":")[1]
					$script:integer = [int]$number
					
					while ($script:integer -gt 5000){
						$AmountResults = Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $CurrentEnd -RecordType $record -UserIds $script:Userstoextract -ResultSize 1 |out-string -Stream | select-string ResultCount
						if($AmountResults){
							$number = $AmountResults.tostring().split(":")[1]
							$script:integer = [int]$number
							if ($script:integer -lt 5000){
								if ($IntervalMinutes -eq 0){
									Exit}
								else{
									write-host "INFO: Temporary lowering time interval to $IntervalMinutes minutes" -ForegroundColor Yellow}}
							else{
								$IntervalMinutes = $IntervalMinutes / 2
								$CurrentEnd = $CurrentStart.AddMinutes($IntervalMinutes)}}
							
						else{
							Write-LogFile "INFO: Retrieving audit logs between $($CurrentStart) and $($CurrentEnd)"
							Write-Host "INFO: Retrieving audit logs between $($CurrentStart) and $($CurrentEnd)" -ForegroundColor green
							$Intervalmin = $IntervalMinutes
							$CurrentStart = $CurrentStart.AddMinutes($Intervalmin)
							$CurrentEnd = $CurrentStart.AddMinutes($Intervalmin)
							$AmountResults = Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $CurrentEnd -RecordType $record -UserIds $script:Userstoextract -ResultSize 1 |out-string -Stream | select-string ResultCount
							if($AmountResults){
								$number = $AmountResults.tostring().split(":")[1]
								$script:integer = [int]$number}}
								}}
					
				ELSE{
					$IntervalMinutes = $ResetInterval}
				if ($CurrentEnd -gt $EndDate){	
					$DURATION = $EndDate - $Backupdate
					$durmin = $DURATION.TotalMinutes
					
					$CurrentEnd = $Backupdate
					$CurrentStart = $Backupdate
					
					$IntervalMinutes = $durmin /2
					if ($IntervalMinutes -eq 0){
						Exit}
					else{
						write-host "INFO: Temporary lowering time interval to $IntervalMinutes minutes" -ForegroundColor Yellow}
						
					$CurrentEnd = $CurrentEnd.AddMinutes($IntervalMinutes)}
				
				ELSEIF($CurrentEnd -eq $EndDate){
					Write-LogFile "INFO: Retrieving audit logs between $($CurrentStart) and $($CurrentEnd)"
					Write-Host "INFO: Retrieving audit logs between $($CurrentStart) and $($CurrentEnd)" -ForegroundColor green
					
					[Array]$results = Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $CurrentEnd -RecordType $record -UserIds $script:Userstoextract -SessionID $SessionID -SessionCommand ReturnNextPreviewPage -ResultSize $ResultSize
					if($results){
						$results | epcsv $OutputFile -NoTypeInformation -Append
					}
					write-host "Acquisition complete, check the Log Directory for your files.." -ForegroundColor Red
					break
					Menu
				}
				$CurrentTries = 0
				$SessionID = [DateTime]::Now.ToString().Replace('/', '_')
				Write-LogFile "INFO: Retrieving audit logs between $($CurrentStart) and $($CurrentEnd)"
				Write-Host "INFO: Retrieving audit logs between $($CurrentStart) and $($CurrentEnd)" -ForegroundColor green
				$CurrentCount = 0
				while ($true){
					$CurrentEnd = $CurrentEnd.AddSeconds(-1)
					[Array]$results = Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $CurrentEnd -RecordType $record -UserIds $script:Userstoextract -SessionID $SessionID -SessionCommand ReturnNextPreviewPage -ResultSize $ResultSize
					$CurrentEnd = $CurrentEnd.AddSeconds(1)
					
					if ($results -eq $null -or $results.Count -eq 0){
						if ($CurrentTries -lt $RetryCount){
							$CurrentTries = $CurrentTries + 1
							continue}
						else{
							Write-LogFile "WARNING: Empty data set returned between $($CurrentStart) and $($CurrentEnd). Retry count reached. Moving forward!"
							break}}
							
					$CurrentTotal = $results[0].ResultCount
					$CurrentCount = $CurrentCount + $results.Count
					
					if ($CurrentTotal -eq $results[$results.Count - 1].ResultIndex){
						$message = "INFO: Successfully retrieved $($CurrentCount) records out of total $($CurrentTotal) for the current time range. Moving on!"
						$results | epcsv $OutputFile -NoTypeInformation -Append
						Write-LogFile $message
						Write-host $message
						break}}
					
				$CurrentStart = $CurrentEnd
				[DateTime]$Backupdate = $CurrentEnd}}
				
				else{
					Write-Host "No logs available for $record"  -ForegroundColor red
					echo ""}}
			
			#SHA256 hash calculation for the output files
			$HASHValues = Join-Path $PSScriptRoot "\Log_Directory\Hashes.csv"
			Get-ChildItem $LogDirectoryPath -Filter *_AuditRecords.csv | Get-FileHash -Algorithm SHA256 | epcsv $HASHValues -NoTypeInformation -Append	
			
			echo ""
			Menu}
	
	"5" {
@"
		
For a full readme please visit our Github page https://github.com/invictus-ir/Microsoft-365-Extractor-Suite

"@}
	"6" {Write-Host "Quitting" -ForegroundColor Green}}}
function Menu{
$menupart2=@"
Following actions are supported by this script:
1 Show available log sources and amount of logging	
2 Extract all audit logging
3 Extract group audit logging
4 Extract specific audit logging (advanced mode)
5 ReadMe
6 Quit

"@
	$menupart2
	$script:input = Read-Host "Select an action" 
	Main
	While($script:input -ne "1" -and $script:input -ne "2" -and $script:input -ne "3" -and $script:input -ne "4" -and $script:input -ne "5" -and $script:input -ne "6"){
		Write-Host "I don't understand what you want to do." -ForegroundColor Red
		Write-Host " " 
		$script:input = Read-Host $menupart2
	Main}}
	
Menu
