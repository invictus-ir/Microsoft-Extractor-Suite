$menupart1=@"


  __  __ _                           __ _     ____    __ _____   ______      _                  _                 
 |  \/  (_)                         / _| |   |___ \  / /| ____| |  ____|    | |                | |             | (_)     | |   | |  
 | \  / |_  ___ _ __ ___  ___  ___ | |_| |_    __) |/ /_| |__   | |__  __  _| |_ _ __ __ _  ___| |_ ___  _ __  | |_  __ _| |__ | |_ 
 | |\/| | |/ __| '__/ _ \/ __|/ _ \|  _| __|  |__ <| '_ \___ \  |  __| \ \/ / __| '__/ _` |/ __| __/ _ \| '__| | | |/ _` | '_ \| __|
 | |  | | | (__| | | (_) \__ \ (_) | | | |_   ___) | (_) |__) | | |____ >  <| |_| | | (_| | (__| || (_) | |    | | | (_| | | | | |_ 
 |_|  |_|_|\___|_|  \___/|___/\___/|_|  \__| |____/ \___/____/  |______/_/\_\\__|_|  \__,_|\___|\__\___/|_|    |_|_|\__, |_| |_|\__|
                                                                                                                     __/ |          
                                                                                                                    |___/           
                                                                                                                            
                                                                                                                                
Copyright (c) 2022 Invictus Incident Response
New version of the Office 365 Extractor script, originally created by Joey Rentenaar & Korstiaan Stam formerly PwC Incident Response Netherlands.
Documentation available on https://github.com/invictus-ir/Microsoft-365-Extractor-Suite

"@


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
	if ([string]::IsNullOrWhiteSpace($IntervalMinutes)) { $IntervalMinutes = "480" }
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
		
		$AmountResults = Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $CurrentEnd -UserIds $script:Userstoextract -ResultSize 1 | Format-List -Property ResultCount| out-string -Stream | select-string ResultCount
		if($AmountResults){
			$number = $AmountResults.tostring().split(":")[1]
			$script:integer = [int]$number
			
			while ($script:integer -gt 5000){
				$AmountResults = Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $CurrentEnd -UserIds $script:Userstoextract -ResultSize 1 | Format-List -Property ResultCount|out-string -Stream | select-string ResultCount
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
					$AmountResults = Search-UnifiedAuditLog -StartDate $CurrentStart -EndDate $CurrentEnd -UserIds $script:Userstoextract -ResultSize 1 | Format-List -Property ResultCount| out-string -Stream | select-string ResultCount
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
			Main
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
}
$menupart1
Main