Function Get-UALGraph {
<#
    .SYNOPSIS
    Gets all the unified audit log entries.

    .DESCRIPTION
    Makes it possible to extract all unified audit data out of a Microsoft 365 environment. 
    The output will be written to: Output\UnifiedAuditLog\

    .PARAMETER UserIds
    UserIds is the UserIds parameter filtering the log entries by the account of the user who performed the actions.

    .PARAMETER StartDate
    startDate is the parameter specifying the start date of the date range.
    Default: Today -90 days

    .PARAMETER EndDate
    endDate is the parameter specifying the end date of the date range.
    Default: Now

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\UnifiedAuditLog

    .PARAMETER MaxEventsPerFile
    Specifies the maximum number of events per output file. When this number is reached, a new file will be created.
    Default: 250000

    .PARAMETER Output
    Output is the parameter specifying the CSV, JSON, JSONL or SOF-ELK output type. The SOF-ELK output can be imported into the platform of the same name.
    Default: JSON

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Debug: Verbose logging for debugging purposes
    Default: Standard

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV/JSON output file.
    Default: UTF8

    .PARAMETER RecordType
    The RecordType parameter filters the log entries by record type.
    Options are: ExchangeItem, ExchangeAdmin, etc.

    .PARAMETER Keyword
    The Keyword parameter allows you to filter the Unified Audit Log for specific keywords.

    .PARAMETER Service
    The Service parameter filters the Unified Audit Log based on the specific services.
    Options are: Exchange,Skype,Sharepoint etc.

    .PARAMETER Operations
    The Operations parameter filters the log entries by operation or activity type. Usage: -Operations UserLoggedIn,MailItemsAccessed
    Options are: New-MailboxRule, MailItemsAccessed, etc.

    .PARAMETER IPAddress
    The IP address parameter is used to filter the logs by specifying the desired IP address.
    
    .PARAMETER SearchName
    Specifies the name of the search query. This parameter is required.

    .PARAMETER SplitFiles
    When specified, splits output into multiple files based on MaxEventsPerFile.
    When set to True, splits output into multiple files based on MaxEventsPerFile.
    Default: If not specified, outputs to a single file.

    .PARAMETER ObjecIDs 
    Exact data returned depends on the service in the current `@odatatype.microsoft.graph.security.auditLogQuery` record.
    For Exchange admin audit logging, the name of the object modified by the cmdlet.
    For SharePoint activity, the full URL path name of the file or folder accessed by a user. 
    For Microsoft Entra activity, the name of the user account that was modified.|
    
    .EXAMPLE
    Get-UALGraph -searchName Test 
    Gets all the unified audit log entries.
    
    .EXAMPLE
    Get-UALGraph -searchName Test -UserIds Test@invictus-ir.com
    Gets all the unified audit log entries for the user Test@invictus-ir.com.
    
    .EXAMPLE
    Get-UALGraph -searchName Test -startDate "2024-03-10T09:28:56Z" -endDate "2024-03-20T09:28:56Z" -Service Exchange
    Retrieves audit log data for the specified time range March 10, 2024 to March 20, 2024 and filters the results to include only events related to the Exchange service.
    
    .EXAMPLE
    Get-UALGraph -searchName Test -startDate "2024-03-01" -endDate "2024-03-10" -IPAddress 182.74.242.26
    Retrieve audit log data for the specified time range March 1, 2024 to March 10, 2024 and filter the results to include only entries associated with the IP address 182.74.242.26.

    .EXAMPLE
    Get-UALGraph -searchName Test -MaxEventsPerFile 500000 -SplitFiles
    Gets all the unified audit log entries with 500,000 events per output file.

#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$searchName,
        [string]$OutputDir = "Output\UnifiedAuditLog\",
        [string]$Encoding = "UTF8",
        [string]$startDate,
        [string]$endDate,
        [string[]]$RecordType = @(),
        [string]$Keyword = "",
        [string]$Service = "",
        [string[]]$Operations = @(),
        [string[]]$UserIds = @(),
        [string[]]$IPAddress = @(),
        [string[]]$ObjecIDs = @(),
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard',
        [double]$MaxEventsPerFile = 250000,
        [ValidateSet("CSV", "JSON", "JSONL", "SOF-ELK")]
        [string]$Output = "JSON",
        [switch]$SplitFiles
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebugEnabled = $script:LogLevel -eq [LogLevel]::Debug

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] PowerShell Version: $($PSVersionTable.PSVersion)" -Level Debug
        Write-LogFile -Message "[DEBUG] Input parameters:" -Level Debug
        Write-LogFile -Message "[DEBUG]   SearchName: '$searchName'" -Level Debug
        Write-LogFile -Message "[DEBUG]   OutputDir: '$OutputDir'" -Level Debug
        Write-LogFile -Message "[DEBUG]   Encoding: '$Encoding'" -Level Debug
        Write-LogFile -Message "[DEBUG]   StartDate: '$startDate'" -Level Debug
        Write-LogFile -Message "[DEBUG]   EndDate: '$endDate'" -Level Debug
        Write-LogFile -Message "[DEBUG]   RecordType: '$($RecordType -join ', ')'" -Level Debug
        Write-LogFile -Message "[DEBUG]   Keyword: '$Keyword'" -Level Debug
        Write-LogFile -Message "[DEBUG]   Service: '$Service'" -Level Debug
        Write-LogFile -Message "[DEBUG]   Operations: '$($Operations -join ', ')'" -Level Debug
        Write-LogFile -Message "[DEBUG]   UserIds: '$($UserIds -join ', ')'" -Level Debug
        Write-LogFile -Message "[DEBUG]   IPAddress: '$($IPAddress -join ', ')'" -Level Debug
        Write-LogFile -Message "[DEBUG]   ObjecIDs: '$($ObjecIDs -join ', ')'" -Level Debug
        Write-LogFile -Message "[DEBUG]   MaxEventsPerFile: $MaxEventsPerFile" -Level Debug
        Write-LogFile -Message "[DEBUG]   Output: '$Output'" -Level Debug
        Write-LogFile -Message "[DEBUG]   SplitFiles: $SplitFiles" -Level Debug
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

    $date = Get-Date -Format "yyyyMMddHHmm"
    $summary = @{
        TotalRecords = 0
        ProcessedRecords = 0
        ExportedFiles = 0
        StartTime = Get-Date
        ProcessingTime = $null
        SearchId = ""
    }

    $requiredScopes = @("AuditLogsQuery.Read.All")
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

    Write-LogFile -Message "=== Starting Microsoft Graph Audit Log Retrieval ===" -Color "Cyan" -Level Standard
    
    StartDate -Quiet
    EndDate -Quiet
    $dateRange = "$($script:StartDate.ToString('yyyy-MM-dd HH:mm:ss')) to $($script:EndDate.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-LogFile -Message "Analysis Period: $dateRange" -Level Standard
    Write-LogFile -Message "Output Directory: $OutputDir" -Level Standard
    Write-LogFile -Message "Output format: $Output" -Level Standard
    Write-LogFile -Message "----------------------------------------`n" -Level Standard

    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir > $null
    } 
    else {
        if (!(Test-Path -Path $OutputDir)) {
            Write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
            Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir exiting script" -Level Minimal
        }
    }

    $body = @{
        "@odata.type" = "#microsoft.graph.security.auditLogQuery"
        displayName = $searchName
        filterStartDateTime = $script:startDate
        filterEndDateTime = $script:endDate
        recordTypeFilters = $RecordType
        keywordFilter = $Keyword
        serviceFilter = $Service
        operationFilters = $Operations
        userPrincipalNameFilters = $UserIds
        ipAddressFilters = $IPAddress
        objectIdFilters = $ObjecIDs
        administrativeUnitIdFilters = @()
        status = ""
    } | ConvertTo-Json

    try {
        
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Initiating Graph API audit log query..." -Level Debug
            $createPerformance = Measure-Command {
                $response = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/security/auditLog/queries" -Body $body -ContentType "application/json"
            }
            Write-LogFile -Message "[DEBUG] Query creation took $([math]::round($createPerformance.TotalSeconds, 2)) seconds" -Level Debug
        } else {
            $response = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/security/auditLog/queries" -Body $body -ContentType "application/json"
        }
        
        $scanId = $response.id
        $summary.SearchId = $scanId
        write-logFile -Message "[INFO] A new Unified Audit Log search has started with the name: $searchName and ID: $scanId." -Color "Green" -Level Minimal
    
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Search created successfully:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Search ID: $scanId" -Level Debug
            Write-LogFile -Message "[DEBUG]   Response status: $($response.status)" -Level Debug
        }

        Start-Sleep -Seconds 10
        $apiUrl = "https://graph.microsoft.com/beta/security/auditLog/queries/$scanId"

        write-logFile -Message "[INFO] Waiting for the scan to start..." -Level Standard
        $lastStatus = ""
        do {
            $response = Invoke-MgGraphRequest -Method Get -Uri $apiUrl -ContentType 'application/json'
            $status = $response.status
            if ($status -ne $lastStatus) {
                $lastStatus = $status
            }
            Start-Sleep -Seconds 5
        } while ($status -ne "succeeded" -and $status -ne "running")
        if ($status -eq "running") {
            write-logFile -Message "[INFO] Unified Audit Log search has started... This can take a while..." -Level Standard
            do {
                $response = Invoke-MgGraphRequest -Method Get -Uri $apiUrl -ContentType 'application/json'
                $status = $response.status
                if ($status -ne $lastStatus) {
                    if ($isDebugEnabled -and $status -ne $lastStatus) {
                        Write-LogFile -Message "[DEBUG] Status changed to: $status" -Level Debug
                    }
                    write-logFile -Message "[INFO] Unified Audit Log search is still running. Waiting..." -Level Standard
                    $lastStatus = $status
                }
                Start-Sleep -Seconds 5
            } while ($status -ne "succeeded")
        }
       write-logFile -Message "[INFO] Unified Audit Log search complete." -Level Minimal
    }
    catch {
        Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Error details:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Error message: $($_.Exception.Message)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
        }
        throw
    }

    try {
        write-logFile -Message "[INFO] Collecting scan results from api (this may take a while)" -Level Standard
        $date = [datetime]::Now.ToString('yyyyMMddHHmmss') 

        $fileCounter = 1
        $currentFileEvents = 0
        $totalEvents = 0
        $outputFileBase = "$($date)-$searchName-UnifiedAuditLog"

        if ($SplitFiles) {
            if ($Output -eq "JSON") {
                $outputFilePath = "$outputFileBase-part$fileCounter.json"
                $filePath = Join-Path -Path $OutputDir -ChildPath $outputFilePath
                "[" | Out-File -FilePath $filePath -Encoding $Encoding
                $firstRecordInFile = $true
            } 
            elseif ($Output -eq "CSV") {
                $outputFilePath = "$outputFileBase-part$fileCounter.csv"
                $filePath = Join-Path -Path $OutputDir -ChildPath $outputFilePath
                $csvCollection = @()
            }
            elseif ($Output -eq "JSONL") {
                $outputFilePath = "$outputFileBase-part$fileCounter.jsonl"
                $filePath = Join-Path -Path $OutputDir -ChildPath $outputFilePath
                $firstRecordInFile = $true
            }
            elseif ($Output -eq "SOF-ELK") {
                $outputFilePath = "$outputFileBase-part$fileCounter.json"
                $filePath = Join-Path -Path $OutputDir -ChildPath $outputFilePath
            }
        } 
        else {
            if ($Output -eq "JSON") {
                $outputFilePath = "$outputFileBase.json"
                $filePath = Join-Path -Path $OutputDir -ChildPath $outputFilePath
                "[" | Out-File -FilePath $filePath -Encoding $Encoding
                $firstRecordInFile = $true
            }
            elseif ($Output -eq "CSV") {
                $outputFilePath = "$outputFileBase.csv"
                $filePath = Join-Path -Path $OutputDir -ChildPath $outputFilePath
                $csvCollection = @()
            }
            elseif ($Output -eq "JSONL") {
                $outputFilePath = "$outputFileBase.jsonl"
                $filePath = Join-Path -Path $OutputDir -ChildPath $outputFilePath
                $firstRecordInFile = $true
            }
            elseif ($Output -eq "SOF-ELK") {
                $outputFilePath = "$outputFileBase.json"
                $filePath = Join-Path -Path $OutputDir -ChildPath $outputFilePath
            }
        }

        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Starting data collection:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Split files: $SplitFiles" -Level Debug
            Write-LogFile -Message "[DEBUG]   Max events per file: $MaxEventsPerFile" -Level Debug
            Write-LogFile -Message "[DEBUG]   Initial file path: $filePath" -Level Debug
        }

        $apiUrl = "https://graph.microsoft.com/beta/security/auditLog/queries/$scanId/records"
        Write-LogFile -Message "[INFO] Starting to collect records..." -Level Standard

        Do {
            $maxRetries = 3
            $retryCount = 0
            $success = $false
            $response = $null

            while (-not $success -and $retryCount -lt $maxRetries) {
                try {
                    if ($isDebugEnabled) {
                        Write-LogFile -Message "[DEBUG] Attempting to fetch records batch (attempt $($retryCount + 1))" -Level Debug
                        Write-LogFile -Message "[DEBUG] API URL: $apiUrl" -Level Debug
                    }
                    $response = Invoke-MgGraphRequest -Method Get -Uri $apiUrl -ContentType "application/json; odata.metadata=minimal; odata.streaming=true;" -OutputType Json
                    $success = $true
                    if ($isDebugEnabled) {
                        Write-LogFile -Message "[DEBUG] Successfully retrieved batch data" -Level Debug
                    }
                }
                catch {
                    $retryCount++
                    $errorMessage = $_.Exception.Message

                    if ($isDebugEnabled) {
                        Write-LogFile -Message "[DEBUG] Error details:" -Level Debug
                        Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
                        Write-LogFile -Message "[DEBUG]   Error message: $errorMessage" -Level Debug
                        Write-LogFile -Message "[DEBUG]   Retry count: $retryCount of $maxRetries" -Level Debug
                    }
                    
                    
                    if ($retryCount -lt $maxRetries) {
                        $waitTime = 30 * $retryCount
                        Write-LogFile -Message "[WARNING] Error: $errorMessage. Retry $retryCount of $maxRetries. Waiting $waitTime seconds before retrying..." -Color "Yellow" -Level Standard
                        Start-Sleep -Seconds $waitTime
                        
                        try {
                            $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes
                            Write-LogFile -Message "[INFO] Successfully refreshed Graph API connection." -Level Standard
                        }
                        catch {
                            Write-LogFile -Message "[WARNING] Failed to refresh credentials: $($_.Exception.Message)" -Level Standard
                        }
                    }
                    else {
                        Write-LogFile -Message "[ERROR] Failed after $maxRetries attempts: $errorMessage" -Color "Red" -Level Minimal
                        throw $_  
                    }
                }
            }

            $responseJson = $response | ConvertFrom-Json 

            if ($responseJson.value -and $responseJson.value.Count -gt 0) {
                $batchCount = $responseJson.value.Count
                $totalEvents += $batchCount

                if ($isDebugEnabled) {
                    Write-LogFile -Message "[DEBUG] Processing batch: $batchCount records (Total: $totalEvents)" -Level Debug
                    Write-LogFile -Message "[DEBUG] Current file events: $currentFileEvents" -Level Debug
                }

                if ($Output -eq "JSON") {
                    foreach ($record in $responseJson.value) {
                        if ($SplitFiles -and $currentFileEvents -ge $MaxEventsPerFile) {
                            "]" | Out-File -FilePath $filePath -Append -Encoding $Encoding
                            Write-LogFile -Message "[INFO] File complete: $outputFilePath ($currentFileEvents events)" -Level Standard
                            
                            $fileCounter++
                            $summary.ExportedFiles++
                            $currentFileEvents = 0
                            
                            $outputFilePath = "$outputFileBase-part$fileCounter.json"
                            $filePath = Join-Path -Path $OutputDir -ChildPath $outputFilePath
                            "[" | Out-File -FilePath $filePath -Encoding $Encoding
                            $firstRecordInFile = $true
                        }

                        if (-not $firstRecordInFile) {
                            "," | Out-File -FilePath $filePath -Append -Encoding $Encoding -NoNewline
                        } else {
                            $firstRecordInFile = $false
                        }
                        "`r`n" | Out-File -FilePath $filePath -Append -Encoding $Encoding -NoNewline

                        $record | ConvertTo-Json -Depth 100 | Out-File -FilePath $filePath -Append -Encoding $Encoding -NoNewline

                        $currentFileEvents++
                        $summary.ProcessedRecords++
                    }
                }
                elseif ($Output -eq "CSV") {
                    $csvCollection += $responseJson.value
                    $currentFileEvents += $batchCount
                    $summary.ProcessedRecords += $batchCount

                    if ($SplitFiles -and $currentFileEvents -ge $MaxEventsPerFile) {
                        $csvCollection | Select-Object id, createdDateTime, auditLogRecordType, operation, organizationId, userType, userId, service, objectId, userPrincipalName, clientIp, administrativeUnits, @{Name = "auditData"; Expression = { $_.auditData | ConvertTo-Json -Depth 100 } } | Export-Csv -Path $filePath -Append -Encoding $Encoding -NoTypeInformation
                        Write-LogFile -Message "[INFO] File complete: $outputFilePath ($currentFileEvents events)" -Level Standard
                        
                        $fileCounter++
                        $summary.ExportedFiles++
                        $currentFileEvents = 0
                        
                        $csvCollection = @()
                        $outputFilePath = "$outputFileBase-part$fileCounter.csv"
                        $filePath = Join-Path -Path $OutputDir -ChildPath $outputFilePath
                    }
                }
                elseif ($Output -eq "JSONL") {
                    foreach ($record in $responseJson.value) {
                        if ($SplitFiles -and $currentFileEvents -ge $MaxEventsPerFile) {
                            Write-LogFile -Message "[INFO] File complete: $outputFilePath ($currentFileEvents events)" -Level Standard
                            
                            $fileCounter++
                            $summary.ExportedFiles++
                            $currentFileEvents = 0

                            $outputFilePath = "$outputFileBase-part$fileCounter.jsonl"
                            $filePath = Join-Path -Path $OutputDir -ChildPath $outputFilePath
                        }
                        if ($record.auditData) {
                            $record.auditData | ConvertTo-Json -Compress -Depth 100 | 
                                Out-File -Append $filePath -Encoding UTF8
                        }
                        "`r`n" | Out-File -FilePath $filePath -Append -Encoding UTF8
                        $currentFileEvents++
                        $summary.ProcessedRecords++
                    }
                }
                elseif ($Output -eq "SOF-ELK") {
                    foreach ($record in $responseJson.value) {
                        if ($SplitFiles -and $currentFileEvents -ge $MaxEventsPerFile) {
                            Write-LogFile -Message "[INFO] File complete: $outputFilePath ($currentFileEvents events)" -Level Standard
                            
                            $fileCounter++
                            $summary.ExportedFiles++
                            $currentFileEvents = 0

                            $outputFilePath = "$outputFileBase-part$fileCounter.json"
                            $filePath = Join-Path -Path $OutputDir -ChildPath $outputFilePath
                        }
                        if ($record.auditData) {
                            $record.auditData | ConvertTo-Json -Compress -Depth 100 | 
                                Out-File -Append $filePath -Encoding UTF8
                        }
                        $currentFileEvents++
                        $summary.ProcessedRecords++
                    }
                }

                if ($totalEvents % 10000 -eq 0 -or $batchCount -lt 100) {
                    Write-LogFile -Message "[INFO] Progress: $totalEvents total events processed" -Level Standard
                    if ($isDebugEnabled) {
                        Write-LogFile -Message "[DEBUG] Progress details:" -Level Debug
                        Write-LogFile -Message "[DEBUG]   Batch size: $batchCount" -Level Debug
                        Write-LogFile -Message "[DEBUG]   Current file: $outputFilePath" -Level Debug
                        Write-LogFile -Message "[DEBUG]   Current file events: $currentFileEvents" -Level Debug
                    }
                }
            } else {
                if ($totalEvents -eq 0) {
                    Write-LogFile -Message "[INFO] No results matched your search." -Color Yellow -Level Minimal
                }
            }
            $apiUrl = $responseJson.'@odata.nextLink'
        } While ($apiUrl)

        if ($currentFileEvents -gt 0) {
            if ($Output -eq "JSON") {
                "]" | Out-File -FilePath $filePath -Append -Encoding $Encoding
            }
            elseif ($Output -eq "CSV" -and $csvCollection.Count -gt 0) {
                $csvCollection | Select-Object id, createdDateTime, auditLogRecordType, operation, organizationId, userType, userId, service, objectId, userPrincipalName, clientIp, administrativeUnits, @{Name = "auditData"; Expression = { $_.auditData | ConvertTo-Json -Depth 100 } } | Export-Csv -Path $filePath -Append -Encoding $Encoding -NoTypeInformation

                
            }
            $summary.ExportedFiles++
        }

        $summary.TotalRecords = $totalEvents
        $summary.ProcessingTime = (Get-Date) - $summary.StartTime

        Write-LogFile -Message "`n=== Audit Log Retrieval Summary ===" -Color "Cyan" -Level Standard
        Write-LogFile -Message "Time Period: $dateRange" -Level Standard
        Write-LogFile -Message "Search Name: $SearchName" -Level Standard
        Write-LogFile -Message "Search ID: $($summary.SearchId)" -Level Standard
        Write-LogFile -Message "Total Records Retrieved: $($summary.TotalRecords)" -Level Standard
        if ($summary.TotalRecords -eq 0) {
            Write-LogFile -Message "No results matched your search criteria." -Color "Yellow" -Level Standard
        }
        Write-LogFile -Message "Files Created: $($summary.ExportedFiles)" -Level Minimal
        Write-LogFile -Message "Output Directory: $OutputDir" -Level Standard
        Write-LogFile -Message "Processing Time: $($summary.ProcessingTime.ToString('hh\:mm\:ss'))"  -Color "Green" -Level Standard
        Write-LogFile -Message "===================================" -Color "Cyan" -Level Standard      
    }
    catch {
        Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        throw
    }
}
            
            
            
            