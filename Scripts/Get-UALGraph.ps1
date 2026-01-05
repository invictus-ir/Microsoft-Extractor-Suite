function Format-AuditRecordForCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $Record
    )
    process {
        $Record | Select-Object id, createdDateTime, auditLogRecordType, operation, organizationId, userType, userId, service, objectId, userPrincipalName, clientIp, administrativeUnits, @{Name = "auditData"; Expression = { $_.auditData | ConvertTo-Json -Depth 100 -Compress } }
    }
}

function Save-StateFile {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)]$StateFilePath
    )
    $State.lastUpdated = (Get-Date).ToString('o')
    $State | ConvertTo-Json -Depth 10 | Set-Content -Path $StateFilePath -Encoding UTF8
}

Function Get-UALGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$searchName,
        [string]$OutputDir,
        [string]$Encoding = "UTF8",
        [string]$startDate,
        [string]$endDate,
        [string[]]$RecordType = @(),
        [string]$Keyword = "",
        [string]$Service = "",
        [string[]]$Operations = @(),
        [string[]]$UserIds = @(),
        [string[]]$IPAddress = @(),
        [string[]]$ObjectIDs = @(),
        [ValidateRange(1, 5000)]
        [System.Nullable[int]]$BatchSize = $null,
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard',
        [double]$MaxEventsPerFile = 250000,
        [ValidateSet("CSV", "JSON", "JSONL", "SOF-ELK")]
        [string]$Output = "JSON",
        [switch]$SplitFiles,
        [switch]$Resume,
        [string]$StateFile
    )

    Init-OutputDir -Component "UnifiedAuditLog" -FilePostfix $searchName -CustomOutputDir $OutputDir
    Init-Logging

    $summary = @{
        TotalRecords     = 0
        ProcessedRecords = 0
        ExportedFiles    = 0
        StartTime        = Get-Date
        ProcessingTime   = $null
        SearchId         = ""
    }

    $requiredScopes = @("AuditLogsQuery.Read.All")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes
    $outputDirPath = Split-Path $script:outputFile -Parent

    Write-LogFile -Message "=== Starting Microsoft Graph Audit Log Retrieval ===" -Color "Cyan" -Level Standard

    StartDate -Quiet
    EndDate -Quiet

    $dateRange = "$($script:StartDate.ToString('yyyy-MM-dd HH:mm:ss')) to $($script:EndDate.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-LogFile -Message "Analysis Period: $dateRange" -Level Standard
    Write-LogFile -Message "Output Directory: $outputDirPath" -Level Standard
    Write-LogFile -Message "Output format: $Output" -Level Standard
    Write-LogFile -Message "----------------------------------------`n" -Level Standard

    $searchSucceeded = $false

    if ($Resume) {
        if (-not $StateFile) {
            $StateFile = Join-Path -Path (Get-Location) -ChildPath "$searchName-UALGraph-state.json"
        }

        if (-not (Test-Path $StateFile)) {
            Write-LogFile -Message "[ERROR] State file not found: $StateFile" -Color "Red" -Level Minimal
            throw "Cannot resume: state file not found. Specify path with -StateFile or ensure $searchName-UALGraph-state.json exists in current directory."
        }

        $state = Get-Content -Path $StateFile | ConvertFrom-Json

        Write-LogFile -Message "[INFO] Resuming from state file: $StateFile" -Color "Cyan" -Level Standard
        Write-LogFile -Message "[INFO] Resuming search: $($state.searchName) (ID: $($state.scanId))" -Level Standard
        Write-LogFile -Message "[INFO] Previously processed: $($state.totalEventsProcessed) events" -Level Standard

        $scanId = $state.scanId
        $summary.SearchId = $scanId
        if ($state.searchStatus -eq "succeeded") {
            $searchSucceeded = $true
        }

        $apiUrl = "https://graph.microsoft.com/beta/security/auditLog/queries/$scanId"

    }
    else {
        $body = @{
            "@odata.type"               = "#microsoft.graph.security.auditLogQuery"
            displayName                 = $searchName
            filterStartDateTime         = $script:startDate
            filterEndDateTime           = $script:endDate
            recordTypeFilters           = $RecordType
            keywordFilter               = $Keyword
            serviceFilter               = $Service
            operationFilters            = $Operations
            userPrincipalNameFilters    = $UserIds
            ipAddressFilters            = $IPAddress
            objectIdFilters             = $ObjectIDs
            administrativeUnitIdFilters = @()
            status                      = ""
        } | ConvertTo-Json

        try {

            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Initiating Graph API audit log query..." -Level Debug
                $createPerformance = Measure-Command {
                    $response = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/security/auditLog/queries" -Body $body -ContentType "application/json"
                }
                Write-LogFile -Message "[DEBUG] Query creation took $([math]::round($createPerformance.TotalSeconds, 2)) seconds" -Level Debug
            }
            else {
                $response = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/security/auditLog/queries" -Body $body -ContentType "application/json"
            }

            $scanId = $response.id
            $summary.SearchId = $scanId

            if (-not $StateFile) {
                $StateFile = Join-Path -Path (Get-Location) -ChildPath "$searchName-UALGraph-state.json"
            }

            $state = @{
                searchName           = $searchName
                scanId               = $scanId
                nextLink             = $null
                totalEventsProcessed = 0
                currentFileEvents    = 0
                fileCounter          = $null
                firstRecordInFile    = $null
                outputFileBase       = $null
                outputFilePath       = $null
                filePath             = $null
                outputDirPath        = $outputDirPath
                outputFormat         = $Output
                splitFiles           = [bool]$SplitFiles
                encoding             = $Encoding
                maxEventsPerFile     = $MaxEventsPerFile
                searchStatus         = "created"
                startedAt            = (Get-Date).ToString('o')
                lastUpdated          = (Get-Date).ToString('o')
            }

            Save-StateFile -State $state -StateFilePath $StateFile
            Write-LogFile -Message "[INFO] State file created: $StateFile" -Level Standard

            Write-LogFile -Message "[INFO] A new Unified Audit Log search has started with the name: $($state.searchName) and ID: $scanId." -Color "Green" -Level Minimal

            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Search created successfully:" -Level Debug
                Write-LogFile -Message "[DEBUG]   Search ID: $scanId" -Level Debug
                Write-LogFile -Message "[DEBUG]   Response status: $($response.status)" -Level Debug
            }

            Start-Sleep -Seconds 10
            $apiUrl = "https://graph.microsoft.com/beta/security/auditLog/queries/$scanId"
            Write-LogFile -Message "[INFO] Waiting for the scan to start..." -Level Standard
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
    }

    if (-not $searchSucceeded) {
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
        Write-LogFile -Message "[INFO] Unified Audit Log search complete." -Level Minimal
        $state.searchStatus = "succeeded"
        Save-StateFile -State $state -StateFilePath $StateFile
    }
    else {
        Write-LogFile -Message "[INFO] Resuming from previously completed search." -Level Standard
    }

    try {
        write-logFile -Message "[INFO] Collecting scan results from api (this may take a while)" -Level Standard

        if ($Resume) {
            if ($state.outputFormat -eq "JSON") {
                Write-LogFile -Message "[ERROR] Cannot resume with JSON output format. JSON files may be corrupted on crash due to bracket/comma encoding. Use JSONL, CSV, or SOF-ELK for resumable exports." -Color "Red" -Level Minimal
                throw "Resume is not supported with JSON output format. Please use -Output JSONL, CSV, or SOF-ELK instead."
            }
        }
        else {
            $state.totalEventsProcessed = 0
        }

        if (-not $state.outputFileBase) {
            $date = [datetime]::Now.ToString('yyyyMMddHHmmss')
            $state.fileCounter = 1
            $state.currentFileEvents = 0
            $state.outputFileBase = "$($date)-$($state.searchName)-UnifiedAuditLog"
            $state.firstRecordInFile = $true

            $fileExtension = switch ($state.outputFormat) {
                "CSV" { "csv" }
                "JSONL" { "jsonl" }
                default { "json" }
            }
            $fileSuffix = if ($state.splitFiles) { "-part$($state.fileCounter)" } else { "" }
            $state.outputFilePath = "$($state.outputFileBase)$fileSuffix.$fileExtension"
            $state.filePath = Join-Path -Path $state.outputDirPath -ChildPath $state.outputFilePath

            if ($state.outputFormat -eq "JSON") {
                "[" | Out-File -FilePath $state.filePath -Encoding $state.encoding
            }

            Save-StateFile -State $state -StateFilePath $StateFile
        }


        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Starting data collection:" -Level Debug
            Write-LogFile -Message "[DEBUG]   Split files: $($state.splitFiles)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Max events per file: $($state.maxEventsPerFile)" -Level Debug
            Write-LogFile -Message "[DEBUG]   Initial file path: $($state.filePath)" -Level Debug
        }

        if ($Resume -and $state.nextLink) {
            $apiUrl = $state.nextLink
            Write-LogFile -Message "[INFO] Resuming from saved position..." -Level Standard
        }
        else {
            if ($BatchSize) {
                $apiUrl = "https://graph.microsoft.com/beta/security/auditLog/queries/$($state.scanId)/records?`$top=$BatchSize"
            }
            else {
                $apiUrl = "https://graph.microsoft.com/beta/security/auditLog/queries/$($state.scanId)/records"
            }
        }
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

            $responseJson = $response | ConvertFrom-Json -Depth 100

            Write-LogFile -Message "[DEBUG] Retrieved batch data, records count: $($responseJson.value.Count)" -Level Standard

            if ($responseJson.value -and $responseJson.value.Count -gt 0) {
                $batchCount = $responseJson.value.Count
                $state.totalEventsProcessed += $batchCount

                if ($isDebugEnabled) {
                    Write-LogFile -Message "[DEBUG] Processing batch: $batchCount records (Total: $($state.totalEventsProcessed))" -Level Debug
                    Write-LogFile -Message "[DEBUG] Current file events: $($state.currentFileEvents)" -Level Debug
                }

                if ($state.outputFormat -eq "JSON") {
                    foreach ($record in $responseJson.value) {
                        if ($state.splitFiles -and $state.currentFileEvents -ge $state.maxEventsPerFile) {
                            "]" | Out-File -FilePath $state.filePath -Append -Encoding $state.encoding
                            Write-LogFile -Message "[INFO] File complete: $($state.outputFilePath) ($($state.currentFileEvents) events)" -Level Standard

                            $state.fileCounter++
                            $summary.ExportedFiles++
                            $state.currentFileEvents = 0

                            $state.outputFilePath = "$($state.outputFileBase)-part$($state.fileCounter).json"
                            $state.filePath = Join-Path -Path $state.outputDirPath -ChildPath $state.outputFilePath
                            "[" | Out-File -FilePath $state.filePath -Encoding $state.encoding
                            $state.firstRecordInFile = $true
                        }

                        if (-not $state.firstRecordInFile) {
                            "," | Out-File -FilePath $state.filePath -Append -Encoding $state.encoding -NoNewline
                        }
                        else {
                            $state.firstRecordInFile = $false
                        }
                        "`r`n" | Out-File -FilePath $state.filePath -Append -Encoding $state.encoding -NoNewline

                        $record | ConvertTo-Json -Depth 100 | Out-File -FilePath $state.filePath -Append -Encoding $state.encoding -NoNewline

                        $state.currentFileEvents++
                        $summary.ProcessedRecords++
                    }
                }
                elseif ($state.outputFormat -eq "CSV") {
                    if (-not $state.splitFiles -or ($state.currentFileEvents + $batchCount) -le [int]$state.maxEventsPerFile) {
                        $responseJson.value | Format-AuditRecordForCsv | Export-Csv -Path $state.filePath -Append -Encoding $state.encoding -NoTypeInformation
                        $state.currentFileEvents += $batchCount
                        $summary.ProcessedRecords += $batchCount
                    }
                    else {
                        $records = $responseJson.value
                        $recordIndex = 0
                        while ($recordIndex -lt $records.Count) {
                            $remaining = [int]$state.maxEventsPerFile - $state.currentFileEvents
                            $toWrite = [Math]::Min($remaining, $records.Count - $recordIndex)

                            if ($toWrite -gt 0) {
                                $records[$recordIndex..($recordIndex + $toWrite - 1)] | Format-AuditRecordForCsv | Export-Csv -Path $state.filePath -Append -Encoding $state.encoding -NoTypeInformation
                                $state.currentFileEvents += $toWrite
                                $summary.ProcessedRecords += $toWrite
                                $recordIndex += $toWrite
                            }

                            if ($state.currentFileEvents -ge [int]$state.maxEventsPerFile -and $recordIndex -lt $records.Count) {
                                Write-LogFile -Message "[INFO] File complete: $($state.outputFilePath) ($($state.currentFileEvents) events)" -Level Standard
                                $state.fileCounter++
                                $summary.ExportedFiles++
                                $state.currentFileEvents = 0
                                $state.outputFilePath = "$($state.outputFileBase)-part$($state.fileCounter).csv"
                                $state.filePath = Join-Path -Path $state.outputDirPath -ChildPath $state.outputFilePath
                            }
                        }
                    }
                }
                elseif ($state.outputFormat -eq "JSONL") {
                    foreach ($record in $responseJson.value) {
                        if ($state.splitFiles -and $state.currentFileEvents -ge $state.maxEventsPerFile) {
                            Write-LogFile -Message "[INFO] File complete: $($state.outputFilePath) ($($state.currentFileEvents) events)" -Level Standard

                            $state.fileCounter++
                            $summary.ExportedFiles++
                            $state.currentFileEvents = 0

                            $state.outputFilePath = "$($state.outputFileBase)-part$($state.fileCounter).jsonl"
                            $state.filePath = Join-Path -Path $state.outputDirPath -ChildPath $state.outputFilePath
                        }
                        if ($record.auditData) {
                            $record.auditData | ConvertTo-Json -Compress -Depth 100 |
                            Out-File -Append $state.filePath -Encoding UTF8
                        }
                        "`r`n" | Out-File -FilePath $state.filePath -Append -Encoding UTF8
                        $state.currentFileEvents++
                        $summary.ProcessedRecords++
                    }
                }
                elseif ($state.outputFormat -eq "SOF-ELK") {
                    foreach ($record in $responseJson.value) {
                        if ($state.splitFiles -and $state.currentFileEvents -ge $state.maxEventsPerFile) {
                            Write-LogFile -Message "[INFO] File complete: $($state.outputFilePath) ($($state.currentFileEvents) events)" -Level Standard

                            $state.fileCounter++
                            $summary.ExportedFiles++
                            $state.currentFileEvents = 0

                            $state.outputFilePath = "$($state.outputFileBase)-part$($state.fileCounter).json"
                            $state.filePath = Join-Path -Path $state.outputDirPath -ChildPath $state.outputFilePath
                        }
                        if ($record.auditData) {
                            $record.auditData | ConvertTo-Json -Compress -Depth 100 |
                            Out-File -Append $state.filePath -Encoding UTF8
                        }
                        $state.currentFileEvents++
                        $summary.ProcessedRecords++
                    }
                }

                if ($state.totalEventsProcessed % 10000 -eq 0 -or $batchCount -lt 100) {
                    Write-LogFile -Message "[INFO] Progress: $($state.totalEventsProcessed) total events processed" -Level Standard
                    if ($isDebugEnabled) {
                        Write-LogFile -Message "[DEBUG] Progress details:" -Level Debug
                        Write-LogFile -Message "[DEBUG]   Batch size: $batchCount" -Level Debug
                        Write-LogFile -Message "[DEBUG]   Current file: $($state.outputFilePath)" -Level Debug
                        Write-LogFile -Message "[DEBUG]   Current file events: $currentFileEvents" -Level Debug
                    }
                }
            }
            else {
                if ($state.totalEventsProcessed -eq 0) {
                    Write-LogFile -Message "[INFO] No results matched your search." -Color Yellow -Level Minimal
                }
            }
            $apiUrl = $responseJson.'@odata.nextLink'

            $state.nextLink = $apiUrl

            Save-StateFile -State $state -StateFilePath $StateFile
        } While ($apiUrl)

        if ($state.currentFileEvents -gt 0) {
            if ($Output -eq "JSON") {
                "]" | Out-File -FilePath $state.filePath -Append -Encoding $Encoding
            }
            $summary.ExportedFiles++
        }

        $summary.TotalRecords = $state.totalEventsProcessed
        $summary.ProcessingTime = (Get-Date) - $summary.StartTime

        $summaryOutput = [ordered]@{
            "Search Information"    = [ordered]@{
                "Search Name" = $SearchName
                "Search ID"   = $summary.SearchId
                "Time Period" = $dateRange
            }
            "Collection Statistics" = [ordered]@{
                "Total Records Retrieved" = $summary.TotalRecords
                "Files Created"           = $summary.ExportedFiles
            }
            "Export Details"        = [ordered]@{
                "Output Directory" = $outputDirPath
                "Processing Time"  = if ($summary.ProcessingTime.Days -gt 0) {
                    "$($summary.ProcessingTime.Days) days, $($summary.ProcessingTime.Hours):$($summary.ProcessingTime.Minutes.ToString('00')):$($summary.ProcessingTime.Seconds.ToString('00'))"
                }
                else {
                    $summary.ProcessingTime.ToString('hh\:mm\:ss')
                }
            }
        }

        if ($summary.TotalRecords -eq 0) {
            Write-LogFile -Message "[INFO] No results matched your search criteria." -Color "Yellow" -Level Standard
        }

        Write-Summary -Summary $summaryOutput -Title "Audit Log Retrieval Summary" -SkipExportDetails

        if (Test-Path $StateFile) {
            Remove-Item -Path $StateFile -Force
            Write-LogFile -Message "[INFO] State file removed after successful completion" -Level Standard
        }
    }
    catch {
        Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        throw
    }
}