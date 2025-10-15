Function Get-Email {
<#
    .SYNOPSIS
    Get a specific email.

    .DESCRIPTION
    Get a specific email based on userId and Internet Message Id and saves the output to a eml or txt file.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\EmailExport

    .PARAMETER UserIds
    The unique identifier of the user.

    .PARAMETER internetMessageId
    The InternetMessageId parameter represents the Internet message identifier of an item.

    .PARAMETER output
    Output is the parameter specifying the eml or txt output type.
    Default: eml

    .PARAMETER inputFile
    The inputFile parameter specifies the .txt file containing multiple Internet Message Identifiers. You can include multiple Internet Message Identifiers in the file. Ensure each ID is placed on a new line.

    .PARAMETER attachment
    The attachment parameter specifies whether the attachment should be saved or not. 
    Default: False 

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Debug: Verbose logging for debugging purposes
    Default: Standard
    
    .EXAMPLE
    Get-Email -userIds fortunahodan@bonacu.onmicrosoft.com -internetMessageId "<d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com>" 
    Retrieves an email from fortunahodan@bonacu.onmicrosoft.com with the internet message identifier <d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com> to a eml file.
    
    .EXAMPLE
    Get-Email -userIds fortunahodan@bonacu.onmicrosoft.com -internetMessageId "<d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com>" -attachment
    Retrieves an email and the attachment from fortunahodan@bonacu.onmicrosoft.com with the internet message identifier <d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com> to a eml file.
        
    .EXAMPLE
    Get-Email -userIds fortunahodan@bonacu.onmicrosoft.com -internetMessageId "<d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com>" -OutputDir C:\Windows\Temp
    Retrieves an email and saves it to C:\Windows\Temp folder.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$userIds,
        [string]$internetMessageId,
        [ValidateSet("eml", "txt")]
        [string]$Output = "eml",
        [string]$OutputDir,
        [switch]$attachment,
        [string]$inputFile,
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    ) 

    Init-Logging
    Init-OutputDir -Component "Email Export" -FilePostfix "EmailExport" -CustomOutputDir $OutputDir
    $outputDir = Split-Path $script:outputFile -Parent

    $summary = @{
        TotalProcessed = 0
        SuccessfulDownloads = 0
        FailedDownloads = 0
        DuplicatesFound = 0
        AttachmentsProcessed = 0
        StartTime = Get-Date
        ProcessingTime = $null
        Errors = @()
    }

    Write-LogFile -Message "=== Starting Email Export ===" -Color "Cyan" -Level Standard
    $requiredScopes = @("Mail.Readwrite")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes
    
    $fileCounter = 1 
    $processedMessages = @{}
    $duplicateMessages = @()
    $notCollected = @()
    $ProgressPreference = 'SilentlyContinue' 

    if ($inputFile) {
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Processing input file: $inputFile" -Level Debug
        }
        try {
            $internetMessageIds = Get-Content $inputFile
            Write-LogFile -Message "[INFO] Found $($internetMessageIds.Count) messages in the input file to process" -Level Standard -Color "Green"
        }
        catch {
            write-LogFile -Message "[ERROR] Failed to read the input file. Ensure it is a text file with the message IDs on new lines: $_" -Level Minimal -Color "Red"
            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Input file read error details:" -Level Debug
                Write-LogFile -Message "[DEBUG]   File path: $inputFile" -Level Debug
                Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Full error: $($_.Exception.ToString())" -Level Debug
            }
            return
        }
    
        foreach ($id in $internetMessageIds) {
            $summary.TotalProcessed++ 
            $id = $id.Trim()
            Write-LogFile -Message "[INFO] Processing Internet Message ID: $id" -Level Standard

            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Processing message details:" -Level Debug
                Write-LogFile -Message "[DEBUG]   Raw ID from file: '$($id)'" -Level Debug
                Write-LogFile -Message "[DEBUG]   Trimmed ID: '$($id)'" -Level Debug
                Write-LogFile -Message "[DEBUG]   Progress: $($summary.TotalProcessed) of $($internetMessageIds.Count)" -Level Debug
            }
           
            try {
                $getMessage = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$userIds/messages?filter=internetMessageId eq '$id'"
                $message = $getMessage.value[0]

                if ($null -eq $message) {
                    Write-LogFile -Message "[WARNING] No message found for Internet Message ID: $($id). This might happen when the email is removed from the mailbox." -Level Minimal -Color "Yellow"
                    $notCollected += $id
                    $summary.FailedDownloads++

                    if ($isDebugEnabled) {
                        Write-LogFile -Message "[DEBUG] Message not found details:" -Level Debug
                        Write-LogFile -Message "[DEBUG]   Searched ID: $id" -Level Debug
                        Write-LogFile -Message "[DEBUG]   API response value count: $($getMessage.value.Count)" -Level Debug
                    }
                    continue
                }

                $messageId = $message.Id
                if ($isDebugEnabled) {
                    Write-LogFile -Message "[DEBUG] Message found successfully:" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Message ID: $messageId" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Subject: $($message.Subject)" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Received: $($message.receivedDateTime)" -Level Debug
                    Write-LogFile -Message "[DEBUG]   From: $($message.from.emailAddress.address)" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Has attachments: $($message.hasAttachments)" -Level Debug
                }

                if ($processedMessages.ContainsKey($messageId)) {
                    $duplicateMessages += @{
                        'MessageId' = $messageId
                        'FirstInternetMessageId' = $processedMessages[$messageId]
                        'SecondInternetMessageId' = $id
                    }
                    $summary.DuplicatesFound++
                    Write-LogFile -Message "[INFO] Duplicate message detected! Message ID $messageId was previously processed with Internet Message ID $($processedMessages[$messageId])" -Color "Yellow" -Level Standard

                    if ($isDebugEnabled) {
                        Write-LogFile -Message "[DEBUG] Duplicate detection details:" -Level Debug
                        Write-LogFile -Message "[DEBUG]   Duplicate message ID: $messageId" -Level Debug
                        Write-LogFile -Message "[DEBUG]   First seen with: $($processedMessages[$messageId])" -Level Debug
                        Write-LogFile -Message "[DEBUG]   Current ID: $id" -Level Debug
                        Write-LogFile -Message "[DEBUG]   Total duplicates found so far: $($summary.DuplicatesFound)" -Level Debug
                    }
                    continue
                }

                $processedMessages[$messageId] = $id
                $subject = $message.Subject -replace '[\\/:*?"<>|]', '_'
                $extension = if ($output -eq "txt") { "txt" } else { "eml" }

                if ($isDebugEnabled) {
                    Write-LogFile -Message "[DEBUG] File preparation:" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Original subject: $($message.Subject)" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Sanitized subject: $subject" -Level Debug
                    Write-LogFile -Message "[DEBUG]   File extension: $extension" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Current file counter: $fileCounter" -Level Debug
                }

                try {
                    $ReceivedDateTime = [datetime]::Parse($message.receivedDateTime).ToString("yyyyMMdd_HHmmss")
                    do {
                        $filePath = "$outputDir\$($fileCounter.ToString('D3'))-$ReceivedDateTime-$subject.$extension"
                        $fileCounter++
                    } while (Test-Path $filePath)
                } catch {
                    Write-LogFile -Message "[WARNING] Could not parse received date time, excluding from filename" -Level Standard -Color "Yellow"
                    do {
                        $filePath = "$outputDir\$($fileCounter.ToString('D3'))-$subject.$extension"
                        $fileCounter++
                    } while (Test-Path $filePath)
                    if ($isDebugEnabled) {
                        Write-LogFile -Message "[DEBUG] Date parsing failed, using file path without date: $filePath" -Level Debug
                        Write-LogFile -Message "[DEBUG] Date parsing error: $($_.Exception.Message)" -Level Debug
                    }
                }

                $contentUri = "https://graph.microsoft.com/v1.0/users/$userIds/messages/" + $messageId + "/`$value"
                Invoke-MgGraphRequest -Method GET $contentUri -OutputFilePath $filePath
                $summary.SuccessfulDownloads++
                $fileCounter++

                Write-LogFile -Message "[SUCCESS] Saved message to: $filePath" -Color "Green" -Level Standard
                if ($attachment.IsPresent){
                    $attachmentProcessed = Get-Attachment -Userid $Userids -internetMessageId $id
                    if ($attachmentProcessed) {
                        $summary.AttachmentsProcessed++
                    }
                }
           }
           catch {
                $summary.FailedDownloads++
                $summary.Errors += "Failed to process $id : $_"
                Write-LogFile -Message "[WARNING] Failed to collect message with ID '$id': $_"
                Write-LogFile -Message "[ERROR] Failed to process message: $_" -Color "Red" -Level Minimal
                $notCollected += $id

                if ($isDebugEnabled) {
                    Write-LogFile -Message "[DEBUG] Message processing error details:" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Failed message ID: $id" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Full error: $($_.Exception.ToString())" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Total failures so far: $($summary.FailedDownloads)" -Level Debug
                }
           }
        }
    }
    else {
        if (-not $internetMessageId) {
            write-LogFile -Message "[ERROR] Either internetMessageId or inputFile must be provided." -Level Minimal -Color "Red"
            return
        }
    
        try {
            $summary.TotalProcessed++ 
            $getMessage = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$userIds/messages?filter=internetMessageId eq '$internetMessageId'"
            $message = $getMessage.value[0]

            if ($null -eq $message) {
                Write-LogFile -Message "[WARNING] No message found for Internet Message ID: $($internetMessageId). This might happen when the email is removed from the mailbox." -Level Minimal -Color "Yellow"
                $summary.FailedDownloads++
                if ($isDebugEnabled) {
                    Write-LogFile -Message "[DEBUG] Single message not found:" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Searched ID: $internetMessageId" -Level Debug
                    Write-LogFile -Message "[DEBUG]   API response value count: $($getMessage.value.Count)" -Level Debug
                }
                return
            }

            $ReceivedDateTime = [datetime]::Parse($message.receivedDateTime).ToString("yyyyMMdd_HHmmss")
            $messageId = $message.id
            $subject = $message.Subject -replace '[\\/:*?"<>|]', '_'

            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Single message details:" -Level Debug
                Write-LogFile -Message "[DEBUG]   Message ID: $messageId" -Level Debug
                Write-LogFile -Message "[DEBUG]   Subject: $($message.Subject)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Sanitized subject: $subject" -Level Debug
                Write-LogFile -Message "[DEBUG]   Received: $($message.receivedDateTime)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Formatted date: $ReceivedDateTime" -Level Debug
                Write-LogFile -Message "[DEBUG]   From: $($message.from.emailAddress.address)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Has attachments: $($message.hasAttachments)" -Level Debug
            }

            $extension = if ($output -eq "txt") { "txt" } else { "eml" }
            do {
                $filePath = "$outputDir\$($fileCounter.ToString('D3'))-$ReceivedDateTime-$subject.$extension"
                $fileCounter++
            } while (Test-Path $filePath)

            $contentUri = "https://graph.microsoft.com/v1.0/users/$userIds/messages/" + $messageId + "/`$value"
            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Single message download:" -Level Debug
                Write-LogFile -Message "[DEBUG]   Content URI: $contentUri" -Level Debug
                Write-LogFile -Message "[DEBUG]   Output file path: $filePath" -Level Debug
                Write-LogFile -Message "[DEBUG]   File extension: $extension" -Level Debug
            }

            Invoke-MgGraphRequest -Method GET $contentUri -OutputFilePath $filePath
            $summary.SuccessfulDownloads++
            Write-LogFile -Message "[INFO] Output written to $filePath" -Color "Green" -Level Standard

            if ($isDebugEnabled) {
                $fileInfo = Get-Item $filePath -ErrorAction SilentlyContinue
                Write-LogFile -Message "[DEBUG] Single message download completed:" -Level Debug
                Write-LogFile -Message "[DEBUG]   Download time: $([math]::round($downloadPerformance.TotalSeconds, 2)) seconds" -Level Debug
                if ($fileInfo) {
                    Write-LogFile -Message "[DEBUG]   File size: $($fileInfo.Length) bytes" -Level Debug
                    Write-LogFile -Message "[DEBUG]   File created: $($fileInfo.CreationTime)" -Level Debug
                }
            }

            if ($attachment.IsPresent){
                $attachmentProcessed = Get-Attachment -Userid $Userids -internetMessageId $internetMessageId
                if ($attachmentProcessed) {
                    $summary.AttachmentsProcessed++
                }
            }
        }
        catch {
            $summary.FailedDownloads++
            $summary.Errors += "Failed to process $internetMessageId : $_"
            Write-LogFile -Message "[WARNING] The 'Mail.Readwrite' is an application-level permission, requiring an application-based connection through the 'Connect-MgGraph' command for its use." -Color "Yellow" -Level Minimal
            Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Level Minimal -Color "Red"

            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Single message processing error details:" -Level Debug
                Write-LogFile -Message "[DEBUG]   Failed message ID: $internetMessageId" -Level Debug
                Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Full error: $($_.Exception.ToString())" -Level Debug
                Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
            }
            return
        }  
    }

    $summary.ProcessingTime = (Get-Date) - $summary.StartTime
    $summaryData = [ordered]@{
        "Processing Statistics" = [ordered]@{
            "Total Messages Processed" = $summary.TotalProcessed
            "Successfully Downloaded" = $summary.SuccessfulDownloads
            "Failed Downloads" = $summary.FailedDownloads
            "Duplicates Found" = $summary.DuplicatesFound
        }
    }

    if ($attachment.IsPresent) {
        $summaryData["Processing Statistics"]["Attachments Processed"] = $summary.AttachmentsProcessed
    }

    if ($duplicateMessages.Count -gt 0) {
        Write-LogFile -Message "`nDuplicate Messages:" -Color "Yellow" -Level Standard
        foreach ($dup in $duplicateMessages) {
            Write-LogFile -Message "  Message ID: $($dup.MessageId)" -Level Standard
            Write-LogFile -Message "    First seen with: $($dup.FirstInternetMessageId)" -Level Standard
            Write-LogFile -Message "    Also found with: $($dup.SecondInternetMessageId)" -Level Standard
        }
    }

    if ($notCollected.Count -gt 0) {
        Write-LogFile -Message "`nFailed to Collect:" -Color "Yellow" -Level Standard
        foreach ($id in $notCollected) {
            Write-LogFile -Message "  - $id" -Level Standard
        }
    }

    Write-Summary -Summary $summaryData -Title "Email Export Summary"
    Write-LogFile -Message "`nNote: Emails saved to: $outputDir" -Level Standard
}
    
    
Function Get-Attachment {
<#
    .SYNOPSIS
    Get a specific attachment.

    .DESCRIPTION
    Get a specific attachment based on userId and Internet Message Id and saves the output.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\Emails

    .PARAMETER UserIds
    The unique identifier of the user.

    .PARAMETER internetMessageId
    The InternetMessageId parameter represents the Internet message identifier of an item.

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Default: Standard

    .EXAMPLE
    Get-Attachment -userIds fortunahodan@bonacu.onmicrosoft.com -internetMessageId "<d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com>" 
    Retrieves the attachment from fortunahodan@bonacu.onmicrosoft.com with the internet message identifier <d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com>.
    
    .EXAMPLE
    Get-Attachment -userIds fortunahodan@bonacu.onmicrosoft.com -internetMessageId "<d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com>" -OutputDir C:\Windows\Temp
    Retrieves an attachment and saves it to C:\Windows\Temp folder.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$userIds,
        [Parameter(Mandatory=$true)]$internetMessageId,
        [string]$OutputDir,
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

   Init-Logging
   Init-OutputDir -Component "Email Export" -SubComponent "Attachments" -FilePostfix "Attachments" -CustomOutputDir $OutputDir
   $outputDir = Split-Path $script:outputFile -Parent

    try {
        $getMessage = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$userIds/messages?filter=internetMessageId eq '$internetMessageId'" -ErrorAction stop
    }
    catch {
        write-logFile -Message "[INFO] Ensure you are connected to Microsoft Graph by running the Connect-MgGraph -Scopes Mail.Readwrite command before executing this script" -Color "Yellow" -Level Minimal
        Write-logFile -Message "[WARNING] The 'Mail.Readwrite' is an application-level permission, requiring an application-based connection through the 'Connect-MgGraph' command for its use." -Color "Red" -Level Minimal
        Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        throw
    }

    $messageId = $getMessage.value.Id
    $hasAttachment = $getMessage.value.HasAttachments
    $ReceivedDateTime = $getMessage.value.ReceivedDateTime.ToString("yyyyMMdd_HHmmss")
    $subject = $getMessage.value.Subject

    if ($hasAttachment -eq "True"){
        Write-LogFile -Message "[INFO] Processing attachments for message: $internetMessageId" -Color "Green" -Level Standard
        $response = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$userIds/messages/$messageId/attachments"
        Write-LogFile -Message "[INFO] Found $($response.value.Count) attachment(s) for email: $internetMessageId" -Level Standard

        foreach ($attachment in $response.value){
            $filename = $attachment.Name
        
            Write-logFile -Message "[INFO] Name: $filename" -Level Standard
            Write-logFile -Message "[INFO] Size: $($attachment.Size)" -Level Standard

            $uri = "https://graph.microsoft.com/v1.0/users/$userIds/messages/$messageId/attachments/$($attachment.Id)/\$value" 
            $response = Invoke-MgGraphRequest -Method Get -Uri $uri 

            $filename = $filename -replace '[\\/:*?"<>|]', '_'
            $filePath = Join-Path $outputDir "$ReceivedDateTime-$subject-$filename"

            $base64B = ($attachment.contentBytes)
            $decoded = [System.Convert]::FromBase64String($base64B)

            # Check PowerShell version and use appropriate parameter
            if ($PSVersionTable.PSVersion.Major -ge 6) {
                Set-Content -Path $filePath -Value $decoded -AsByteStream
            } else {
                Set-Content -Path $filePath -Value $decoded -Encoding Byte
            }

            Write-logFile -Message "[INFO] Output written to '$subject-$filename'" -Color "Green" -Level Standard
            return $true
        }
    }

    else {
        return $false
    }
}
    
    
Function Show-Email {
<#
    .SYNOPSIS
    Show a specific email in the PowerShell Window.

    .DESCRIPTION
    Show a specific email in the PowerShell Window based on userId and Internet Message Id.
    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Default: Standard

    .EXAMPLE
    Show-Email -userIds {userId} -internetMessageId {InternetMessageId}
    Show a specific email in the PowerShell Window.
    
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$userIds,
        [Parameter(Mandatory=$true)]$internetMessageId,
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    Init-Logging

    $requiredScopes = @("Mail.Readwrite")
    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes

    Write-logFile -Message "[INFO] Running Show-Email" -Color "Green" -Level Standard

    try {

        $message = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$userIds/messages?filter=internetMessageId eq '$internetMessageId'" -ErrorAction stop
    }
    catch {
        Write-logFile -Message "[WARNING] The 'Mail.Readwrite' is an application-level permission, requiring an application-based connection through the 'Connect-MgGraph' command for its use." -Color "Red" -Level Minimal
        Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
        throw
    }

    $message.Value
}
            