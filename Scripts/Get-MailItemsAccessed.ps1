Function Get-Sessions {
<#
    .SYNOPSIS
    Find SessionID(s) in the Audit Log.

    .DESCRIPTION
    Find SessionID(s) in the Audit Log. You can filter based on IP address or Username. The first step is to identify what sessions belong to the threat actor. 
    With this information you can go to the next step and find the MessageID(s) belonging to those sessions. Output is saved in: Output\MailItemsAccessed\
    
    .PARAMETER UserIds
    The unique identifier of the user.

    .PARAMETER StartDate
    startDate is the parameter specifying the start date of the date range.

    .PARAMETER EndDate
    endDate is the parameter specifying the end date of the date range.
    
    .PARAMETER IP
    The IP address parameter is used to filter the logs by specifying the desired IP address.

    .PARAMETER OutputDir
    outputDir is the parameter specifying the output directory.
    Default: Output\MailItemsAccessed

    .PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Debug: Verbose logging for debugging purposes
    Default: Standard

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
    Default: UTF8

    .PARAMETER Output
    "Yes" or "No" to specify whether the output should be saved to a file.
    Default: Yes

    .EXAMPLE
    Get-Sessions -StartDate 1/4/2024 -EndDate 5/4/2024
    Collects all sessions for all users between 1/4/2024 and 5/4/2024.
    
    .EXAMPLE
    Get-Sessions -StartDate 1/4/2024 -EndDate 5/4/2024 -UserIds HR@invictus-ir.com
    Collects all sessions for the user HR@invictus-ir.com.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$StartDate,
        [Parameter(Mandatory=$true)]$EndDate,
        [string]$OutputDir = "Output\MailItemsAccessed",
        [string]$UserIds,
        [string]$IP,
        [string]$Encoding = "UTF8",
        [ValidateSet("Yes", "No")]
        [string]$Output = "Yes",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebugEnabled = $script:LogLevel -eq [LogLevel]::Debug

    $summary = @{
        TotalEvents = 0
        UniqueSessions = @{}
        OperationCount = 0
        StartTime = Get-Date
        ProcessingTime = $null
        QueryType = "All Events"
    }

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] PowerShell Version: $($PSVersionTable.PSVersion)" -Level Debug
        Write-LogFile -Message "[DEBUG] Input parameters:" -Level Debug
        Write-LogFile -Message "[DEBUG]   StartDate: $StartDate" -Level Debug
        Write-LogFile -Message "[DEBUG]   EndDate: $EndDate" -Level Debug
        Write-LogFile -Message "[DEBUG]   OutputDir: $OutputDir" -Level Debug
        Write-LogFile -Message "[DEBUG]   UserIds: $UserIds" -Level Debug
        Write-LogFile -Message "[DEBUG]   IP: $IP" -Level Debug
        Write-LogFile -Message "[DEBUG]   Encoding: $Encoding" -Level Debug
        Write-LogFile -Message "[DEBUG]   Output: $Output" -Level Debug
        Write-LogFile -Message "[DEBUG]   LogLevel: $LogLevel" -Level Debug
        
        $exchangeModule = Get-Module -Name ExchangeOnlineManagement -ErrorAction SilentlyContinue
        if ($exchangeModule) {
            Write-LogFile -Message "[DEBUG] ExchangeOnlineManagement Module Version: $($exchangeModule.Version)" -Level Debug
        } else {
            Write-LogFile -Message "[DEBUG] ExchangeOnlineManagement Module not loaded" -Level Debug
        }

        try {
            $connectionInfo = Get-ConnectionInformation -ErrorAction SilentlyContinue
            if ($connectionInfo) {
                Write-LogFile -Message "[DEBUG] Connection Status: $($connectionInfo.State)" -Level Debug
                Write-LogFile -Message "[DEBUG] Connection Type: $($connectionInfo.TokenStatus)" -Level Debug
                Write-LogFile -Message "[DEBUG] Connected Account: $($connectionInfo.UserPrincipalName)" -Level Debug
            } else {
                Write-LogFile -Message "[DEBUG] No active Exchange Online connection found" -Level Debug
            }
        } catch {
            Write-LogFile -Message "[DEBUG] Unable to retrieve connection information" -Level Debug
        }
    }

    if (!(test-path $OutputDir)) {
        New-Item -ItemType Directory -Force -Name $OutputDir > $null
        write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
    } else {
        if (!(Test-Path -Path $OutputDir)) {
            Write-Error "[Error] Custom directory invalid: $OutputDir exiting script" -ErrorAction Stop
            Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir" -Level Minimal
        }
    }

    if ($UserIds -and $IP) {
        $summary.QueryType = "User and IP Filter"
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Query type: User and IP Filter" -Level Debug
            Write-LogFile -Message "[DEBUG]   User: $UserIds" -Level Debug
            Write-LogFile -Message "[DEBUG]   IP: $IP" -Level Debug
        }
    } elseif ($UserIds) {
        $summary.QueryType = "User Filter"
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Query type: User Filter" -Level Debug
            Write-LogFile -Message "[DEBUG]   User: $UserIds" -Level Debug
        }
    } elseif ($IP) {
        $summary.QueryType = "IP Filter"
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Query type: IP Filter" -Level Debug
            Write-LogFile -Message "[DEBUG]   IP: $IP" -Level Debug
        }
    } else {
        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] Query type: All Events (no filter)" -Level Debug
        }
    }

    Write-LogFile -Message "=== Starting Session Collection ===" -Color "Cyan" -Level Standard
    
    if ($UserIds -And !$IP){
        try {
            $amountResults = (Search-UnifiedAuditLog -StartDate $StartDate -UserIds $UserIds -EndDate $EndDate -Operations "MailItemsAccessed" -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount)
        }
        catch {
            write-logFile -Message "[INFO] Ensure you are connected to M365 by running the Connect-M365 command before executing this script" -Color "Yellow" -Level Minimal
            Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Connection error details:" -Level Debug
                Write-LogFile -Message "[DEBUG]   Exception type: $($_.Exception.GetType().Name)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Full error: $($_.Exception.ToString())" -Level Debug
                Write-LogFile -Message "[DEBUG]   Stack trace: $($_.ScriptStackTrace)" -Level Debug
            }
            throw
        }

        if($amountResults -gt 4999){
            write-logFile -Message "[WARNING] A total of $amountResults events have been identified, surpassing the maximum limit of 5000 results for a single session. To refine your search, kindly provide more specific details, such as specifying a user or IP address." -Color "Red" -Level Minimal
        }

        else {   
            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Retrieving audit logs for user: $UserIds" -Level Debug
            }
            $mailItemRecords = (Search-UnifiedAuditLog -UserIds $UserIds -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -Operations "MailItemsAccessed")
            $Results = @()
            
            foreach($rec in $mailItemRecords) {
                $AuditData = ConvertFrom-Json $Rec.Auditdata

                if ($isDebugEnabled) {
                    Write-LogFile -Message "[DEBUG] Processing audit record:" -Level Debug
                    Write-LogFile -Message "[DEBUG]   CreationTime: $($AuditData.CreationTime)" -Level Debug
                    Write-LogFile -Message "[DEBUG]   UserId: $($AuditData.UserId)" -Level Debug
                    Write-LogFile -Message "[DEBUG]   Operation: $($AuditData.Operation)" -Level Debug
                    Write-LogFile -Message "[DEBUG]   SessionId: $($AuditData.SessionId)" -Level Debug
                    Write-LogFile -Message "[DEBUG]   ClientIPAddress: $($AuditData.ClientIPAddress)" -Level Debug
                    Write-LogFile -Message "[DEBUG]   OperationCount: $($AuditData.OperationCount)" -Level Debug
                }

                $Line = [PSCustomObject]@{
                    TimeStamp   = $AuditData.CreationTime
                    User        = $AuditData.UserId
                    Action      = $AuditData.Operation
                    SessionId   = $AuditData.SessionId
                    ClientIP    = $AuditData.ClientIPAddress
                    OperationCount = $AuditData.OperationCount
                }

                $summary.TotalEvents++
                if ($AuditData.SessionId) {
                    $summary.UniqueSessions[$AuditData.SessionId] = $true

                    if ($isDebugEnabled) {
                        Write-LogFile -Message "[DEBUG]   Added SessionId to unique sessions: $($AuditData.SessionId)" -Level Debug
                    }
                }
                
                if ($AuditData.OperationCount) {
                    $summary.OperationCount += $AuditData.OperationCount

                    if ($isDebugEnabled) {
                        Write-LogFile -Message "[DEBUG]   Added OperationCount: $($AuditData.OperationCount)" -Level Debug
                    }
                }                
                $Results += $Line
            }
            
            $Results | Sort SessionId, TimeStamp | Format-Table Timestamp, User, Action, SessionId, ClientIP, OperationCount -AutoSize
         }

        if (($Output -eq "Yes") -and $results.Count -gt 0) {
            $filePath = "$OutputDir\Sessions-$UserIds.csv"
            $Results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
            Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green" -Level Standard
        }  
    }

    elseif($IP -And !$UserIds){
        $Results = @()
        try {
            $amountResults = (Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -FreeText $IP -Operations "MailItemsAccessed" -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount)
        }
        catch {
            write-logFile -Message "[INFO] Ensure you are connected to M365 by running the Connect-M365 command before executing this script" -Color "Yellow" -Level Minimal
            Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
            throw
        }
        if($amountResults -gt 4999){
            write-logFile -Message "[WARNING] A total of $amountResults events have been identified, surpassing the maximum limit of 5000 results for a single session. To refine your search, kindly provide more specific details, such as specifying a user." -Color "Red" -Level Minimal
        }
        else{              
            $MailItemRecords = (Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -FreeText $IP -ResultSize 5000 -Operations "MailItemsAccessed")
            ForEach($Rec in $MailItemRecords){
                $AuditData = ConvertFrom-Json $Rec.Auditdata
                $Line = [PSCustomObject]@{
                    TimeStamp   = $AuditData.CreationTime
                    User        = $AuditData.UserId
                    Action      = $AuditData.Operation
                    SessionId   = $AuditData.SessionId
                    ClientIP    = $AuditData.ClientIPAddress
                    OperationCount = $AuditData.OperationCount
                }
                    
                f($AuditData.ClientIPAddress -eq $IP){
                    $summary.TotalEvents++
                    
                    if ($AuditData.SessionId) {
                        $summary.UniqueSessions[$AuditData.SessionId] = $true
                    }
                    
                    if ($AuditData.OperationCount) {
                        $summary.OperationCount += $AuditData.OperationCount
                    }
                    $Results += $Line
                }
             }

            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Processing complete" -Level Debug
                Write-LogFile -Message "[DEBUG]   Total events processed: $($summary.TotalEvents)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Unique sessions found: $($summary.UniqueSessions.Count)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Total operation count: $($summary.OperationCount)" -Level Debug
            }
                
            $Results | Sort SessionId, TimeStamp | Format-Table Timestamp, User, Action, SessionId, ClientIP, OperationCount -AutoSize
        }
        
        if (($Output -eq "Yes") -and $results.Count -gt 0) {
            $filePath = "$OutputDir\Sessions-$IP.csv"
            $Results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
            Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green" -Level Standard
        }  
    }
        
    elseif($IP -And $UserIds){
        $Results = @()
        try {
            $amountResults = (Search-UnifiedAuditLog -UserIds $UserIds -FreeText $IP -StartDate $StartDate -EndDate $EndDate -Operations "MailItemsAccessed" -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount)
        }
        catch {
            write-logFile -Message "[INFO] Ensure you are connected to M365 by running the Connect-M365 command before executing this script" -Color "Yellow" -Level Minimal
            Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
            break
        }
        
        if($amountResults -gt 4999){
            write-logFile -Message "[WARNING] A total of $amountResults events have been identified, surpassing the maximum limit of 5000 results for a single session. To refine your search, kindly provide a more specific time window." -Color "Red" -Level Minimal
        }
        else{
            $MailItemRecords = (Search-UnifiedAuditLog -UserIds $UserIds -FreeText $IP -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -Operations "MailItemsAccessed")
    
            foreach($Rec in $MailItemRecords){
                $AuditData = ConvertFrom-Json $Rec.Auditdata
                $Line = [PSCustomObject]@{
                    TimeStamp   = $AuditData.CreationTime
                    User        = $AuditData.UserId
                    Action      = $AuditData.Operation
                    SessionId   = $AuditData.SessionId
                    ClientIP    = $AuditData.ClientIPAddress
                    OperationCount = $AuditData.OperationCount
                }
                    
                if($AuditData.ClientIPAddress -eq $IP){
                    $summary.TotalEvents++
                    
                    if ($AuditData.SessionId) {
                        $summary.UniqueSessions[$AuditData.SessionId] = $true
                    }
                    
                    if ($AuditData.OperationCount) {
                        $summary.OperationCount += $AuditData.OperationCount
                    }
                    $Results += $Line
                }
            }

            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Processing complete" -Level Debug
                Write-LogFile -Message "[DEBUG]   Total events processed: $($summary.TotalEvents)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Unique sessions found: $($summary.UniqueSessions.Count)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Total operation count: $($summary.OperationCount)" -Level Debug
            }
                
            $Results | Sort SessionId, TimeStamp | Format-Table Timestamp, User, Action, SessionId, ClientIP, OperationCount -AutoSize
        }
        if (($Output -eq "Yes") -and $results.Count -gt 0) {
            $filePath = "$OutputDir\Sessions-$UserIds-$IP.csv"
            $Results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
            Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green" -Level Standard
        }   
    }

    else{
        $Results = @()
        try {
            $amountResults = (Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations "MailItemsAccessed" -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount)
        }
        catch {
            write-logFile -Message "[INFO] Ensure you are connected to M365 by running the Connect-M365 command before executing this script" -Color "Yellow" -Level Minimal
            Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
            throw
        }
        if($amountResults -gt 4999){
            write-logFile -Message "[WARNING] A total of $amountResults events have been identified, surpassing the maximum limit of 5000 results for a single session. To refine your search, kindly provide more specific details, such as specifying a user." -Color "Red" -Level Minimal
        }
        else {   
            $MailItemRecords = (Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -Operations "MailItemsAccessed")
            
            foreach($Rec in $MailItemRecords) {
                $AuditData = ConvertFrom-Json $Rec.Auditdata
                $Line = [PSCustomObject]@{
                    TimeStamp   = $AuditData.CreationTime
                    User        = $AuditData.UserId
                    Action      = $AuditData.Operation
                    SessionId   = $AuditData.SessionId
                    ClientIP    = $AuditData.ClientIPAddress
                    OperationCount = $AuditData.OperationCount
                }
                    
                $summary.TotalEvents++
                if ($AuditData.SessionId) {
                    $summary.UniqueSessions[$AuditData.SessionId] = $true
                }
                
                if ($AuditData.OperationCount) {
                    $summary.OperationCount += $AuditData.OperationCount
                }
                   
                $Results += $Line
            }

            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Processing complete" -Level Debug
                Write-LogFile -Message "[DEBUG]   Total events processed: $($summary.TotalEvents)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Unique sessions found: $($summary.UniqueSessions.Count)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Total operation count: $($summary.OperationCount)" -Level Debug
            }

            $Results | Sort SessionId, TimeStamp | Format-Table Timestamp, User, Action, SessionId, ClientIP, OperationCount -AutoSize
        }
        if (($Output -eq "Yes") -and $results.Count -gt 0) {
            $filePath = "$OutputDir\Sessions.csv"
            $Results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
        }   
    }

    $summary.ProcessingTime = (Get-Date) - $summary.StartTime

    if ($Results.Count -gt 0) {
        Write-LogFile -Message "`n=== Session Analysis Summary ===" -Color "Cyan" -Level Standard
        Write-LogFile -Message "Query Information:" -Level Standard
        Write-LogFile -Message "  Filter: $($summary.QueryType)" -Level Standard
        Write-LogFile -Message "  Time Range: $StartDate to $EndDate" -Level Standard

        Write-LogFile -Message "`nEvent Statistics:" -Level Standard
        Write-LogFile -Message "  Total Events: $($summary.TotalEvents)" -Level Standard
        Write-LogFile -Message "  Unique Sessions: $($summary.UniqueSessions.Count)" -Level Standard
        Write-LogFile -Message "  Total Operations: $($summary.OperationCount)" -Level Standard

        Write-LogFile -Message "`nExported File:" -Level Standard
        Write-LogFile -Message "  - $filePath" -Level Standard
        Write-LogFile -Message "`nProcessing Time: $($summary.ProcessingTime.ToString('mm\:ss'))" -Color "Green" -Level Standard
        Write-LogFile -Message "===================================" -Color "Cyan" -Level Standard
    }
}

function Get-MessageIDs {
<#
    .SYNOPSIS
    Find the InternetMessageID(s).

    .DESCRIPTION
    Find the InternetMessageID(s). You can filter on SessionID(s) or IP addresses. After you identified the session(s) of the threat actor, you can use this information to find all MessageID(s).
    belonging to the sessions. With the MessageID(s) you can identify what emails were exposed to the threat actor. Output is saved in: Output\MailItemsAccessed\

    .PARAMETER StartDate
    startDate is the parameter specifying the start date of the date range.

    .PARAMETER EndDate
    endDate is the parameter specifying the end date of the date range.

    .PARAMETER OutputDir
    outputDir is the parameter specifying the output directory.
    Default: Output\MailItemsAccessed

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
    Default: UTF8
    
    .PARAMETER Sessions
    The sessions parameter is used to filter the logs by specifying the desired session id.

    .PARAMETER IP
    The IP address parameter is used to filter the logs by specifying the desired IP address.

    .PARAMETER Output
    "Yes" or "No" to specify whether the output should be saved to a file.
    Default: Yes

    .PARAMETER LogLevel
    Specifies the level of logging:
    None:  No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
    Debug: Verbose logging for debugging purposes
    Default: Standard

    .PARAMETER Download
    To specifiy whether the messages and their attachments should be saved.

    .EXAMPLE
    Get-MessageIDs -StartDate 1/4/2024 -EndDate 5/4/2024
    Collects all sessions for all users between 1/4/2024 and 5/4/2024.
    
    .EXAMPLE
    Get-MessageIDs -StartDate 1/4/2024 -EndDate 5/4/2024 -IP 1.1.1.1
    Collects all sessions for the IP address 1.1.1.1.

    .EXAMPLE
    Get-MessageIDs -StartDate 1/4/2024 -EndDate 5/4/2024 -IP 1.1.1.1 -Download
    Collects all sessions for the IP address 1.1.1.1 and downloads the e-mails and attachments.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]$StartDate,
        [Parameter(Mandatory=$true)]$EndDate,
        [string]$OutputDir = "Output\MailItemsAccessed",
        [string]$IP,
        [string]$Encoding = "UTF8",
        [string]$Sessions,
        [ValidateSet("Yes", "No")]
        [string]$Output = "Yes",
        [switch]$Download,
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
    )

    Set-LogLevel -Level ([LogLevel]::$LogLevel)
    $isDebugEnabled = $script:LogLevel -eq [LogLevel]::Debug

    $summary = @{
        TotalEvents = 0
        StartTime = Get-Date
        ProcessingTime = $null
        QueryType = "All Events"
    }

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] PowerShell Version: $($PSVersionTable.PSVersion)" -Level Debug
        Write-LogFile -Message "[DEBUG] Input parameters:" -Level Debug
        Write-LogFile -Message "[DEBUG]   StartDate: $StartDate" -Level Debug
        Write-LogFile -Message "[DEBUG]   EndDate: $EndDate" -Level Debug
        Write-LogFile -Message "[DEBUG]   OutputDir: $OutputDir" -Level Debug
        Write-LogFile -Message "[DEBUG]   IP: $IP" -Level Debug
        Write-LogFile -Message "[DEBUG]   Encoding: $Encoding" -Level Debug
        Write-LogFile -Message "[DEBUG]   Sessions: $Sessions" -Level Debug
        Write-LogFile -Message "[DEBUG]   Output: $Output" -Level Debug
        Write-LogFile -Message "[DEBUG]   Download: $($Download.IsPresent)" -Level Debug
        Write-LogFile -Message "[DEBUG]   LogLevel: $LogLevel" -Level Debug
        
        $exchangeModule = Get-Module -Name ExchangeOnlineManagement -ErrorAction SilentlyContinue
        if ($exchangeModule) {
            Write-LogFile -Message "[DEBUG] ExchangeOnlineManagement Module Version: $($exchangeModule.Version)" -Level Debug
        } else {
            Write-LogFile -Message "[DEBUG] ExchangeOnlineManagement Module not loaded" -Level Debug
        }

        if ($Download.IsPresent) {
            $graphModule = Get-Module -Name Microsoft.Graph* -ErrorAction SilentlyContinue
            if ($graphModule) {
                Write-LogFile -Message "[DEBUG] Microsoft Graph Modules loaded:" -Level Debug
                foreach ($module in $graphModule) {
                    Write-LogFile -Message "[DEBUG]   - $($module.Name) v$($module.Version)" -Level Debug
                }
            } else {
                Write-LogFile -Message "[DEBUG] No Microsoft Graph modules loaded" -Level Debug
            }
        }
    }

    if (!(test-path $OutputDir)) {
        New-Item -ItemType Directory -Force -Name $OutputDir > $null
    } else {
        if (!(Test-Path -Path $OutputDir)) {
            Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir" -Level Minimal
        }
    }
    
    Write-LogFile -Message "=== Starting Message IDs Collection ===" -Color "Cyan" -Level Standard

    if ($Download.IsPresent) {
        $requiredScopes = @("Mail.ReadWrite")
        $graphAuth = Get-GraphAuthType -RequiredScopes $requiredScopes
    }
    
    if (!$Sessions -And !$IP){
        try {
            $amountResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations "MailItemsAccessed" -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount
        }
        catch {
            write-logFile -Message "[INFO] Ensure you are connected to M365 by running the Connect-M365 command before executing this script" -Color "Yellow" -Level Minimal
            Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
            throw
        }

        if ($amountResults -gt 4999){
            write-logFile -Message "[WARNING] A total of $amountResults events have been identified, surpassing the maximum limit of 5000 results for a single session. To refine your search, kindly lower the time window." -Color "Red" -Level Minimal
            return
        }

        else {
            $results=@()
            $MailItemRecords = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -Operations "MailItemsAccessed"

            forEach ($Rec in $MailItemRecords){
                $summary.TotalEvents++
                $AuditData = ConvertFrom-Json $Rec.Auditdata
                $InternetMessageId = $AuditData.Folders.FolderItems
                $TimeStamp = $AuditData.CreationTime
                $SessionId = $AuditData.SessionId
                $ClientIP = $AuditData.ClientIPAddress
                $userId = $AuditData.UserId
                $sizeInBytes = $AuditData.SizeInBytes
                                
                if ($AuditData.OperationCount -gt 1){
                    $summary.OperationCount += $AuditData.OperationCount
                    foreach ($message in $InternetMessageId){
                        $iMessageID = $message.InternetMessageId
                        $sizeInBytes = $message.SizeInBytes

                        $resultObject = [PSCustomObject]@{
                            Timestamp           = $TimeStamp
                            User                = $userId
                            IPaddress           = $ClientIP
                            SessionID           = $SessionId
                            InternetMessageId   = $iMessageID
                            SizeInBytes         = $sizeInBytes
                        }
                        
                        $results += $resultObject
                        if ($Download.IsPresent){
                            if (![string]::IsNullOrWhiteSpace($iMessageID)) {
                                DownloadMails($iMessageID,$userId)
                            }
                        }
                    }
                }
                            
                else {
                    $SessionID = ""
                    $iMessageID = $AuditData.Folders.FolderItems.InternetMessageId
                    
                    $resultObject = [PSCustomObject]@{
                        Timestamp           = $TimeStamp
                        User                = $userId
                        IPaddress           = $ClientIP
                        SessionID           = $SessionId
                        InternetMessageId   = $iMessageID
                        SizeInBytes         = $sizeInBytes
                    }
                    
                    $results += $resultObject
                    if ($Download.IsPresent){
                        if (![string]::IsNullOrWhiteSpace($iMessageID)) {
                            DownloadMails($iMessageID,$userId)
                        }
                    }
                }
            }
        }
        $results | Sort TimeStamp | Format-Table Timestamp, User, IPaddress, SessionID, InternetMessageId, SizeInBytes -AutoSize
        
        if (($Output -eq "Yes") -and $results.Count -gt 0) {
            $date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
            $filePath = "$OutputDir\$date-MessageIDs.csv"
            $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
            Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green" -Level Standard
        } 
    }

    elseif ($IP -And $Sessions){
        try {
            $amountResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -FreeText $IP -Operations "MailItemsAccessed" -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount
        }
        catch {
            write-logFile -Message "[INFO] Ensure you are connected to M365 by running the Connect-M365 command before executing this script" -Color "Yellow" -Level Minimal
            Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
            throw
        }

        if ($amountResults -gt 4999){
            write-logFile -Message "[WARNING] A total of $amountResults events have been identified, surpassing the maximum limit of 5000 results for a single session. To refine your search, kindly lower the time window." -Color "Red" -Level Minimal
            return
        }

        else {
            $results=@()
            $MailItemRecords = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -FreeText $IP -ResultSize 5000 -Operations "MailItemsAccessed"
        
            forEach ($Rec in $MailItemRecords){
                $summary.TotalEvents++
                $AuditData = ConvertFrom-Json $Rec.Auditdata
                $InternetMessageId = $AuditData.Folders.FolderItems
                $TimeStamp = $AuditData.CreationTime
                $SessionId = $AuditData.SessionId
                $ClientIP = $AuditData.ClientIPAddress
                $userId = $AuditData.UserId
                $sizeInBytes = $AuditData.SizeInBytes
        
                if($SessionId){
                    if($Sessions.Contains($SessionId)){
                        if($ClientIP -eq $IP){

                            if ($AuditData.OperationCount -gt 1){
                                foreach ($message in $InternetMessageId){
                                    $iMessageID = $message.InternetMessageId
                                    $sizeInBytes = $message.SizeInBytes
            
                                    $resultObject = [PSCustomObject]@{
                                        Timestamp           = $TimeStamp
                                        User                = $userId
                                        IPaddress           = $ClientIP
                                        SessionID           = $SessionId
                                        InternetMessageId   = $iMessageID
                                        SizeInBytes         = $sizeInBytes
                                    }
                                    
                                    $results += $resultObject

                                    if ($Download.IsPresent){
                                        if (![string]::IsNullOrWhiteSpace($iMessageID)) {
                                            DownloadMails($iMessageID,$userId)
                                        }
                                    }
                                }
                            }
                                        
                            else {
                                $SessionID = ""
                                $iMessageID = $AuditData.Folders.FolderItems.InternetMessageId
                                
                                $resultObject = [PSCustomObject]@{
                                    Timestamp           = $TimeStamp
                                    User                = $userId
                                    IPaddress           = $ClientIP
                                    SessionID           = $SessionId
                                    InternetMessageId   = $iMessageID
                                    SizeInBytes         = $sizeInBytes
                                }
                                
                                $results += $resultObject

                                if ($Download.IsPresent){
                                    if (![string]::IsNullOrWhiteSpace($iMessageID)) {
                                        DownloadMails($iMessageID,$userId)
                                    }
                                }
                            }                               
                        }
                        
                    }
                }
            }
        }
        $results | Sort TimeStamp | Format-Table Timestamp, User, IPaddress, SessionID, InternetMessageId, SizeInBytes -AutoSize

        if (($Output -eq "Yes") -and $results.Count -gt 0) {
            $date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
            $filePath = "$OutputDir\$date-MessageIDs.csv"
            $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
            Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green" -Level Standard
        }
    }

    elseif ($Sessions -And !$IP){
        try {
            $amountResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -FreeText $Sessions -Operations "MailItemsAccessed" -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount
        }
        catch {
            write-logFile -Message "[INFO] Ensure you are connected to M365 by running the Connect-M365 command before executing this script" -Color "Yellow" -Level Minimal
            Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
            throw
        }
        
        if ($amountResults -gt 4999){
            write-logFile -Message "[WARNING] A total of $amountResults events have been identified, surpassing the maximum limit of 5000 results for a single session. To refine your search, kindly lower the time window." -Color "Red" -Level Minimal
            return
        }

        else {
            $results=@()
            $MailItemRecords = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -FreeText $Sessions -Operations "MailItemsAccessed"
        
            forEach ($Rec in $MailItemRecords){
                $summary.TotalEvents++
                $AuditData = ConvertFrom-Json $Rec.Auditdata
                $InternetMessageId = $AuditData.Folders.FolderItems
                $TimeStamp = $AuditData.CreationTime
                $SessionId = $AuditData.SessionId
                $ClientIP = $AuditData.ClientIPAddress
                $userId = $AuditData.UserId
                $sizeInBytes = $AuditData.SizeInBytes

                if($SessionId){
                    if($Sessions.Contains($SessionId)){
                        if ($AuditData.OperationCount -gt 1){
                            foreach ($message in $InternetMessageId){
                                $iMessageID = $message.InternetMessageId
                                $sizeInBytes = $message.SizeInBytes
            
                                $resultObject = [PSCustomObject]@{
                                    Timestamp           = $TimeStamp
                                    User                = $userId
                                    IPaddress           = $ClientIP
                                    SessionID           = $SessionId
                                    InternetMessageId   = $iMessageID
                                    SizeInBytes         = $sizeInBytes
                                }
                                
                                $results += $resultObject

                                if ($Download.IsPresent){
                                    if (![string]::IsNullOrWhiteSpace($iMessageID)) {
                                        DownloadMails($iMessageID,$userId)
                                    }
                                }
                            }
                        }
                                    
                        else {
                            $SessionID = ""
                            $iMessageID = $AuditData.Folders.FolderItems.InternetMessageId
                            
                            $resultObject = [PSCustomObject]@{
                                Timestamp           = $TimeStamp
                                User                = $userId
                                IPaddress           = $ClientIP
                                SessionID           = $SessionId
                                InternetMessageId   = $iMessageID
                                SizeInBytes         = $sizeInBytes
                            }
                            
                            $results += $resultObject

                            if ($Download.IsPresent){
                                if (![string]::IsNullOrWhiteSpace($iMessageID)) {
                                    DownloadMails($iMessageID,$userId)
                                }
                            }
                        }                               
                    }    
                }
            }
        }
        $results | Sort TimeStamp | Format-Table Timestamp, User, IPaddress, SessionID, InternetMessageId, SizeInBytes  

        if (($Output -eq "Yes") -and $results.Count -gt 0) {
            $filePath = "$OutputDir\MessageIDs-$Sessions.csv"
            $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
            Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green" -Level Standard
        }
    }
        
    elseif (!$Sessions -And $IP){
        try {
            $amountResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -FreeText $IP -Operations "MailItemsAccessed" -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount
        }
        catch {
            write-logFile -Message "[INFO] Ensure you are connected to M365 by running the Connect-M365 command before executing this script" -Color "Yellow" -Level Minimal
            Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red" -Level Minimal
            throw
        }

        if ($amountResults -gt 4999){
            write-logFile -Message "[WARNING] A total of $amountResults events have been identified, surpassing the maximum limit of 5000 results for a single session. To refine your search, kindly lower the time window." -Color "Red" -Level Minimal
        }

        else {
            $results=@()
            $MailItemRecords = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -FreeText $IP -ResultSize 5000 -Operations "MailItemsAccessed"

            forEach ($Rec in $MailItemRecords){
                $summary.TotalEvents++
                $AuditData = ConvertFrom-Json $Rec.Auditdata
                $InternetMessageId = $AuditData.Folders.FolderItems
                $TimeStamp = $AuditData.CreationTime
                $SessionId = $AuditData.SessionId
                $ClientIP = $AuditData.ClientIPAddress
                $sizeInBytes = $AuditData.SizeInBytes

                $userId = $AuditData.UserId
                  
                if($ClientIP -eq $IP){
                    if ($AuditData.OperationCount -gt 1){
                        foreach ($message in $InternetMessageId){
                            $iMessageID = $message.InternetMessageId
                            $sizeInBytes = $message.SizeInBytes
            
                            $resultObject = [PSCustomObject]@{
                                Timestamp           = $TimeStamp
                                User                = $userId
                                IPaddress           = $ClientIP
                                SessionID           = $SessionId
                                InternetMessageId   = $iMessageID
                                SizeInBytes         = $sizeInBytes
                            }
                            
                            $results += $resultObject

                            if ($Download.IsPresent){
                                if (![string]::IsNullOrWhiteSpace($iMessageID)) {
                                    DownloadMails($iMessageID,$userId)
                                }
                            }
                        }
                    }
                                
                    else {
                        $SessionID = ""
                        $iMessageID = $AuditData.Folders.FolderItems.InternetMessageId
                        
                        $resultObject = [PSCustomObject]@{
                            Timestamp           = $TimeStamp
                            User                = $userId
                            IPaddress           = $ClientIP
                            SessionID           = $SessionId
                            InternetMessageId   = $iMessageID
                            SizeInBytes         = $sizeInBytes
                        }
                        
                        $results += $resultObject

                        if ($Download.IsPresent){
                            if (![string]::IsNullOrWhiteSpace($iMessageID)) {
                                DownloadMails($iMessageID,$userId)
                            }
                        }
                    }                               
                }          
            }
        }
        $results | Sort TimeStamp | Format-Table Timestamp, User, IPaddress, SessionID, InternetMessageId, SizeInBytes  

        if (($Output -eq "Yes") -and $results.Count -gt 0) {
            $date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
            $filePath = "$OutputDir\$date-MessageIDs.csv"
            $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
        }
    }
    
    $summary.ProcessingTime = (Get-Date) - $summary.StartTime

    if ($Results.Count -gt 0) {
        Write-LogFile -Message "`n=== Session Analysis Summary ===" -Color "Cyan" -Level Standard
        Write-LogFile -Message "Time Range: $StartDate to $EndDate" -Level Standard
        Write-LogFile -Message "Total MailItemsAccessed Events processed: $($summary.TotalEvents)" -Level Standard
        Write-LogFile -Message "Output Directory: $OutputDir" -Level Standard
        Write-LogFile -Message "`nProcessing Time: $($summary.ProcessingTime.ToString('mm\:ss'))" -Color "Green" -Level Standard
        Write-LogFile -Message "===================================" -Color "Cyan" -Level Standard
    }
}

function DownloadMails($iMessageID,$UserIds){
    if ($iMessageID -is [array]) {
        $iMessageID = $iMessageID[0]
    }

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] DownloadMails function called" -Level Debug
        Write-LogFile -Message "[DEBUG]   Input iMessageID: '$iMessageID'" -Level Debug
        Write-LogFile -Message "[DEBUG]   Input UserIds: '$UserIds'" -Level Debug
        Write-LogFile -Message "[DEBUG]   Current fileCounter: $script:fileCounter" -Level Debug
    }
    
    if (-not (Get-Variable -Name fileCounter -ErrorAction SilentlyContinue)) {
        $script:fileCounter = 1
    }

    if ([string]::IsNullOrWhiteSpace($iMessageID)) {
        Write-LogFile -Message "[WARNING] Invalid or empty message ID provided" -Color "Red" -Level Minimal
        return
    }

    if ($outputDir -eq "" ){
        $outputDir = "Output\MailItemsAccessed\Emails"
        if (!(test-path $outputDir)) {
            New-Item -ItemType Directory -Force -Name $outputDir > $null
        }
    }

    try {
        try {
            $onlyMessageID = $iMessageID.Split(" ")[0]
            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Processing message ID split" -Level Debug
                Write-LogFile -Message "[DEBUG]   Original ID: '$iMessageID'" -Level Debug
                Write-LogFile -Message "[DEBUG]   Split ID: '$onlyMessageID'" -Level Debug
            }
        }
        catch {
            Write-logFile -Message "[WARNING] Unable to download message with unknown ID '$iMessageID'." -Color "Yellow" -Level minimal
        }

        try {
            $getMessage = Get-MgUserMessage -Filter "internetMessageId eq '$onlyMessageID'" -UserId $UserIds -ErrorAction Stop

            if ($null -eq $getMessage) {
                Write-LogFile -Message "[WARNING] No message found with ID '$onlyMessageID'" -Color "Yellow" -Level Minimal
                return
            }

            if ($isDebugEnabled) {
                Write-LogFile -Message "[DEBUG] Successfully retrieved message from Graph API" -Level Debug
                Write-LogFile -Message "[DEBUG]   Message ID: '$($getMessage.Id)'" -Level Debug
                Write-LogFile -Message "[DEBUG]   Subject: '$($getMessage.Subject)'" -Level Debug
                Write-LogFile -Message "[DEBUG]   ReceivedDateTime: '$($getMessage.ReceivedDateTime)'" -Level Debug
                Write-LogFile -Message "[DEBUG]   HasAttachments: '$($getMessage.HasAttachments)'" -Level Debug
                Write-LogFile -Message "[DEBUG]   Attachments count: $($getMessage.Attachments.Count)" -Level Debug
            }

            if ($messageId -match " ") {
                $messageId = $messageId.Split(" ")[0]
            }
            
            $messageId = $getMessage.Id
            $attachment = $getMessage.Attachments
        } catch {
            Write-LogFile -Message "[WARNING] Error retrieving message with ID '$onlyMessageID': $($_.Exception.Message)" -Color "Yellow" -Level Minimal
            return
        }

        if ($getMessage.ReceivedDateTime -is [DateTime]) {
            $ReceivedDateTime = $getMessage.ReceivedDateTime.ToString("yyyyMMdd_HHmmss")
        } else {
            $ReceivedDateTime = "unabletogetdate"  # Fallback to custom string
        }

        $subject = $getMessage.Subject
        $subject = $subject -replace '[\\/:*?"<>|]', '_'

        if ($isDebugEnabled) {
            Write-LogFile -Message "[DEBUG] File naming preparation" -Level Debug
            Write-LogFile -Message "[DEBUG]   Processed date: '$ReceivedDateTime'" -Level Debug
            Write-LogFile -Message "[DEBUG]   Original subject: '$($getMessage.Subject)'" -Level Debug
            Write-LogFile -Message "[DEBUG]   Sanitized subject: '$subject'" -Level Debug
        }

        do {
            $filePath = "$outputDir\$($script:fileCounter.ToString('D3'))-$ReceivedDateTime-$subject.eml"
            $script:fileCounter++
        } while (Test-Path $filePath)

        try {
            Get-MgUserMessageContent -MessageId $messageId -UserId $UserIds -OutFile $filePath


            Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green" -Level Standard
        } catch {
            if ($_.Exception.Message -like "*Cannot bind argument to parameter 'MessageId' because it is an empty string*") {
                Write-logFile -Message "[WARNING] Unable to download message with ID '$iMessageID' was likely deleted." -Color "Red" -Level minimal
            } else {
                Write-logFile -Message "[WARNING] Unable to download message with ID '$iMessageID." -Color "Red" -Level minimal
            }
        }

        if ($attachment -eq "True"){
            Write-logFile -Message "[INFO] Found Attachment file!" -Level Standard
            $attachment = Get-MgUserMessageAttachment -UserId $UserIds -MessageId $messageId

            $filename = $attachment.Name

            Write-logFile -Message "[INFO] Downloading attachment" -Level Standard
            Write-logFile -Message "[INFO] Name: $filename" -Level Standard
            Write-logFile -Message "[INFO] Size: $($attachment.Size)" -Level Standard

            $base64B = ($attachment).AdditionalProperties.contentBytes
            $decoded = [System.Convert]::FromBase64String($base64B)

            $filename = $filename -replace '[\\/:*?"<>|]', '_'
            do {
                $filePath = "$outputDir\$($script:fileCounter.ToString('D3'))-$ReceivedDateTime-$filename"
                $script:fileCounter++
            } while (Test-Path $filePath)

            Set-Content -Path $filePath -Value $decoded -Encoding Byte

            Write-logFile -Message "[INFO] File Attachment Successfully Written to $filePath" -Color "Green" -Level Standard
        }
    }
    catch {
        Write-logFile -Message "[WARNING] The 'Mail.ReadWrite' is an application-level permission, requiring an application-based connection through the 'Connect-MgGraph' command for its use." -Color "Red" -Level minimal
        Write-logFile "[WARNING] Error Message: $($_.Exception.Message)"  -Level minimal
    }
}
    
    