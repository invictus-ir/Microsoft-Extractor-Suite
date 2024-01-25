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

	.PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
	Default: UTF8

    .PARAMETER Output
    "Y" or "N" to specify whether the output should be saved to a file.
	Default: Y

	.EXAMPLE
    Get-Sessions -StartDate 1/4/2023 -EndDate 5/4/2023
	Collects all sessions for all users between 1/4/2023 and 5/4/2023.
    
    .EXAMPLE
    Get-Sessions Get-Sessions -StartDate 1/4/2023 -EndDate 5/4/2023 -UserIds HR@invictus-ir.com
	Collects all sessions for the user HR@invictus-ir.com.
#>
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true)]$StartDate,
        [Parameter(Mandatory=$true)]$EndDate,
		[string]$OutputDir,
        [string]$UserIds,
        [string]$IP,
		[string]$Encoding,
        [string]$Output
	)

    try {
		$areYouConnected = Get-AdminAuditLogConfig -ErrorAction stop
	}
	catch {
		write-logFile -Message "[WARNING] You must call Connect-M365 before running this script" -Color "Red"
		break
	}

    if ($OutputDir -eq "" ){
        $OutputDir = "Output\MailItemsAccessed"
        if (!(test-path $OutputDir)) {
            write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
            New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
        }
    }

    if ($Encoding -eq "" ){
		$Encoding = "UTF8"
	}

    Write-logFile -Message "[INFO] Running Get-Sessions" -Color "Green"
    
    if ($UserIds -And !$IP){
        $Results = @()

        $amountResults = (Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations "MailItemsAccessed" -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount)

        if($amountResults -gt 4999){
            write-logFile -Message "[WARNING] A total of $amountResults events have been identified, surpassing the maximum limit of 5000 results for a single session. To refine your search, kindly provide more specific details, such as specifying a user or IP address." -Color "Red"
        }

        else{   
            $mailItemRecords = (Search-UnifiedAuditLog -UserIds $UserIds -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -Operations "MailItemsAccessed")
            
            foreach($rec in $mailItemRecords) {
                $AuditData = ConvertFrom-Json $Rec.Auditdata
                $Line = [PSCustomObject]@{
                TimeStamp   = $AuditData.CreationTime
                User        = $AuditData.UserId
                Action      = $AuditData.Operation
                SessionId   = $AuditData.SessionId
                ClientIP    = $AuditData.ClientIPAddress
                OperationCount = $AuditData.OperationCount
            }
                
                $Results += $Line
            }
            
            $Results | Sort SessionId, TimeStamp | Format-Table Timestamp, User, Action, SessionId, ClientIP, OperationCount -AutoSize
         }

        if (($output -ne "N") -And ($output -ne "No")) {
            $filePath = "$OutputDir\Sessions-$UserIds.csv"
            $Results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
            Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green"
        }  
    }

        elseif($IP -And !$UserIds){
            $Results = @()

            $amountResults = (Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations "MailItemsAccessed" -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount)

            if($amountResults -gt 4999){
                write-logFile -Message "[WARNING] A total of $amountResults events have been identified, surpassing the maximum limit of 5000 results for a single session. To refine your search, kindly provide more specific details, such as specifying a user." -Color "Red"
            }

            else{              
                $MailItemRecords = (Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -Operations "MailItemsAccessed")

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
                    
                    if($AuditData.ClientIPAddress -eq $IP){
                        $Results += $Line
                    }
                 }
                    
                $Results | Sort SessionId, TimeStamp | Format-Table Timestamp, User, Action, SessionId, ClientIP, OperationCount -AutoSize
            }

            if (($output -ne "N") -And ($output -ne "No")) {
                $filePath = "$OutputDir\Sessions-$IP.csv"
                $Results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
                Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green"
            }  
        }
            
        elseif($IP -And $UserIds){
            $Results = @()

            $amountResults = (Search-UnifiedAuditLog -UserIds $UserIds -StartDate $StartDate -EndDate $EndDate -Operations "MailItemsAccessed" -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount)
            if($amountResults -gt 4999){
                write-logFile -Message "[WARNING] A total of $amountResults events have been identified, surpassing the maximum limit of 5000 results for a single session. To refine your search, kindly provide a more specific time window." -Color "Red"
            }

            else{
                $MailItemRecords = (Search-UnifiedAuditLog -UserIds $UserIds -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -Operations "MailItemsAccessed")
        
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
                    $Results += $Line
                }
            }
                    
                $Results | Sort SessionId, TimeStamp | Format-Table Timestamp, User, Action, SessionId, ClientIP, OperationCount -AutoSize
            }

            if (($output -ne "N") -And ($output -ne "No")) {
                $filePath = "$OutputDir\Sessions-$UserIds-$IP.csv"
                $Results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
                Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green"
            }   
        }
    
        else{
            $Results = @()

            $amountResults = (Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations "MailItemsAccessed" -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount)

            if($amountResults -gt 4999){
                write-logFile -Message "[WARNING] A total of $amountResults events have been identified, surpassing the maximum limit of 5000 results for a single session. To refine your search, kindly provide more specific details, such as specifying a user." -Color "Red"
            }

            else{   
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
                    
                $Results += $Line}
                $Results | Sort SessionId, TimeStamp | Format-Table Timestamp, User, Action, SessionId, ClientIP, OperationCount -AutoSize
            }

            if (($output -ne "N") -And ($output -ne "No")) {
                $filePath = "$OutputDir\Sessions.csv"
                $Results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
                Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green"
            }   
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

    .PARAMETER Download
    To specifiy whether the messages and their attachments should be saved.
	Default: No

	.EXAMPLE
    Get-MessageIDs -StartDate 1/4/2023 -EndDate 5/4/2023
	Collects all sessions for all users between 1/4/2023 and 5/4/2023.
    
    .EXAMPLE
    Get-MessageIDs Get-Sessions -StartDate 1/4/2023 -EndDate 5/4/2023 -IP 1.1.1.1
	Collects all sessions for the IP address 1.1.1.1.

    .EXAMPLE
    Get-MessageIDs Get-Sessions -StartDate 1/4/2023 -EndDate 5/4/2023 -IP 1.1.1.1 -Download Yes
	Collects all sessions for the IP address 1.1.1.1 and downloads the e-mails and attachments.
#>
    [CmdletBinding()]
	param(
        [Parameter(Mandatory=$true)]$StartDate,
        [Parameter(Mandatory=$true)]$EndDate,
		[string]$OutputDir,
        [string]$IP,
		[string]$Encoding,
        [string]$Sessions,
        [string]$Output,
        [string]$Download
	)

    try {
		$areYouConnected = Get-AdminAuditLogConfig -ErrorAction stop
	}
	catch {
		write-logFile -Message "[WARNING] You must call Connect-M365 before running this script" -Color "Red"
		break
	}

    if ($OutputDir -eq "" ){
        $OutputDir = "Output\MailItemsAccessed"
        if (!(test-path $OutputDir)) {
            write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
            New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
        }
    }

    if ($Encoding -eq "" ){
		$Encoding = "UTF8"
	}
    
    Write-logFile -Message "[INFO] Running Get-MessageIDs" -Color "Green"

    $results=@();
	
	if (!$Sessions -And !$IP){
		$amountResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations "MailItemsAccessed" -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount
		
        if ($amountResults -gt 4999){
            write-logFile -Message "[WARNING] A total of $amountResults events have been identified, surpassing the maximum limit of 5000 results for a single session. To refine your search, kindly lower the time window." -Color "Red"
        }

        else {
            $MailItemRecords = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -Operations "MailItemsAccessed"

            forEach ($Rec in $MailItemRecords){
                $AuditData = ConvertFrom-Json $Rec.Auditdata
                $InternetMessageId = $AuditData.Folders.FolderItems
                $TimeStamp = $AuditData.CreationTime
                $SessionId = $AuditData.SessionId
                $ClientIP = $AuditData.ClientIPAddress
                $userId = $AuditData.UserId
                                
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

                        if ($Download -eq "Yes" ){
                            DownloadMails($iMessageID,$userId)
                        } 
                    }
                }
                            
                else {
                    $SessionID = ""
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

                    if ($Download -eq "Yes" ){
                        DownloadMails($iMessageID,$userId)
                    }
                }
            }
        }
        $results | Sort TimeStamp | Format-Table Timestamp, User, IPaddress, SessionID, InternetMessageId, SizeInBytes
        
        if (($output -ne "N") -And ($output -ne "No")) {
            $date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
            $filePath = "$OutputDir\MessageIDs-$date.csv"
            $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
            Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green"
        } 
    }

    elseif ($IP -And $Sessions){
        $amountResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations "MailItemsAccessed" -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount
		
        if ($amountResults -gt 4999){
            write-logFile -Message "[WARNING] A total of $amountResults events have been identified, surpassing the maximum limit of 5000 results for a single session. To refine your search, kindly lower the time window." -Color "Red"
        }

        else {
            $MailItemRecords = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -Operations "MailItemsAccessed"
        
            forEach ($Rec in $MailItemRecords){
                $AuditData = ConvertFrom-Json $Rec.Auditdata
                $InternetMessageId = $AuditData.Folders.FolderItems
                $TimeStamp = $AuditData.CreationTime
                $SessionId = $AuditData.SessionId
                $ClientIP = $AuditData.ClientIPAddress
                $userId = $AuditData.UserId
        
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

                                    if ($Download -eq "Yes" ){
                                        DownloadMails($iMessageID,$userId)
                                    }
                                }
                            }
                                        
                            else {
                                $SessionID = ""
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

                                if ($Download -eq "Yes" ){
                                    DownloadMails($iMessageID,$userId)
                                }
                            }                               
                        }
                        
                    }
                }
            }
        }
        $results | Sort TimeStamp | Format-Table Timestamp, User, IPaddress, SessionID, InternetMessageId, SizeInBytes  

        if (($output -ne "N") -And ($output -ne "No")) {
            $date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
            $filePath = "$OutputDir\MessageIDs-$date.csv"
            $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
            Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green"
        }
    }

    elseif ($Sessions -And !$IP){
        $amountResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations "MailItemsAccessed" -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount
		
        if ($amountResults -gt 4999){
            write-logFile -Message "[WARNING] A total of $amountResults events have been identified, surpassing the maximum limit of 5000 results for a single session. To refine your search, kindly lower the time window." -Color "Red"
        }

        else {
            $MailItemRecords = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -Operations "MailItemsAccessed"
        
            forEach ($Rec in $MailItemRecords){
                $AuditData = ConvertFrom-Json $Rec.Auditdata
                $InternetMessageId = $AuditData.Folders.FolderItems
                $TimeStamp = $AuditData.CreationTime
                $SessionId = $AuditData.SessionId
                $ClientIP = $AuditData.ClientIPAddress
                $userId = $AuditData.UserId

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

                                if ($Download -eq "Yes" ){
                                    DownloadMails($iMessageID,$userId)
                                }
                            }
                        }
                                    
                        else {
                            $SessionID = ""
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

                            if ($Download -eq "Yes" ){
                                DownloadMails($iMessageID,$userId)
                            }
                        }                               
                    }    
                }
            }
        }
        $results | Sort TimeStamp | Format-Table Timestamp, User, IPaddress, SessionID, InternetMessageId, SizeInBytes  

        if (($output -ne "N") -And ($output -ne "No")) {
            $filePath = "$OutputDir\MessageIDs-$SessionId.csv"
            $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
            Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green"
        }
    }
        
    elseif (!$Sessions -And $IP){
        $amountResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations "MailItemsAccessed" -ResultSize 1 | Select-Object -First 1 -ExpandProperty ResultCount
        
        if ($amountResults -gt 4999){
            write-logFile -Message "[WARNING] A total of $amountResults events have been identified, surpassing the maximum limit of 5000 results for a single session. To refine your search, kindly lower the time window." -Color "Red"
        }

        else {
            $MailItemRecords = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -Operations "MailItemsAccessed"
        
            forEach ($Rec in $MailItemRecords){
                $AuditData = ConvertFrom-Json $Rec.Auditdata
                $InternetMessageId = $AuditData.Folders.FolderItems
                $TimeStamp = $AuditData.CreationTime
                $SessionId = $AuditData.SessionId
                $ClientIP = $AuditData.ClientIPAddress
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

                            if ($Download -eq "Yes" ){
                                DownloadMails($iMessageID,$userId)
                            }
                        }
                    }
                                
                    else {
                        $SessionID = ""
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

                        if ($Download -eq "Yes" ){
                            DownloadMails($iMessageID,$userId)
                        }
                    }                               
                }          
            }
        }
        $results | Sort TimeStamp | Format-Table Timestamp, User, IPaddress, SessionID, InternetMessageId, SizeInBytes  

        if (($output -ne "N") -And ($output -ne "No")) {
            $date = [datetime]::Now.ToString('yyyyMMddHHmmss') 
            $filePath = "$OutputDir\MessageIDs-$date.csv"
            $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
            Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green"
        }
    }                       
}

function DownloadMails($iMessageID,$UserIds){

    $onlyMessageID = $iMessageID.Split(" ")[0]
    if ($outputDir -eq "" ){
        $outputDir = "Output\MailItemsAccessed\Emails"
        if (!(test-path $outputDir)) {
            write-logFile -Message "[INFO] Creating the following directory: $outputDir"
            New-Item -ItemType Directory -Force -Name $outputDir | Out-Null
        }
    }

    try {
        $getMessage = Get-MgUserMessage -Filter "internetMessageId eq '$onlyMessageID'" -UserId $userId -ErrorAction stop
        $messageId = $getMessage.Id
        $attachment = $getMessage.Attachments

        $filePath = "$outputDir\$messageId.msg"

        Get-MgUserMessageContent -MessageId $messageId -UserId $userId -OutFile $filePath
        Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green"

        if ($attachment -eq "True"){
            Write-logFile -Message "[INFO] Found Attachment file!"
            $attachment = Get-MgUserMessageAttachment -UserId $userIds -MessageId $iMessageID
            $filename = $attachment.Name

            Write-logFile -Message "[INFO] Downloading attachment"
            Write-host "[INFO] Name: $filename"
            write-host "[INFO] Size: $($attachment.Size)"

            $base64B = ($attachment).AdditionalProperties.contentBytes
            $decoded = [System.Convert]::FromBase64String($base64B)

            $filePath = "$OutputDir\'$messageId-$filename'"
            Set-Content $filePath -Value $decoded -Encoding Byte

            Write-logFile -Message "[INFO] File Attachment Successfully Written to $filePath" -Color "Green"
        }
    }
    catch {
        Write-logFile -Message "[WARNING] You must call Connect-MgGraph -Scopes Mail.Read, Mail.ReadBasic, Mail.ReadBasic.All, Mail.ReadWrite before running the -Download flag" -Color "Red"
        Write-logFile -Message "[WARNING] The 'Mail.ReadBasic.All' is an application-level permission, requiring an application-based connection through the 'Connect-MgGraph' command for its use." -Color "Red"
        break
    }

    



}

