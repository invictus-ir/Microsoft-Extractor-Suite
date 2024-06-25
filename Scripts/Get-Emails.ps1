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
    
    .EXAMPLE
    Get-Email -userIds fortunahodan@bonacu.onmicrosoft.com -internetMessageId "<d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com>" 
    Retrieves an email from fortunahodan@bonacu.onmicrosoft.com with the internet message identifier <d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com> to a eml file.
	
    .EXAMPLE
	Get-Email -userIds fortunahodan@bonacu.onmicrosoft.com -internetMessageId "<d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com>" -attachment True
    Retrieves an email and the attachment from fortunahodan@bonacu.onmicrosoft.com with the internet message identifier <d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com> to a eml file.
		
	.EXAMPLE
	Get-Email -userIds fortunahodan@bonacu.onmicrosoft.com -internetMessageId "<d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com>" -OutputDir C:\Windows\Temp
	Retrieves an email and saves it to C:\Windows\Temp folder.
#>
    [CmdletBinding()]
	param(
		[Parameter(Mandatory=$true)]$userIds,
		[string]$internetMessageId,
        [string]$Output = "eml",
		[string]$outputDir = "Output\EmailExport",
        [switch]$attachment,
        [string]$inputFile
	)  

    Write-logFile -Message "[INFO] Running Get-Email" -Color "Green"

    if (!(Test-Path -Path $outputDir)) {
        Write-LogFile -Message "[INFO] Creating the following directory: $outputDir"
        New-Item -ItemType Directory -Path $outputDir -Force > $null
    } else {
        Write-LogFile -Message "[INFO] Directory exists: $outputDir"
    }

    if ($inputFile) {
        try {
            $internetMessageIds = Get-Content $inputFile
        }
        catch {
            Write-Error "[ERROR] Failed to read the input file. Ensure it is a text file with the message IDs on new lines: $_"
            return
        }
    
        $notCollected = @()
        foreach ($id in $internetMessageIds) {
            $id = $id.Trim()
            write-host "[INFO] Identified: $id"
           
            try {
                $getMessage = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$userIds/messages?filter=internetMessageId eq '$id'"
                $message = $getMessage.value[0]
                $ReceivedDateTime = [datetime]::Parse($message.ReceivedDateTime).ToString("yyyyMMdd_HHmmss")
                $messageId = $message.Id
                $subject = $message.Subject -replace '[\\/:*?"<>|]', '_'
        
                if ($output -eq "txt") {
                    $filePath = "$outputDir\$ReceivedDateTime-$subject.txt"
                }
                
                else {
                    $filePath = "$outputDir\$ReceivedDateTime-$subject.eml"
                }

                $contentUri = "https://graph.microsoft.com/v1.0/users/$userIds/messages/$messageId/\$value"            
                Invoke-MgGraphRequest -Uri $contentUri -Method Get -OutputFilePath $filePath
                Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green"

                if ($attachment.IsPresent){
                    Get-Attachment -Userid $Userids -internetMessageId $id
                }
           }
           catch {
               Write-Warning "[WARNING] Failed to collect message with ID '$id': $_"
               $notCollected += $id 
           }
        }
        if ($notCollected.Count -gt 0) {
            Write-logFile -Message "[INFO] The following messages have not been collected:" -Color "Yellow"
            foreach ($notCollectedID in $notCollected) {
                Write-logFile -Message "  $notCollectedID" -Color "Yellow"
            }
        }
    }

    else {
        if (-not $internetMessageId) {
            Write-Error "[ERROR] Either internetMessageId or inputFile must be provided."
            return
        }
    
        try {
            $getMessage = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$userIds/messages?filter=internetMessageId eq '$internetMessageId'"
            $message = $getMessage.value[0]
            $ReceivedDateTime = [datetime]::Parse($message.ReceivedDateTime).ToString("yyyyMMdd_HHmmss")
            $messageId = $message.Id
            $subject = $message.Subject -replace '[\\/:*?"<>|]', '_'

            if ($output -eq "txt") {
                $filePath = "$outputDir\$ReceivedDateTime-$subject.txt"
            }
            
            else {
                $filePath = "$outputDir\$ReceivedDateTime-$subject.eml"
            }

            $contentUri = "https://graph.microsoft.com/v1.0/users/$userIds/messages/$messageId/\$value"               
            Invoke-MgGraphRequest -Uri $contentUri -Method Get -OutputFilePath $filePath
            Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green"

            if ($attachment.IsPresent){
                Get-Attachment -Userid $Userids -internetMessageId $internetMessageId
            }
        }
        catch {
            Write-logFile -Message "[WARNING] You must call Connect-MgGraph -Scopes Mail.ReadBasic.All before running this script" -Color "Red"
            Write-logFile -Message "[WARNING] The 'Mail.ReadBasic.All' is an application-level permission, requiring an application-based connection through the 'Connect-MgGraph' command for its use." -Color "Red"
            return
        }  
    }   
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
		[string]$outputDir = "Output\EmailExport"
	)

    Write-logFile -Message "[INFO] Running Get-Attachment" -Color "Green"

    if (!(Test-Path -Path $outputDir)) {
        Write-LogFile -Message "[INFO] Creating the following directory: $outputDir"
        New-Item -ItemType Directory -Path $outputDir -Force > $null
    } else {
        Write-LogFile -Message "[INFO] Directory exists: $outputDir"
    }

    try {
        $getMessage = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$userIds/messages?filter=internetMessageId eq '$internetMessageId'" -ErrorAction stop
    }
    catch {
        Write-logFile -Message "[WARNING] You must call Connect-MgGraph -Scopes Mail.ReadBasic.All before running this script" -Color "Red"
        Write-logFile -Message "[WARNING] The 'Mail.ReadBasic.All' is an application-level permission, requiring an application-based connection through the 'Connect-MgGraph' command for its use." -Color "Red"
        Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red"
        break
    }

    $messageId = $getMessage.value.Id
    $hasAttachment = $getMessage.value.HasAttachments
    $ReceivedDateTime = $getMessage.value.ReceivedDateTime.ToString("yyyyMMdd_HHmmss")
    $subject = $getMessage.value.Subject

    if ($hasAttachment -eq "True"){
        $response = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$userIds/messages/$messageId/attachments"

        foreach ($attachment in $response.value){
            $filename = $attachment.Name
        
            Write-logFile -Message "[INFO] Downloading attachment"
            Write-host "[INFO] Name: $filename"
            write-host "[INFO] Size: $($attachment.Size)"

            $uri = "https://graph.microsoft.com/v1.0/users/$userIds/messages/$messageId/attachments/$($attachment.Id)/\$value" 
            $response = Invoke-MgGraphRequest -Method Get -Uri $uri 

            $filename = $filename -replace '[\\/:*?"<>|]', '_'
            $filePath = Join-Path $outputDir "$ReceivedDateTime-$subject-$filename"

            $base64B = ($attachment.contentBytes)
            $decoded = [System.Convert]::FromBase64String($base64B)
            Set-Content -Path $filePath -Value $decoded -Encoding Byte
        
            Write-logFile -Message "[INFO] Output written to '$subject-$filename'" -Color "Green"
        }
    }

    else {
        Write-logFile -Message "[WARNING] No attachment found for: $subject" -Color "Red"
    }
}


Function Show-Email {
<#
    .SYNOPSIS
    Show a specific email in the PowerShell Window.

    .DESCRIPTION
    Show a specific email in the PowerShell Window based on userId and Internet Message Id.

    .EXAMPLE
    Show-Email -userIds {userId} -internetMessageId {InternetMessageId}
    Show a specific email in the PowerShell Window.
	
#>
    [CmdletBinding()]
	param(
		[Parameter(Mandatory=$true)]$userIds,
		[Parameter(Mandatory=$true)]$internetMessageId
	)

    Write-logFile -Message "[INFO] Running Show-Email" -Color "Green"

    try {

        $message = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$userIds/messages?filter=internetMessageId eq '$internetMessageId'" -ErrorAction stop
    }
    catch {
        Write-logFile -Message "[WARNING] You must call Connect-MgGraph -Scopes Mail.ReadBasic.All before running this script" -Color "Red"
        Write-logFile -Message "[WARNING] The 'Mail.ReadBasic.All' is an application-level permission, requiring an application-based connection through the 'Connect-MgGraph' command for its use." -Color "Red"
        Write-logFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red"
        break
    }

    $message.Value
}