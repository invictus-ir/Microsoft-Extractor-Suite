Function Get-Email {
<#
    .SYNOPSIS
    Get a specific email.

    .DESCRIPTION
    Get a specific email based on userId and Internet Message Id and saves the output to a msg or txt file.

	.PARAMETER OutputDir
	OutputDir is the parameter specifying the output directory.
	Default: Output\EmailExport

	.PARAMETER UserIds
    The unique identifier of the user.

    .PARAMETER internetMessageId
    The InternetMessageId parameter represents the Internet message identifier of an item.

    .PARAMETER output
    Output is the parameter specifying the msg or txt output type.
	Default: msg

    .PARAMETER attachment
    The attachment parameter specifies whether the attachment should be saved or not. 
    Default: False 
    
    .EXAMPLE
    Get-Email -userIds fortunahodan@bonacu.onmicrosoft.com -internetMessageId "<d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com>" 
    Retrieves an email from fortunahodan@bonacu.onmicrosoft.com with the internet message identifier <d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com> to a msg file.
	
    .EXAMPLE
	Get-Email -userIds fortunahodan@bonacu.onmicrosoft.com -internetMessageId "<d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com>" -attachment True
    Retrieves an email and the attachment from fortunahodan@bonacu.onmicrosoft.com with the internet message identifier <d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com> to a msg file.
		
	.EXAMPLE
	Get-Email -userIds fortunahodan@bonacu.onmicrosoft.com -internetMessageId "<d6f15b97-e3e3-4871-adb2-e8d999d51f34@az.westeurope.microsoft.com>" -OutputDir C:\Windows\Temp
	Retrieves an email and saves it to C:\Windows\Temp folder.
#>
    [CmdletBinding()]
	param(
		[Parameter(Mandatory=$true)]$userIds,
		[Parameter(Mandatory=$true)]$internetMessageId,
        [string]$output,
		[string]$outputDir,
        [string]$attachment
	)

    Write-logFile -Message "[INFO] Running Get-Email" -Color "Green"

    try {
        $areYouConnected = Get-MgUserMessage -UserId $userIds -Filter "internetMessageId eq '$internetMessageId'"
    }
    catch {
        Write-logFile -Message "[WARNING] You must call Connect-MgGraph -Scopes Mail.Read, Mail.ReadBasic, Mail.ReadBasic.All before running this script" -Color "Red"
        Write-logFile -Message "[WARNING] The 'Mail.ReadBasic.All' is an application-level permission, requiring an application-based connection through the 'Connect-MgGraph' command for its use." -Color "Red"
        break
    }

    if ($outputDir -eq "" ){
        $outputDir = "Output\EmailExport"
        if (!(test-path $outputDir)) {
            write-logFile -Message "[INFO] Creating the following directory: $outputDir"
            New-Item -ItemType Directory -Force -Name $outputDir | Out-Null
        }
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

    $getMessage = Get-MgUserMessage -UserId $userIds -Filter "internetMessageId eq '$internetMessageId'"
    $messageId = $getMessage.Id

    $subject = $getMessage.Subject
    $subject = $subject -replace '[\\/:*?"<>|]', '_'

    $ReceivedDateTime = $getMessage.ReceivedDateTime.ToString("yyyyMMdd_HHmmss")

    if ($output -eq "txt") {
        $filePath = "$outputDir\$ReceivedDateTime-$subject.txt"
    }
    
    else {
        $filePath = "$outputDir\$ReceivedDateTime-$subject.msg"
    }

    Get-MgUserMessageContent -MessageId $messageId -UserId $userIds -OutFile $filePath
    Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green"

    if ($attachment -eq "True"){
        Get-Attachment -Userid $Userids -internetMessageId $internetMessageId
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
		[string]$outputDir
	)

    Write-logFile -Message "[INFO] Running Get-Attachment" -Color "Green"

    try {
        $areYouConnected = Get-MgUserMessage -Filter "internetMessageId eq '$internetMessageId'" -UserId $userIds -ErrorAction stop
    }
    catch {
        Write-logFile -Message "[WARNING] You must call Connect-MgGraph -Scopes Mail.Read, Mail.ReadBasic, Mail.ReadBasic.All before running this script" -Color "Red"
        Write-logFile -Message "[WARNING] The 'Mail.ReadBasic.All' is an application-level permission, requiring an application-based connection through the 'Connect-MgGraph' command for its use." -Color "Red"
        break
    }

    if ($outputDir -eq "" ){
        $outputDir = "Output\EmailExport"
        if (!(test-path $outputDir)) {
            New-Item -ItemType Directory -Force -Name $outputDir | Out-Null
            write-logFile -Message "[INFO] Creating the following directory: $outputDir"
        }
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

    $getMessage = Get-MgUserMessage -Filter "internetMessageId eq '$internetMessageId'" -UserId $userIds
    $messageId = $getMessage.Id
    $hasAttachment = $getMessage.HasAttachments
    $ReceivedDateTime = $getMessage.ReceivedDateTime.ToString("yyyyMMdd_HHmmss")
    $subject = $getMessage.Subject

    if ($hasAttachment -eq "True"){
        $attachment = Get-MgUserMessageAttachment -UserId $userIds -MessageId $messageId
        $filename = $attachment.Name
    
        Write-logFile -Message "[INFO] Downloading attachment"
        Write-host "[INFO] Name: $filename"
        write-host "[INFO] Size: $($attachment.Size)"
    
        $base64B = ($attachment).AdditionalProperties.contentBytes
        $decoded = [System.Convert]::FromBase64String($base64B)

        $filename = $filename -replace '[\\/:*?"<>|]', '_'
        $filePath = Join-Path -Path $outputDir -ChildPath "$ReceivedDateTime-$filename"
        Set-Content -Path $filePath -Value $decoded -Encoding Byte
    
        Write-logFile -Message "[INFO] Output written to '$subject-$filename'" -Color "Green"
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
        $areYouConnected = Get-MgUserMessage -Filter "internetMessageId eq '$internetMessageId'" -UserId $userIds -ErrorAction stop
    }
    catch {
        Write-logFile -Message "[WARNING] You must call Connect-MgGraph -Scopes Mail.Read, Mail.ReadBasic, Mail.ReadBasic.All, Mail.ReadWrite before running this script" -Color "Red"
        Write-logFile -Message "[WARNING] The 'Mail.ReadBasic.All' is an application-level permission, requiring an application-based connection through the 'Connect-MgGraph' command for its use." -Color "Red"
        break
    }

    Get-MgUserMessage -Filter "internetMessageId eq '$internetMessageId'" -UserId $userIds | fl *
}