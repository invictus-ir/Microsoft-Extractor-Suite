function Get-RiskyUsers {
<#
    .SYNOPSIS
    Retrieves the risky users. 

    .DESCRIPTION
    Retrieves the risky users from the Entra ID Identity Protection, which marks an account as being at risk based on the pattern of activity for the account.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\RiskyEvents

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
    Default: UTF8
    
    .EXAMPLE
    Get-RiskyUsers
    Retrieves all risky users.
	
    .EXAMPLE
    Get-RiskyUsers -Encoding utf32
    Retrieves all risky users and exports the output to a CSV file with UTF-32 encoding.
		
    .EXAMPLE
    Get-RiskyUsers -OutputDir C:\Windows\Temp
    Retrieves all risky users and saves the output to the C:\Windows\Temp folder.	
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir = "Output\RiskyEvents",
        [string]$Encoding = "UTF8"
    )

    $authType = Get-GraphAuthType
    if ($authType -eq "Delegated") {
        Connect-MgGraph -Scopes IdentityRiskEvent.Read.All,IdentityRiskyServicePrincipal.Read.All,IdentityRiskyUser.Read.All -NoWelcome > $null
    }

    if (!(test-path $OutputDir)) {
        New-Item -ItemType Directory -Force -Name $OutputDir > $null
        write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
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

    Write-logFile -Message "[INFO] Running Get-RiskyUsers" -Color "Green"
    $results=@();
    $count = 0
    
    try {
        $uri = "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers"
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri

            if ($response.value) {
                foreach ($user in $response.value) {
                    $results += [PSCustomObject]@{
                        Id = $user.Id
                        IsDeleted = $user.IsDeleted
                        IsProcessing = $user.IsProcessing
                        RiskDetail = $user.RiskDetail
                        RiskLastUpdatedDateTime = $user.RiskLastUpdatedDateTime
                        RiskLevel = $user.RiskLevel
                        RiskState = $user.RiskState
                        UserDisplayName = $user.UserDisplayName
                        UserPrincipalName = $user.UserPrincipalName
                        AdditionalProperties = $user.AdditionalProperties -join ", "
                    }

                    $count++
                }
            }
        
            $uri = $response.'@odata.nextLink'
        } while ($uri -ne $null)
    } catch {
        write-logFile -Message "[INFO] Ensure you are connected to Microsoft Graph by running the Connect-MgGraph -Scopes IdentityRiskEvent.Read.All,IdentityRiskyServicePrincipal.Read.All,IdentityRiskyUser.Read.All command before executing this script" -Color "Yellow"
        Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red"
        break
    }

    $date = Get-Date -Format "yyyyMMddHHmm"
    $filePath = "$OutputDir\$($date)-RiskyUsers.csv"

    if ($results.Count -gt 0) {
        $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
        Write-LogFile -Message "[INFO] A total of $count Risky Users found"
        Write-LogFile -Message "[INFO] Output written to $filePath" -Color "Green"
    } else {
        Write-LogFile -Message "[INFO] No Risky Users found" -Color "Yellow"
    }
}

function Get-RiskyDetections {
<#
    .SYNOPSIS
    Retrieves the risky detections from the Entra ID Identity Protection.

    .DESCRIPTION
    Retrieves the risky detections from the Entra ID Identity Protection.

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\RiskyEvents

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
    Default: UTF8
        
    .EXAMPLE
    Get-RiskyDetections
    Retrieves all the risky detections.
	
    .EXAMPLE
    Get-RiskyDetections -Encoding utf32
    Retrieves the risky detections and exports the output to a CSV file with UTF-32 encoding.
		
    .EXAMPLE
    Get-RiskyDetections -OutputDir C:\Windows\Temp
    Retrieves the risky detections and saves the output to the C:\Windows\Temp folder.	
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir= "Output\RiskyEvents",
        [string]$Encoding = "UTF8"
    )

    $authType = Get-GraphAuthType
    if ($authType -eq "Delegated") {
        Connect-MgGraph -Scopes IdentityRiskEvent.Read.All,IdentityRiskyServicePrincipal.Read.All,IdentityRiskyUser.Read.All -NoWelcome > $null
    }

    if (!(test-path $OutputDir)) {
        New-Item -ItemType Directory -Force -Name $OutputDir > $null
        write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
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

    Write-logFile -Message "[INFO] Running Get-RiskyDetections" -Color "Green"
    $results=@();
    $count = 0

    try {
        $uri = "https://graph.microsoft.com/v1.0/identityProtection/riskDetections"
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri

            if ($response.value) {
                foreach ($detection in $response.value) {
                    $results += [PSCustomObject]@{
                        Activity = $detection.Activity
                        ActivityDateTime = $detection.ActivityDateTime
                        AdditionalInfo = $detection.AdditionalInfo
                        CorrelationId = $detection.CorrelationId
                        DetectedDateTime = $detection.DetectedDateTime
                        IPAddress = $detection.IPAddress
                        Id = $detection.Id
                        LastUpdatedDateTime = $detection.LastUpdatedDateTime
                        City = $detection.Location.City
                        CountryOrRegion = $detection.Location.CountryOrRegion
                        State = $detection.Location.State
                        RequestId = $detection.RequestId
                        RiskDetail = $detection.RiskDetail
                        RiskEventType = $detection.RiskEventType
                        RiskLevel = $detection.RiskLevel
                        RiskState = $detection.RiskState
                        DetectionTimingType = $detection.DetectionTimingType
                        Source = $detection.Source
                        TokenIssuerType = $detection.TokenIssuerType
                        UserDisplayName = $detection.UserDisplayName
                        UserId = $detection.UserId
                        UserPrincipalName = $detection.UserPrincipalName
                        AdditionalProperties = $detection.AdditionalProperties -join ", "
                    }
                    $count++
                }
            }

            $uri = $response.'@odata.nextLink'
        } while ($uri -ne $null)
    } catch {
        write-logFile -Message "[INFO] Ensure you are connected to Microsoft Graph by running the Connect-MgGraph -Scopes IdentityRiskEvent.Read.All,IdentityRiskyServicePrincipal.Read.All,IdentityRiskyUser.Read.All command before executing this script" -Color "Yellow"
        Write-LogFile -Message "[ERROR] An error occurred: $($_.Exception.Message)" -Color "Red"
	Write-LogFile -Message "[ERROR (Continued)] Check the below, as the target tenant may not be licenced for this feature $($_.ErrorDetails.Message)" -Color "Red"
        break
    }

    $date = Get-Date -Format "yyyyMMddHHmm"
    $filePath = "$OutputDir\$($date)-RiskyDetections.csv"
    if ($results.Count -gt 0) {
        $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
        Write-LogFile -Message "[INFO] A total of $count Risky Detections found"
        Write-LogFile -Message "[INFO] Output written to $filePath" -Color "Green"
    } else {
        Write-LogFile -Message "[INFO] No Risky Detections found" -Color "Yellow"
    }
}
