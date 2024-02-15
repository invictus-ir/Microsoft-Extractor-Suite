function Get-RiskyUsers {
<#
    .SYNOPSIS
    Retrieves the risky users. 

    .DESCRIPTION
    Retrieves the risky users from the Entra ID Identity Protection, which marks an account as being at risk based on the pattern of activity for the account.
    The output will be written to: Output\UserInfo\

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\UserInfo

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
    Default: UTF8

    .PARAMETER Application
    Application is the parameter specifying App-only access (access without a user) for authentication and authorization.
    Default: Delegated access (access on behalf a user)
    
    .EXAMPLE
    Get-RiskyUsers
    Retrieves all risky users.

    .EXAMPLE
    Get-RiskyUsers -Application
    Retrieves all risky users via application authentication.
	
    .EXAMPLE
    Get-RiskyUsers -Encoding utf32
    Retrieves all risky users and exports the output to a CSV file with UTF-32 encoding.
		
    .EXAMPLE
    Get-RiskyUsers -OutputDir C:\Windows\Temp
    Retrieves all risky users and saves the output to the C:\Windows\Temp folder.	
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir,
        [string]$Encoding,
        [switch]$Application
    )

    if ($Encoding -eq "" ){
        $Encoding = "UTF8"
    }

    if (!($Application.IsPresent)) {
        Connect-MgGraph -Scopes IdentityRiskEvent.Read.All -NoWelcome
    }

    try {
        $areYouConnected = Get-MgRiskyUser -ErrorAction stop
    }
    catch {
        Write-logFile -Message "[WARNING] You must call Connect-GraphAPI -Scopes IdentityRiskyUser.Read.All before running this script" -Color "Red"
        break
    }

    if ($OutputDir -eq "" ){
        $OutputDir = "Output\UserInfo"
        if (!(test-path $OutputDir)) {
            write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
            New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
        }
    }

    Write-logFile -Message "[INFO] Running Get-RiskyUsers" -Color "Green"
    $results=@();
    $count = 0

    Get-MgRiskyUser -All | ForEach-Object {
        $myObject = [PSCustomObject]@{
            History                           = "-"
            Id                                = "-"
            IsDeleted                         = "-"
            IsProcessing                      = "-"
            RiskDetail                        = "-"
            RiskLastUpdatedDateTime           = "-"
            RiskLevel                         = "-"
            RiskState                         = "-"
            UserDisplayName                   = "-"
            UserPrincipalName                 = "-"
            AdditionalProperties              = "-"
        }

        $myobject.History = $_.History
        $myobject.Id = $_.Id
        $myobject.IsDeleted = $_.IsDeleted
        $myobject.IsProcessing = $_.IsProcessing
        $myobject.RiskDetail = $_.RiskDetail
        $myobject.RiskLastUpdatedDateTime = $_.RiskLastUpdatedDateTime
        $myobject.RiskLevel = $_.RiskLevel
        $myobject.RiskState = $_.RiskState
        $myobject.UserDisplayName = $_.UserDisplayName
        $myobject.UserPrincipalName = $_.UserPrincipalName
        $myobject.AdditionalProperties = $_.AdditionalProperties | out-string

        $results+= $myObject;
        $count = $count +1
    }

    $filePath = "$OutputDir\RiskyUsers.csv"
    $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
    Write-logFile -Message "[INFO] A total of $count Risky Users found"
    Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green"
}

function Get-RiskyDetections {
<#
    .SYNOPSIS
    Retrieves the risky detections from the Entra ID Identity Protection.

    .DESCRIPTION
    Retrieves the risky detections from the Entra ID Identity Protection.
    The output will be written to: Output\UserInfo\

    .PARAMETER OutputDir
    OutputDir is the parameter specifying the output directory.
    Default: Output\UserInfo

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the CSV output file.
    Default: UTF8

    .PARAMETER Application
    Application is the parameter specifying App-only access (access without a user) for authentication and authorization.
    Default: Delegated access (access on behalf a user)
        
    .EXAMPLE
    Get-RiskyDetections
    Retrieves all the risky detections.

    .EXAMPLE
    Get-RiskyDetections -Application
    Retrieves all the risky detections via application authentication.
	
    .EXAMPLE
    Get-RiskyDetections -Encoding utf32
    Retrieves the risky detections and exports the output to a CSV file with UTF-32 encoding.
		
    .EXAMPLE
    Get-RiskyDetections -OutputDir C:\Windows\Temp
    Retrieves the risky detections and saves the output to the C:\Windows\Temp folder.	
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir,
        [string]$Encoding,
        [switch]$Application
    )

    if (!($Application.IsPresent)) {
        Connect-MgGraph -Scopes IdentityRiskEvent.Read.All -NoWelcome
    }

    try {
        $areYouConnected = Get-MgRiskDetection -ErrorAction stop
    }
    catch {
        Write-logFile -Message "[WARNING] You must call Connect-GraphAPI -Scopes IdentityRiskEvent.Read.All before running this script" -Color "Red"
        break
    }

    if ($Encoding -eq "" ){
        $Encoding = "UTF8"
    }

    if ($OutputDir -eq "" ){
        $OutputDir = "Output\UserInfo"
        if (!(test-path $OutputDir)) {
            write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
            New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
        }
    }

    Write-logFile -Message "[INFO] Running Get-RiskyDetections" -Color "Green"
    $results=@();
    $count = 0
    Get-MgRiskDetection -All | ForEach-Object {
        $myObject = [PSCustomObject]@{
            Activity                        = "-"
            ActivityDateTime                = "-"
            AdditionalInfo                  = "-"
            CorrelationId                   = "-"
            DetectedDateTime                = "-"
            IPAddress                       = "-"
            Id                              = "-"
            LastUpdatedDateTime             = "-"
            City                            = "-"
            CountryOrRegion                 = "-"
            State                           = "-"
            RequestId                       = "-"
            RiskDetail                      = "-"
            RiskEventType                   = "-"
            RiskLevel                       = "-"
            riskState                       = "-"
            detectionTimingType             = "-"
            Source                          = "-"
            TokenIssuerType                 = "-"
            UserDisplayName                 = "-"
            UserId                          = "-"
            UserPrincipalName               = "-"
            AdditionalProperties            = "-"
        }

        $myobject.Activity = $_.Activity
        $myobject.ActivityDateTime = $_.ActivityDateTime
        $myobject.AdditionalInfo = $_.AdditionalInfo
        $myobject.CorrelationId = $_.CorrelationId
        $myobject.DetectedDateTime = $_.DetectedDateTime
        $myobject.IPAddress = $_.IPAddress
        $myobject.Id = $_.Id
        $myobject.LastUpdatedDateTime = $_.LastUpdatedDateTime
        $myobject.City = $_.Location.City | out-string
        $myobject.CountryOrRegion = $_.Location.CountryOrRegion | out-string
        $myobject.State = $_.Location.State | out-string
        $myobject.RequestId = $_.RequestId
        $myobject.RiskDetail = $_.RiskDetail
        $myobject.RiskEventType = $_.RiskEventType
        $myobject.RiskLevel = $_.RiskLevel
        $myobject.riskState = $_.riskState
        $myobject.detectionTimingType = $_.detectionTimingType
        $myobject.Source = $_.Source
        $myobject.TokenIssuerType = $_.TokenIssuerType
        $myobject.UserDisplayName = $_.UserDisplayName
        $myobject.UserId = $_.UserId
        $myobject.UserPrincipalName = $_.UserPrincipalName
        $myobject.AdditionalProperties = $_.AdditionalProperties | out-string

        $results+= $myObject;
        $count = $count +1
    }

    $filePath = "$OutputDir\RiskyDetections.csv"
    $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
    Write-logFile -Message "[INFO] A total of $count Risky Detections found"
    Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green"
}
