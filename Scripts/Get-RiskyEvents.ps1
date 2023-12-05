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
        [string]$OutputDir,
        [string]$Encoding
    )

    if ($Encoding -eq "" ){
        $Encoding = "UTF8"
    }

    try {
        $areYouConnected = Get-MgRiskyUser -ErrorAction stop
    }
    catch {
        Write-logFile -Message "[WARNING] You must call Connect-GraphAPI before running this script" -Color "Red"
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
    $results = Get-MgRiskyUser -All

    $filePath = "$OutputDir\RiskyUsers.csv"
    $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
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
        [string]$OutputDir,
        [string]$Encoding
    )

    try {
        $areYouConnected = Get-MgRiskDetection -ErrorAction stop
    }
    catch {
        Write-logFile -Message "[WARNING] You must call Connect-GraphAPI before running this script" -Color "Red"
        break
    }

    if ($Encoding -eq "" ){
        $Encoding = "UTF8"
    }

    if ($OutputDir -eq "" ){
        $OutputDir = "Output\UserInfo\"
        if (!(test-path $OutputDir)) {
            write-logFile -Message "[INFO] Creating the following directory: $OutputDir"
            New-Item -ItemType Directory -Force -Name $OutputDir | Out-Null
        }
    }

    Write-logFile -Message "[INFO] Running Get-RiskyDetections" -Color "Green"
    $results = Get-MgRiskDetection -All

    $filePath = "$OutputDir\RiskyDetections.csv"
    $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
    Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green"
}



