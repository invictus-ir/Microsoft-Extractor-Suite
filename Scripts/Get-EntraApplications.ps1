function Get-EntraApplications {
    <#
    .SYNOPSIS
    Gets of current Azure Entra ID applications.

    .DESCRIPTION
    TheGet-EntraApplications GraphAPI cmdlet collects the current state of .

	.PARAMETER LogLevel
    Specifies the level of logging:
    None: No logging
    Minimal: Critical errors only
    Standard: Normal operational logging
	Debug: Verbose logging for debugging purposes
    Default: Standard

    .PARAMETER OutputDir
    outputDir is the parameter specifying the output directory.
    Default: The output will be written to: Output\EntraID\{date_Applications}\{timestamp}-Applications.json

    .PARAMETER Encoding
    Encoding is the parameter specifying the encoding of the JSON output file.
    Default: UTF8

    .EXAMPLE
    Get-EntraApplications
    Get all Entra applications
#>
    [CmdletBinding()]
    param(
        [string]$OutputDir,
        [string]$Encoding = "UTF8",
        [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
        [string]$LogLevel = 'Standard'
	)

    Init-Logging
    Write-LogFile -Message "=== Starting Application Collection ===" -Color "Cyan" -Level Standard
    Init-OutputDir -Component "EntraID" -SubComponent "Applications" -FilePostfix "Applications"
	$requiredScopes = @("Application.Read.All")
    Check-GraphContext -RequiredScopes $requiredScopes

    Write-LogFile -Message "[INFO] Collecting EntraID Applications"
    $applications = Get-MgApplication
    $results = @()
    foreach ($app in $applications) {
        $owners = Get-MgApplicationOwner -ApplicationId $app.Id
        $object = [PSCustomObject]@{
            DisplayName = $app.DisplayName
            Id = $app.Id
            AppId  = $app.AppId
            CreatedDateTime = $app.CreatedDateTime
            OwnerIds =  $owners | ForEach-Object { $_.Id  }  | join-String -Separator ", "
            OwnerDisplayNames = ""
        }

        if ($owners.AdditionalProperties) {
            $object.OwnerDisplayNames = $owners.AdditionalProperties | ForEach-Object { $_['displayName'] }  | join-String -Separator ", "
        }
        $results += $object
    }
    $results | Export-Csv -Path $script:outputFile -NoTypeInformation -Encoding $Encoding

    $summary = @{
		TotalApplications = $results.Count
	}
	Write-Summary -Summary $summary
}