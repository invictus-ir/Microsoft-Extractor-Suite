
Function Get-ConditionalAccess {
<#
    .SYNOPSIS
    Retrieves all the conditional access policies. 

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
    Get-ConditionalAccess
    Retrieves all risky users.
	
    .EXAMPLE
	Get-ConditionalAccess -Encoding utf32
	Retrieves all risky users and exports the output to a CSV file with UTF-32 encoding.
		
	.EXAMPLE
	Get-ConditionalAccess -OutputDir C:\Windows\Temp
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
        $areYouConnected = get-MgIdentityConditionalAccessPolicy -ErrorAction stop
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

    Write-logFile -Message "[INFO] Running Get-ConditionalAccess" -Color "Green"
    $results=@();

    get-MgIdentityConditionalAccessPolicy -all | ForEach-Object {
        $myObject = [PSCustomObject]@{
            DisplayName         = "-"
            CreatedDateTime     = "-"
            Description         = "-"
            Id                  = "-"
            ModifiedDateTime    = "-"
            State               = "-"
        }

        $myobject.DisplayName = $_.DisplayName
        $myobject.CreatedDateTime = $_.CreatedDateTime
        $myobject.Description = $_.Description
        $myobject.Id = $_.Id
        $myobject.ModifiedDateTime = $_.ModifiedDateTime
        $myobject.State = $_.State
        $results+= $myObject;

    }

    $filePath = "$OutputDir\ConditionalAccessPolicy.csv"
    $results | Export-Csv -Path $filePath -NoTypeInformation -Encoding $Encoding
    Write-logFile -Message "[INFO] Output written to $filePath" -Color "Green" 
}