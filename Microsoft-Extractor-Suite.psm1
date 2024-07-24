# Set supported TLS methods
[Net.ServicePointManager]::SecurityProtocol = "Tls12, Tls13"

$manifest = Import-PowerShellDataFile "$PSScriptRoot\Microsoft-Extractor-Suite.psd1"
$version = $manifest.ModuleVersion
$host.ui.RawUI.WindowTitle = "Microsoft-Extractor-Suite $version"

$logo=@"
 +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+
 |M|i|c|r|o|s|o|f|t| |E|x|t|r|a|c|t|o|r| |S|u|i|t|e|
 +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+                                                                                                                                                                     
Copyright 2024 Invictus Incident Response
Created by Joey Rentenaar & Korstiaan Stam
"@

Write-Host $logo -ForegroundColor Yellow

$outputDir = "Output"
if (!(test-path $outputDir)) {
	New-Item -ItemType Directory -Force -Name $Outputdir > $null
}

$retryCount = 0 
	
Function StartDate
{
	if (($startDate -eq "") -Or ($null -eq $startDate)) {
		$script:StartDate = [datetime]::Now.ToUniversalTime().AddDays(-90)
		write-LogFile -Message "[INFO] No start date provived by user setting the start date to: $($script:StartDate.ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Yellow"
	}
	else
	{
		$script:startDate = $startDate -as [datetime]
		if (!$script:startDate ) { 
			write-LogFile -Message "[WARNING] Not A valid start date and time, make sure to use YYYY-MM-DD" -Color "Red"
		} 
	}
}

Function StartDateAz
{
	if (($startDate -eq "") -Or ($null -eq $startDate)) {
		$script:StartDate = [datetime]::Now.ToUniversalTime().AddDays(-30)
		write-LogFile -Message "[INFO] No start date provived by user setting the start date to: $($script:StartDate.ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Yellow"
	}
	else
	{
		$script:startDate = $startDate -as [datetime]
		if (!$script:startDate ) { 
			write-LogFile -Message "[WARNING] Not A valid start date and time, make sure to use YYYY-MM-DD" -Color "Red"
		} 
	}
}

function EndDate
{
	if (($endDate -eq "") -Or ($null -eq $endDate)) {
		$script:EndDate = [datetime]::Now.ToUniversalTime()
		write-LogFile -Message "[INFO] No end date provived by user setting the end date to: $($script:EndDate.ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Yellow"
	}

	else {
		$script:endDate = $endDate -as [datetime]
		if (!$endDate) { 
			write-LogFile -Message "[WARNING] Not A valid end date and time, make sure to use YYYY-MM-DD" -Color "Red"
		} 
	}
}

$logFile = "Output\LogFile.txt"
function Write-LogFile([String]$message,$color)
{
	$outputDir = "Output"
	if (!(test-path $outputDir)) {
		New-Item -ItemType Directory -Force -Name $Outputdir > $null
	}

	switch ($color) {
        "Yellow" { [Console]::ForegroundColor = [ConsoleColor]::Yellow }
        "Red" 	 { [Console]::ForegroundColor = [ConsoleColor]::Red }
        "Green"  { [Console]::ForegroundColor = [ConsoleColor]::Green }
        default  { [Console]::ResetColor() }
    }

    [Console]::WriteLine($message)
    [Console]::ResetColor()
    $logToWrite = [DateTime]::Now.ToString() + ": " + $message
    $logToWrite | Out-File -FilePath $LogFile -Append
}

function versionCheck{
	$moduleName = "Microsoft-Extractor-Suite"
	$currentVersionString = $version

	$currentVersion = [Version]$currentVersionString
    $latestVersionString = (Find-Module -Name $moduleName).Version.ToString()
    $latestVersion = [Version]$latestVersionString


	$latestVersion = (Find-Module -Name $moduleName).Version.ToString()

	if ($currentVersion -lt $latestVersion) {
		write-LogFile -Message "`n[INFO] You are running an outdated version ($currentVersion) of $moduleName. The latest version is ($latestVersion), please update to the latest version." -Color "Yellow"
	}
}

function Get-GraphAuthType {
    param (
        [string[]]$RequiredScopes
    )

    $context = Get-MgContext
    if (-not $context) {
        $authType = "none"
        $scopes = @()
    } else {
        $authType = $context | Select-Object -ExpandProperty AuthType
        $scopes = $context | Select-Object -ExpandProperty Scopes
    }

    $missingScopes = @()
    foreach ($requiredScope in $RequiredScopes) {
        if (-not ($scopes -contains $requiredScope)) {
            $missingScopes += $requiredScope
        }
    }

    $joinedScopes = $RequiredScopes -join ","
    switch ($authType) {
        "delegated" {
            if ($missingScopes.Count -gt 0) {
                foreach ($missingScope in $missingScopes) {
                    Write-LogFile -Message "[INFO] Missing Graph scope detected: $missingScope" -Color "Yellow"
                }
                
                Write-LogFile -Message "[INFO] Attempting to re-authenticate with the appropriate scope(s): $joinedScopes" -Color "Green"
                Connect-MgGraph -NoWelcome -Scopes $joinedScopes > $null
            }
        }
        "AppOnly" {
            if ($missingScopes.Count -gt 0) {
                foreach ($missingScope in $missingScopes) {
                    Write-LogFile -Message "[INFO] The connected application is missing Graph scope detected: $missingScope" -Color "Red"
                }
            }
        }
        "none" {
            Write-LogFile -Message "[INFO] No active Connect-MgGraph session found. Attempting to connect with the appropriate scope(s): $joinedScopes" -Color "Green"
            Connect-MgGraph -NoWelcome -Scopes $joinedScopes
        }
    }

    return @{
        AuthType = $authType
        Scopes = $scopes
        MissingScopes = $missingScopes
    }
}

function Merge-OutputFiles {
    param (
        [Parameter(Mandatory)][string]$OutputDir,
        [Parameter(Mandatory)][string]$OutputType,
        [string]$MergedFileName
    )

    $outputDirMerged = Join-Path -Path $OutputDir -ChildPath "Merged"
    If (!(Test-Path $outputDirMerged)) {
        Write-LogFile -Message "[INFO] Creating the following directory: $outputDirMerged"
        New-Item -ItemType Directory -Force -Path $outputDirMerged > $null
    }

	$mergedPath = Join-Path -Path $outputDirMerged -ChildPath $MergedFileName
	
    switch ($OutputType) {
        'CSV' {
			Get-ChildItem $OutputDir -Filter *.csv | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $mergedPath -NoTypeInformation -Append -Encoding UTF8
            Write-LogFile -Message "[INFO] CSV files merged into $mergedPath"
        }
        'JSON' {
			$allJsonObjects = Get-ChildItem $OutputDir -Filter *.json | ForEach-Object {
                Get-Content -Path $_.FullName -Raw | ConvertFrom-Json
            }
            $allJsonObjects | ConvertTo-Json -Depth 100 | Set-Content $mergedPath
            Write-Host "[INFO] JSON files merged into $mergedPath"
        }
        default {
            Write-LogFile -Message "[ERROR] Unsupported file type specified: $OutputType" -Color Red
        }
    }
}

versionCheck

Export-ModuleMember -Function * -Alias * -Variable * -Cmdlet *
