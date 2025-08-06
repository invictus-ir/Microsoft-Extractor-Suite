param (
    [switch]$NoWelcome = $false
)

# Set supported TLS methods
[Net.ServicePointManager]::SecurityProtocol = "Tls12, Tls13"

$manifest = Import-PowerShellDataFile "$PSScriptRoot\Microsoft-Extractor-Suite.psd1"
$version = $manifest.ModuleVersion
$host.ui.RawUI.WindowTitle = "Microsoft-Extractor-Suite $version"

if (-not $NoWelcome) {
    $logo=@"
 +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+
 |M|i|c|r|o|s|o|f|t| |E|x|t|r|a|c|t|o|r| |S|u|i|t|e|
 +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+                                                                                                                                                                     
Copyright 2025 Invictus Incident Response
Created by Joey Rentenaar & Korstiaan Stam
"@

    Write-Host $logo -ForegroundColor Yellow
}

$outputDir = "Output"
if (!(test-path $outputDir)) {
	New-Item -ItemType Directory -Force -Name $Outputdir > $null
}

$retryCount = 0 
	
Function StartDate {
    param([switch]$Quiet)
    
    if (($startDate -eq "") -Or ($null -eq $startDate)) {
        $script:StartDate = [datetime]::Now.ToUniversalTime().AddDays(-90)
        if (-not $Quiet) {
            Write-LogFile -Message "[INFO] No start date provided by user setting the start date to: $($script:StartDate.ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Yellow"
        }
    }
    else {
        $script:startDate = $startDate -as [datetime]
        if (!$script:startDate -and -not $Quiet) { 
            Write-LogFile -Message "[WARNING] Not A valid start date and time, make sure to use YYYY-MM-DD" -Color "Red"
        } 
    }
}

Function StartDateUAL {
    param([switch]$Quiet)
    
    if (($startDate -eq "") -Or ($null -eq $startDate)) {
        $script:StartDate = [datetime]::Now.ToUniversalTime().AddDays(-180)
        if (-not $Quiet) {
            Write-LogFile -Message "[INFO] No start date provided by user setting the start date to: $($script:StartDate.ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Yellow"
        }
    }
    else {
        $script:startDate = $startDate -as [datetime]
        if (!$script:startDate -and -not $Quiet) { 
            Write-LogFile -Message "[WARNING] Not A valid start date and time, make sure to use YYYY-MM-DD" -Color "Red"
        } 
    }
}

Function StartDateAz {
    param([switch]$Quiet)
    
    if (($startDate -eq "") -Or ($null -eq $startDate)) {
        $script:StartDate = [datetime]::Now.ToUniversalTime().AddDays(-30)
        if (-not $Quiet) {
            Write-LogFile -Message "[INFO] No start date provided by user setting the start date to: $($script:StartDate.ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Yellow"
        }
    }
    else {
        $script:startDate = $startDate -as [datetime]
        if (!$script:startDate -and -not $Quiet) { 
            Write-LogFile -Message "[WARNING] Not A valid start date and time, make sure to use YYYY-MM-DD" -Color "Red"
        } 
    }
}

function EndDate {
    param([switch]$Quiet)
    
    if (($endDate -eq "") -Or ($null -eq $endDate)) {
        $script:EndDate = [datetime]::Now.ToUniversalTime()
        if (-not $Quiet) {
            Write-LogFile -Message "[INFO] No end date provided by user setting the end date to: $($script:EndDate.ToString("yyyy-MM-ddTHH:mm:ssK"))" -Color "Yellow"
        }
    }
    else {
        $script:endDate = $endDate -as [datetime]
        if (!$endDate -and -not $Quiet) { 
            Write-LogFile -Message "[WARNING] Not A valid end date and time, make sure to use YYYY-MM-DD" -Color "Red"
        } 
    }
}

[Flags()]
enum LogLevel {
    None     = 0
    Minimal  = 1
    Standard = 2
    Debug    = 3
}

$script:LogLevel = [LogLevel]::Standard

function Set-LogLevel {
    param (
        [LogLevel]$Level
    )
    $script:LogLevel = $Level
}


$logFile = "Output\LogFile.txt"
function Write-LogFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [string]$Color,
        [switch]$NoNewLine,
        [LogLevel]$Level = [LogLevel]::Standard
    )

    if ($Level -gt $script:LogLevel) {
        return
    }

    if ($script:LogLevel -eq [LogLevel]::None) {
        return
    }

	$outputDir = "Output"
	if (!(test-path $outputDir)) {
		New-Item -ItemType Directory -Force -Name $Outputdir > $null
	}

    if(!$color -and $Level -eq [LogLevel]::Debug) {
        $color = "Yellow"
    }

	switch ($color) {
        "Yellow" { [Console]::ForegroundColor = [ConsoleColor]::Yellow }
        "Red" 	 { [Console]::ForegroundColor = [ConsoleColor]::Red }
        "Green"  { [Console]::ForegroundColor = [ConsoleColor]::Green }
        "Cyan"   { [Console]::ForegroundColor = [ConsoleColor]::Cyan }
        "White"  { [Console]::ForegroundColor = [ConsoleColor]::White }
        default  { [Console]::ResetColor() }
    }

    $logMessage = if (!$NoTimestamp) {
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    } else {
        $Message
    }

    if ($NoNewLine) {
        [Console]::Write($Message)
    } else {
        [Console]::WriteLine($Message)
    }

    [Console]::ResetColor()
    $logMessage | Out-File -FilePath $LogFile -Append
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
            if ($RequiredScopes -contains "Mail.ReadWrite") {
                Write-LogFile -Message "[WARNING] 'Mail.ReadWrite' is being requested under a delegated authentication type. 'Mail.ReadWrite' permissions only work when authenticating with an application." -Color "Yellow"
            }
            elseif ($missingScopes.Count -gt 0) {
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
            if ($RequiredScopes -contains "Mail.ReadWrite") {
                Write-LogFile -Message "[WARNING] 'Mail.ReadWrite' is being requested under a delegated authentication type. 'Mail.ReadWrite' permissions only work when authenticating with an application." -Color "Yellow"
            }
            else {
                Write-LogFile -Message "[INFO] No active Connect-MgGraph session found. Attempting to connect with the appropriate scope(s): $joinedScopes" -Color "Green"
                Connect-MgGraph -NoWelcome -Scopes $joinedScopes
            }
        }
    }

    return @{
        AuthType = $authType
        Scopes = $scopes
        MissingScopes = $missingScopes
    }
}

function Init-Logging {
    Set-LogLevel -Level ([LogLevel]::$LogLevel)
	$isDebugEnabled = $script:LogLevel -eq [LogLevel]::Debug

	$script:scriptStartedAt = Get-Date

	if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] PowerShell Version: $($PSVersionTable.PSVersion)" -Level Debug
        Write-LogFile -Message "[DEBUG] Input parameters:" -Level Debug
        foreach ($param in $PSBoundParameters.GetEnumerator()) {
            Write-LogFile -Message "[DEBUG]   $($param.Key): $($param.Value)" -Level Debug
        }

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

function Check-GraphContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object]$RequiredScopes
    )

    $graphAuth = Get-GraphAuthType -RequiredScopes $RequiredScopes

    if ($isDebugEnabled) {
        Write-LogFile -Message "[DEBUG] Graph authentication completed" -Level Debug
        try {
            $context = Get-MgContext
            if ($context) {
                Write-LogFile -Message "[DEBUG] Graph context information:" -Level Debug
                Write-LogFile -Message "[DEBUG]   Account: $($context.Account)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Environment: $($context.Environment)" -Level Debug
                Write-LogFile -Message "[DEBUG]   TenantId: $($context.TenantId)" -Level Debug
                Write-LogFile -Message "[DEBUG]   Scopes: $($context.Scopes -join ', ')" -Level Debug
            }
        } catch {
            Write-LogFile -Message "[DEBUG] Could not retrieve Graph context details" -Level Debug
        }
    }
}

function Init-OutputDir {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Component,
        [string]$SubComponent = "",
        [Parameter(Mandatory=$true)]
        [string]$FilePostfix
    )

	$date = [datetime]::Now.ToString('yyyyMMdd')
	if ($OutputDir -eq "" ){
		$OutputDir = "Output\$Component\$($date)"
		if ($SubComponent -ne "") {
            $OutputDir += "-$SubComponent"
        }
		if (!(test-path $OutputDir)) {
		    Write-LogFile -Message "[DEBUG] Creating output directory: $OutputDir" -Level Debug
			New-Item -ItemType Directory -Force -path $OutputDir > $null
		}
	}
	else {
        if (!(Test-Path -Path $OutputDir)) {
            Write-LogFile -Message "[Error] Custom directory invalid: $OutputDir" -Level Minimal -Color "Red"
            return
        }
    }

    Write-LogFile -Message "[DEBUG] Using output directory: $OutputDir" -Level Debug
    $filename = "$($date)-$FilePostfix.csv"
	$script:outputFile = Join-Path $OutputDir $filename
}

function Write-Summary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object]$Summary
    )

    Write-LogFile -Message "`n=== Summary ===" -Color "Cyan" -Level Standard
    foreach ($param in $Summary.GetEnumerator()) {
        if ($param.value -is [hashtable] -or $param.value -is [System.Collections.Specialized.OrderedDictionary]) {
            Write-LogFile -Message "$($param.key):" -Level Standard
            foreach($subitem in $param.value.GetEnumerator()) {
                Write-LogFile -Message "  $($subitem.key): $($subitem.value)" -Level Standard
            }
            Write-LogFile -Message " " -Level Standard
        } else {
            Write-LogFile -Message "$($param.key): $($param.value)" -Level Standard
        }
    }

    $ProcessingTime = (Get-Date) - $script:ScriptStartedAt
    Write-LogFile -Message "`nExport Details:" -Level Standard
    Write-LogFile -Message "  Output File: $script:outputFile" -Level Standard
    Write-LogFile -Message "  Processing Time: $($ProcessingTime.ToString('mm\:ss'))" -Color "Green" -Level Standard
    Write-LogFile -Message "===================================" -Color "Cyan" -Level Standard


}

function Merge-OutputFiles {
    param (
        [Parameter(Mandatory)][string]$OutputDir,
        [Parameter(Mandatory)][string]$OutputType,
        [string]$MergedFileName,
        [switch]$SofElk
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
        'SOF-ELK' {
			Get-ChildItem $OutputDir -Filter *.json | Select-Object -ExpandProperty FullName | ForEach-Object { Get-Content -Path $_ | Where-Object { $_.Trim() -ne "" } } | Out-File -Append $mergedPath -Encoding UTF8 
            Write-LogFile -Message "[INFO] SOF-ELK files merged into $mergedPath"
        }
        'JSON' {           
            "[" | Set-Content $mergedPath -Encoding UTF8

            $firstFile = $true
            Get-ChildItem $OutputDir -Filter *.json | ForEach-Object {
                $content = Get-Content -Path $_.FullName -Raw
                
                $content = $content.Trim()
                if ($content.StartsWith('[')) {
                    $content = $content.Substring(1)
                }
                if ($content.EndsWith(']')) {
                    $content = $content.Substring(0, $content.Length - 1)
                }
                $content = $content.Trim()

                if (-not $firstFile -and $content) {
                    Add-Content -Path $mergedPath -Value "," -Encoding UTF8 -NoNewline
                }

                if ($content) {
                    Add-Content -Path $mergedPath -Value $content -Encoding UTF8 -NoNewline
                    $firstFile = $false
                }
            }
            "]" | Add-Content $mergedPath -Encoding UTF8
            Write-LogFile -Message "[INFO] JSON files merged into $mergedPath"
            
        }
        'JSONL' {
            $jsonlFiles = Get-ChildItem -Path $OutputDir -Filter *.jsonl
            if ($jsonlFiles.Count -eq 0) {
                Write-LogFile -Message "[ERROR] No JSONL files found in the specified directory: $OutputDir" -Color Red
                return
            }

            $mergedContent = @()
            foreach ($file in $jsonlFiles) {
                $content = Get-Content -Path $file.FullName -Raw
                $mergedContent += $content.Trim()
            }

            Set-Content -Path $mergedPath -Value ($mergedContent -join "`n") -Encoding UTF8
            Write-LogFile -Message "[INFO] JSONL files merged into $mergedPath"
        }
        default {
            Write-LogFile -Message "[ERROR] Unsupported file type specified: $OutputType" -Color Red
        }
    }
}

versionCheck

Export-ModuleMember -Function * -Alias * -Variable * -Cmdlet *
