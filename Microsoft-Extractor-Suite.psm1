# Set supported TLS methods
[Net.ServicePointManager]::SecurityProtocol = "Tls12, Tls13"

$manifest = Import-PowerShellDataFile "$PSScriptRoot\Microsoft-Extractor-Suite.psd1"
$version = $manifest.ModuleVersion
$host.ui.RawUI.WindowTitle="Microsoft-Extractor-Suite $version"

$logo=@"

 +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+
 |M|i|c|r|o|s|o|f|t| |E|x|t|r|a|c|t|o|r| |S|u|i|t|e|
 +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+
                                                                                                                                                                            
Copyright (c) 2023 Invictus Incident Response
Created by Joey Rentenaar & Korstiaan Stam
"@

Write-Host $logo -ForegroundColor Yellow

$outputDir = "Output"
if (!(test-path $outputDir)) {
	New-Item -ItemType Directory -Force -Name $Outputdir | Out-Null
}
	
Function StartDate
{
	if (($startDate -eq "") -Or ($null -eq $startDate)) {
		$startDate = [datetime]::Now.ToUniversalTime().AddDays(-90)
		$startDate = Get-Date $startDate -Format "yyyy-MM-dd HH:mm:ss"
		write-LogFile -Message "[INFO] No start date provived by user setting the start date to: $startDate" -Color "Yellow"
		
		$script:StartDate = Get-Date $startDate -Format "yyyy-MM-dd HH:mm:ss"
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
		$endDate = [datetime]::Now.ToUniversalTime()
		$endDate = Get-Date $endDate -Format "yyyy-MM-dd HH:mm:ss"
		write-LogFile -Message "[INFO] No end date provived by user setting the end date to: $endDate" -Color "Yellow"
		
		$script:endDate = Get-Date $endDate -Format "yyyy-MM-dd HH:mm:ss"
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
	if ($color -eq "Yellow")
	{
		Write-host $message -ForegroundColor Yellow
	}
	elseif ($color -eq "Red")
	{
		Write-host $message -ForegroundColor Red
	}
	elseif ($color -eq "Green")
	{
		Write-host $message -ForegroundColor Green
	}
	else {
		Write-host $message
	}
	
	$logToWrite = [DateTime]::Now.ToString() + ": " + $message
	$logToWrite | Out-File $LogFile -Append
}
