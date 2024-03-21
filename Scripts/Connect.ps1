Function Connect-M365
{
	versionCheck
	Connect-ExchangeOnline -Showbanner:$false -ShowProgress:$true
}

Function Connect-Azure
{
	versionCheck
	Connect-AzureAD | Out-Null
}

Function Connect-AzureAZ
{
	versionCheck
	Connect-AzAccount | Out-Null
}
