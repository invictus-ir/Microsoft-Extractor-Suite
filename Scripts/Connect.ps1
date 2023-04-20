Function Connect-M365
{
	Connect-ExchangeOnline -Showbanner:$false -ShowProgress:$true
}

Function Connect-Azure
{
	Connect-AzureAD | Out-Null
}