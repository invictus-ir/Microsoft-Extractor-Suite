Function Connect-M365
{
	versionCheck
	Connect-ExchangeOnline > $null
}

Function Connect-Azure
{
	versionCheck
	Connect-AzureAD > $null
}

Function Connect-AzureAZ
{
	versionCheck
	Connect-AzAccount > $null
}

