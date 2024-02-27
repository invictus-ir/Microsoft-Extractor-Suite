Function Connect-M365
{
	Connect-ExchangeOnline -Showbanner:$false -ShowProgress:$true
}

Function Connect-Azure
{
	Connect-AzureAD | Out-Null
}

Function Connect-AzureAZ
{
	Connect-AzAccount | Out-Null
}

Function Connect-GraphAPI
{
	Connect-MgGraph -Scopes AuditLog.Read.All, Directory.Read.All -NoWelcome
}
