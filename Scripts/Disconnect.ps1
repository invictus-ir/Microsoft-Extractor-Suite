Function Disconnect-M365
{
    Disconnect-Exchangeonline -Confirm:$false > $null;
    Remove-Module ExchangeOnlineManagement -Force > $null;
}

Function Disconnect-Azure
{
    Disconnect-MgGraph > $null;
    Disconnect-AzureAD > $null;
    Remove-Module AzureADPreview -Force > $null;
    Remove-Module Microsoft.Graph -Force > $null;
}

Function Disconnect-AzureAZ
{
    Clear-AzContext -Force > $null;
    Disconnect-AzAccount -Force > $null;
    Remove-Module Az -Force > $null;
}

