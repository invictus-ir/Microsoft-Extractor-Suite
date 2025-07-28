Function Connect-M365
{
    PARAM(
        [string]
        $ConnectionUri,
        [string]
        $AzureADAuthorizationEndpointUri,
        [ValidateSet('O365China', 'O365Default', 'O365GermanyCloud', 'O365USGovDoD', 'O365USGovGCCHigh')]
        [string]
        $ExchangeEnvironmentName,
        [string[]]
        $PSSessionOptions,
        [string]
        $DelegatedOrganization,
        [string]
        $Prefix,
        [string[]]
        $CommandName,
        [string[]]
        $FormatTypeName,
        [string]
        $AccessToken,
        [string]
        $AppId,
        [switch]
        $BypassMailboxAnchoring,
        [X509Certificate]
        $Certificate,
        [string]
        $CertificateFilePath,
        [SecureString]
        $CertificatePassword,
        [string]
        $CertificateThumbprint,
        [PSCredential]
        $Credential,
        [switch]
        $Device,
        [switch]
        $EnableErrorReporting,
        [switch]
        $InlineCredential,
        [string]
        $LogDirectoryPath,
        [string]
        $LogLevel,
        [switch]
        $ManagedIdentity,
        [string]
        $ManagedIdentityAccountId,
        [string]
        $Organization,
        [int]
        $PageSize,
        [switch]
        $ShowBanner,
        [X509Certificate]
        $SigningCertificate,
        [switch]
        $SkipLoadingCmdletHelp,
        [switch]
        $SkipLoadingFormatData,
        [Boolean]
        $TrackPerformance,
        [Boolean]
        $UseMultithreading,
        [string]
        $UserPrincipalName,
        [Switch]
        $UseRPSSession
    )
    versionCheck
    Connect-ExchangeOnline @PSBoundParameters > $null;
}

Function Connect-AzureAZ
{
    PARAM(
        [String]
        $AccessToken ,
        [String]
        $AccountId ,
        [String]
        $ApplicationId ,
        [String]
        $AuthScope ,
        [SecureString]
        $CertificatePassword,
        [String]
        $CertificatePath ,
        [String]
        $CertificateThumbprint ,
        [String]
        $ContextName ,
        [PSCredential]
        $Credential,
        [string]
        $DefaultProfile ,
        [String]
        $Environment ,
        [String]
        $FederatedToken ,
        [switch]
        $Force ,
        [String]
        $GraphAccessToken ,
        [switch]
        $Identity,
        [String]
        $KeyVaultAccessToken ,
        [int]
        $MaxContextPopulation,
        [String]
        $MicrosoftGraphAccessToken ,
        [ValidateSet('CurrentUser', 'Process')]
        [string]
        $Scope,
        [switch]
        $SendCertificateChain,
        [switch]
        $ServicePrincipal,
        [switch]
        $SkipContextPopulation ,
        [switch]
        $SkipValidation ,
        [String]
        $Subscription ,
        [String]
        $Tenant ,
        [switch]
        $UseDeviceAuthentication,
        [switch]
        $Confirm,
        [switch]
        $WhatIf
    )
    versionCheck
    Connect-AzAccount @PSBoundParameters > $null;
}