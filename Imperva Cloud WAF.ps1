#
# Imperva Cloud WAF - An Adaptable Application Driver for Venafi
#
$Script:AdaptableAppVer = '202608111632'
$Script:AdaptableAppDrv = 'Imperva Cloud WAF'

<#

Adaptable Application Fields are defined one per line below in the following format:
 [Field Name] | [Field Label] | [Binary/Boolean Flags]
    flag #1: Enabled? (Will not be displayed if 0)
    Flag #2: Can be set at policy level?
    Flag #3: Mandatory?

You cannot add to, change, or remove the field names. Enable or disable as needed.

-----BEGIN FIELD DEFINITIONS-----
Text1|Imperva Site ID|101
Text2|Text Label #2|000
Text3|Imperva Base Folder|110
Text4|Imperva Discovered Folder|110
Text5|Imperva Driver Options|110
Option1|Debug Imperva Driver|110
Option2|Discover Sub Accounts|110
Passwd|Password Field|000
-----END FIELD DEFINITIONS-----

#>

# These options can be modified by passing in text strings (Text5)
#
# APIBody:      Output the masked body of API calls to the debug logs
# APICalls:     Output REST API calls for both Imperva and Venafi
# APICallI:     Output REST API calls for Imperva
# APICallV:     Output REST API calls for Venafi
# APIReplies:   Output API replies from both Imperva and Venafi
# APIReplyI:    Output API replies from Imperva
# APIReplyV:    Output API replies from Venafi
# CallFunction: Log all calls to functions in the driver
# Discovered:   Output the list of discovered apps returned to Venafi
# DumpGeneral:  Output the masked General hashtable to the debug logs
# DumpSpecific: Output the unredacted Specific hashtable to the debug logs
# UnmaskFields: This will unmask sensitive fields in the debug output
# WAFErrors:    Log non-fatal WAF errors when retrieving certificates from
#               the WAF front-end (API Errors are always logged)

$Script:DebugOptions = @{
    APIBody      = $false
    APICallV     = $false
    APICallI     = $false
    APIReplyV    = $false
    APIReplyI    = $false
    Discovered   = $false
    DumpGeneral  = $false
    DumpSpecific = $false
    CallFunction = $false
    RedactData   = $true
    WAFBadRC     = $false
    WAFErrors    = $false
}

$Script:SensitiveFields = (
    'Password',
    'UserPass',
    'AuxPass',
    'VarPass',
    'UserPrivKey',
    'PassPhrase',
    'Private_Key',
    'Certificate'
)

# Track Venafi authorization internally to remove VenafiPS dependencies
$Script:vAuth = $null

# If the website has been moved between subaccounts on Imperva then attempt to just
# move the application to the correct device rather than throwing a validation error
$Script:MoveWebSites = $true    # not currently implemented

# Stage 800: OPTIONAL FUNCTION
# Provision each of the certificates in the CA trust chain
# This function supports the "ResumeLater" result code
function Install-Chain
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    return @{ Result="NotUsed"; }
}

# Stage 801: OPTIONAL FUNCTION (unless Install-Certificate has not been implemented)
# Provision the private key associated with the certificate
# This function supports the "ResumeLater" result code
function Install-PrivateKey
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    return @{ Result="NotUsed"; }
}

# Stage 802: MANDATORY FUNCTION (unless Install-PrivateKey has been implemented)
# Provision the certificate. Can also provision the chain and private key.
# This function supports the "ResumeLater" result code
function Install-Certificate
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    Set-TlsLevels
    Initialize-VenDebugLog -General $General -Specific $Specific

    $siteId =$General.VarText1

    $rawCert="$($Specific.CertPem)$($Specific.ChainPem)"
    $rawKey ="$($Specific.PrivKeyPemEncrypted)"

    $certB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($rawCert.Replace("`r`n","`n")))
    $keyB64  = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($rawKey.Replace("`r`n","`n")))

    # v2 API - custom certificate management
    $apiUrl  = "https://my.imperva.com/api/prov/v2/sites/$($siteId)/customCertificate"

    Add-Type -AssemblyName System.Security
    $X509Certificate  = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($certB64))
    $AuthTypeFullName = $X509Certificate.SignatureAlgorithm.FriendlyName
    if ($AuthTypeFullName -like '*RSA*') {
        $X509AuthType = 'RSA'
    } else {
        $X509AuthType = 'ECC'
    }
    Write-VenDebugLog "Setting certificate auth-type to '$($X509AuthType)' ($($AuthTypeFullName) $($X509Certificate.SignatureAlgorithm.Value))"

    $apiBody = @{
        'certificate' = $certB64
        'private_key' = $keyB64
        'passphrase'  = $Specific.EncryptPass
        'auth_type'   = $X509AuthType # 'RSA or ECC'
    }

    try {
        $siteInfo = Invoke-ImpervaRestMethod -General $General -Method Put -Uri $apiUrl -Body $apiBody
    } catch {
        Write-VenDebugLog "Install Failure: $($_)" -ThrowException
    }

    if ($siteInfo.res -ne 0) {
        $apiError = "API error $($siteInfo.res): $($siteInfo.res_message)"
        if ($siteInfo.debug_info.certificate) {
            $apiError += " ($($siteInfo.debug_info.certificate))"
        }
        Write-VenDebugLog $apiError
        Write-VenDebugLog "$($siteInfo|ConvertTo-Json -Depth 9 -Compress)"
        if ($siteInfo.res -eq 3015) {
            Write-VenDebugLog "Temporary Error - Returning control to Venafi (Resume Later)"
            return @{ Result="ResumeLater"; }
        }
        Write-VenDebugLog "Install FAILED - Returning control to Venafi"
        throw $apiError
    }

    Write-VenDebugLog "Certificate Installed - Returning control to Venafi"
    return @{ Result="Success"; }
}

# Stage 803: OPTIONAL FUNCTION
# Associate the provisioned certificate and private key to the application
# This function supports the "ResumeLater" result code
function Update-Binding
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )

    return @{ Result="NotUsed"; }
}

# Stage 804: OPTIONAL FUNCTION
# Activate/Commit the updated certificate and private key for the application
# This function supports the "ResumeLater" result code
function Activate-Certificate
{
    # This line tells VS Code to not flag this function's name as a "problem"
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseApprovedVerbs', '', Justification='Forced by Venafi', Scope='function')]
    
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )

    return @{ Result="NotUsed"; }
}

# VALIDATION: MANDATORY FUNCTION
# Extract public certificate information used for validation and possibly update the database
# Option 1: Extract and return the public certificate (and optionally the certificate chain)
# -- Option 1 can update the certificate in the TPP database
# Option 2: Return only the certificate thumbprint and serial number to match against the existing inventory
# -- Option 2 can only be used to validate the installation - it cannot update the database
function Extract-Certificate
{
    # This line tells VS Code to not flag this function's name as a "problem"
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseApprovedVerbs', '', Justification='Forced by Venafi', Scope='function')]
    
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )

    Set-TlsLevels
    Initialize-VenDebugLog -General $General

    $siteId = $General.VarText1

    if ($General.HostAddress -ne '') {
        $wafAccount=$General.HostAddress
    }

    $apiUrl  = "https://my.imperva.com/api/prov/v1/sites/status"
    $apiBody = "site_id=$($siteId)"

    try {
        $siteInfo=Invoke-ImpervaRestMethod -General $General -Method Post -Uri $apiUrl -Body $apiBody
    } catch {
        Write-VenDebugLog "Failed to retrieve site status: $($_)"
        throw("Failed to retrieve site status: $($_)")
    }

    if ($siteInfo.res -ne 0) {
        "API error $($siteInfo.res): $($siteInfo.debug_info.Error)" | Write-VenDebugLog -ThrowException
    }

    $accountRegex = "^$($wafAccount)$"
    if ($wafAccount) {
        if ($siteInfo.account_id -notmatch $accountRegex) {
            $apiError = "Account Mismatch: Site #$($siteId) expected to be in Account #$($wafAccount), but found in Account #$($siteInfo.account_id) instead."
            Write-VenDebugLog $apiError
            throw $apiError
        }
    }

    $customCert = Get-ImpervaCustomCertificate -General $General -Website $siteInfo
    Revoke-VenafiAccessToken

    Write-VenDebugLog "[$($siteInfo.display_name)] is Site #$($siteId) in Account #$($siteInfo.account_id)."
    Write-VenDebugLog "Extracted Thumbprint ($($customCert.fingerprint)) and Serial Number ($($customCert.serialNumber))"
    Write-VenDebugLog "Success - Returning control to Venafi"
    return @{ Result="Success"; Serial=$($customCert.serialNumber); Thumbprint=$($customCert.fingerprint) }
}

# VALIDATION: OPTIONAL FUNCTION
# Extract the certificate's private key
function Extract-PrivateKey
{
    # This line tells VS Code to not flag this function's name as a "problem"
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseApprovedVerbs', '', Justification='Forced by Venafi', Scope='function')]
    
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    return @{ Result="NotUsed"; }
}

# Stage 805: OPTIONAL FUNCTION
# Clean up past versions of the certificate if TPP has provisioned the certificate at least 3 times
function Remove-Certificate
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    return @{ Result="NotUsed"; }
}

# DISCOVERY: OPTIONAL FUNCTION
# Required only for onboard discovery support
#
# Note that Imperva does not provide a mechanism to export either
# the public or private certificate via API forcing us to spoof
# Venafi's required functionality. Tolerable, but far from ideal.
function Discover-Certificates
{
    # This line tells VS Code to not flag this function's name as a "problem"
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseApprovedVerbs', '', Justification='Forced by Venafi', Scope='function')]
    
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )
 
    $started=Get-Date

    Set-TlsLevels
    Initialize-VenDebugLog -General $General

    # Important constants for the discovery function
    if (($null -eq $General.VarText4) -or ($General.VarText4.Trim() -eq '')) {
        # Default folder name is 'Discovered'
        $DiscoveredFolder = 'Discovered'
    } elseif ($General.VarText4.Trim() -in ('.','\','.\')) {
        # Place discovered sub-account devices in the base folder
        $DiscoveredFolder = ''
    } else {
        # Sanitize the provided discovered folder name
        $DiscoveredFolder = $General.VarText4.Trim() -replace '[^\p{L}\p{Nd} -_]',''
    }
    $BasicPost = @{
        General = $General
        Method  = 'Post'
    }
    $DiscoveryApi = $BasicPost + @{
        Uri     = 'https://my.imperva.com/api/prov/v1/sites/list'
    }

    # How many objects to pull per API call - maximum supported by Imperva is 100
    $psize=100

    # Set WAF Account ID and search string
    if ($General.HostAddress -in ('','*')) {
        # This indicates the 'flat' style
        $wafAccount = '*'
        $wafSearch  = ''
    } else {
        $wafAccount    = $General.HostAddress
        $wafSearch     = "account_id=$($wafAccount)&"
        $AccountAPI    = $BasicPost + @{
            Uri = [uri]"https://my.imperva.com/api/prov/v1/account?account_id=$($wafAccount)"
        }
        $SubAccountAPI = $BasicPost + @{
            Uri = [uri]"https://my.imperva.com/api/prov/v1/accounts/listSubAccounts?account_id=$($wafAccount)"
        }

        # Grab the account name purely for logging purposes
        $ImpervaResponse = Invoke-ImpervaRestMethod @AccountAPI
        if ($ImpervaResponse.res -eq 0) {
            $AccountNameBadge = " ($($ImpervaResponse.account_name))"
        }

        # Poll Imperva for list of active sub accounts
        $ImpervaResponse = Invoke-ImpervaRestMethod @SubAccountAPI

        if ($ImpervaResponse.res -eq 9415) {
            # Error 9415 Operation is not allowed on this type of account
            Write-VenDebugLog "Imperva Account# $($wafAccount) is a Sub-Account$($AccountNameBadge)"
        } elseif ($ImpervaResponse.res -eq 0) {
            $SubAccountList = $ImpervaResponse.resultList
            Write-VenDebugLog "Imperva Account# $($wafAccount) is a Parent Account with $($SubAccountList.Count) Sub-Accounts$($AccountNameBadge)"
        }
    }
    $accountRegex = "^$($WafAccount)$"

    # Only perform Venafi device scanning and sub-account work if there are actually sub-accounts in Imperva
    if ($SubAccountList) {
        $BaseFolder = $General.VarText3.Trim()
        # Base Folder must be defined and the sub-account discovery option needs to be enabled
        if (($BaseFolder) -and ($General.VarBool2 -eq $true)) {
            # Login to Venafi
            if ($General|Get-VenafiAccessToken) {
                # Validate Base Folder Exists (Text3)
                $cpBody = @{
                    'ObjectDN' = $BaseFolder
                }
                $CheckPolicy = @{
                    'Method' = 'Post'
                    'Uri'    = "https://$($Script:vAuth.ApiHost)/vedsdk/Config/IsValid"
                    'Body'   = $cpBody
                }
                try {
                    $vResponse  = Invoke-VenafiRestMethod @CheckPolicy
                    $BasePolicy = $vResponse.Object
                } catch {
                    # ignore errors
                }
                if ($BasePolicy.TypeName -eq 'Policy') {
                    # Define the Discovered policy folder DN
                    $DiscoveredFolderDN = "$($BasePolicy.DN)"
                    if ($DiscoveredFolder) {
                        $DiscoveredFolderDN += "\$($DiscoveredFolder)"
                    }
                    Write-VenDebugLog "Base Policy DN: $($BasePolicy.DN)"
                    Write-VenDebugLog "Discovered DN: $($DiscoveredFolderDN)"

                    # Gather Sub Account IDs from Devices under the Base Policy
                    $GetDevicesBody = @{
                        Class     = 'Device'
                        ObjectDN  = $BasePolicy.DN
                        Recursive = 1
                    }
                    $GetDevices = @{
                        Method  = 'Post'
                        Uri     = "https://$($Script:vAuth.ApiHost)/vedsdk/Config/FindObjectsOfClass"
                        Body    = $GetDevicesBody
                    }
                    try {
                        $vResponse  = Invoke-VenafiRestMethod @GetDevices
                        $DeviceList = $vResponse.Objects
                    } catch {
                        Write-VenDebugLog "ERROR: Device list lookup failed: $($_)"
                    }

                    if ($DeviceList.Count) {
                        Write-VenDebugLog "Found $($DeviceList.Count) Imperva devices in Venafi"
                        # Grab the "Host" addresses for existing Imperva devices
                        foreach ($item in $DeviceList) {
                            $GetHostValueBody = @{
                                AttributeName = 'Host'
                                ObjectDN      = $item.DN
                            }
                            $GetHostValue = @{
                                Method = 'Post'
                                Uri    = "https://$($Script:vAuth.ApiHost)/vedsdk/Config/Read"
                                Body   = $GetHostValueBody
                            }
                            try {
                                # Lookup the 'Host' attribute for this device in Venafi
                                $vResponse = Invoke-VenafiRestMethod @GetHostValue
                            } catch {
                                Write-VenDebugLog "Host/Account ID lookup failed for device [$($item.Name)]"
                                continue
                            }
                            if (-not $vResponse.Values[0]) {
                                Write-VenDebugLog "[$($item.Name)] has no Host/Account ID in Venafi"
                                continue
                            }

                            # Create a new member property with the Host/Account ID for later use
                            $item | Add-Member -MemberType NoteProperty -Name 'AccountID' -Value $vResponse.Values[0]
                        }

                        Write-VenDebugLog 'Beginning Sub-Account Discovery'
                        # This is a parent/main account - process subaccounts
                        foreach ($subAccount in $SubAccountList) {
                            if ($subAccount.parent_id -eq $wafAccount) {
                                # Check list of sub accounts in Venafi
                                $vDevice = $DeviceList | Where-Object -Property 'AccountID' -EQ -Value $subAccount.sub_account_id

                                if ($vDevice.Count -gt 1) {
                                    # Multiple Matches!!!
                                    Write-VenDebugLog "WARNING: Found multiple ($($vDevice.Count)) device matches for [$($subAccount.sub_account_id): $($subAccount.sub_account_name)]"
                                    foreach ($item in $vDevice) {
                                        Write-VenDebugLog ">>>>> $($vDevice.DN)"
                                    }
                                } elseif ($vDevice) {
                                    # Single match found
                                    Write-VenDebugLog "Mapped [$($subAccount.sub_account_id): $($subAccount.sub_account_name)] to [$($vDevice.DN)]"
                                } else {
                                    # Not found - Create new device entry for sub account
                                    $cpBody = @{
                                        'ObjectDN' = $DiscoveredFolderDN
                                    }
                                    $CheckPolicy.Body = $cpBody
                                    try {
                                        $vResponse        = Invoke-VenafiRestMethod @CheckPolicy
                                        $DiscoveredPolicy = $vResponse.Object
                                    } catch {
                                        # Policy does not exist
                                    }
                                    if (-not $DiscoveredPolicy) {
                                        # Create it and populate the policy object
                                        $CreatePolicyBody = @{
                                            Class             = 'Policy'
                                            ObjectDN          = $DiscoveredFolderDN
                                            NameAttributeList = @{ Description = 'Newly Discovered Imperva Sub-Accounts' }
                                        }
                                        $CreatePolicy = @{
                                            Method = 'Post'
                                            Uri    = "https://$($Script:vAuth.ApiHost)/vedsdk/Config/Create"
                                            Body   = $CreatePolicyBody
                                        }
                                        try {
                                            $vResponse        = Invoke-VenafiRestMethod @CreatePolicy
                                            $DiscoveredPolicy = $vResponse.Object
                                        } catch {
                                            # Silently ignore failures and continue
                                        }
                                    }

                                    # Keep unicode letters, decimal numbers, and literal spaces - strip anything else from the account name
                                    $NewDeviceName = "$($subAccount.sub_account_id) $(($subAccount.sub_account_name -replace '[^\p{L}\p{Nd} ]',''))"
                                    if ($DiscoveredPolicy.TypeName -eq 'Policy') {
                                        # Create the new Imperva device
                                        $NewDeviceDN         = "$($DiscoveredPolicy.DN)\$($NewDeviceName)"
                                        $NewDeviceAttributes = @(
                                            @{
                                                Name  = 'Host'
                                                Value = "$($subAccount.sub_account_id)"
                                            },
                                            @{
                                                Name  = 'Description'
                                                Value = "$($subAccount.sub_account_name) (ID: $($subAccount.sub_account_id))"
                                            }
                                        )
                                        $CreateDeviceBody    = @{
                                            Class             = 'Device'
                                            ObjectDN          = $NewDeviceDN
                                            NameAttributeList = $NewDeviceAttributes
                                        }
                                        $CreateDevice = @{
                                            Method = 'Post'
                                            Uri    = "https://$($Script:vAuth.ApiHost)/vedsdk/Config/Create"
                                            Body   = $CreateDeviceBody
                                        }
                                        try {
                                            $vResponse = Invoke-VenafiRestMethod @CreateDevice
                                            $NewDevice = $vResponse.Object
                                        } catch {
                                            $ErrorMessage = "$($_)"
                                        }

                                        if ($ErrorMessage) {
                                            Write-VenDebugLog "Device Creation Failed: $($ErrorMessage)"
                                        } elseif ($NewDevice) {
                                            Write-VenDebugLog "New Device Created: $($NewDevice.DN)"
                                        } else {
                                            Write-VenDebugLog "Device Creation Failed: $($NewDeviceDN)"
                                        }
                                    } elseif ($DiscoveredPolicy) {
                                        # This is not a policy... cannot create objects here!
                                        Write-VenDebugLog "$($DiscoveredPolicy.DN) is not a 'Policy' ($($DiscoveredPolicy.TypeName))"
                                        Write-VenDebugLog ">>>>> Failed to create new Imperva device [$($NewDeviceName)]"
                                    } else {
                                        # No policy or object exists ... creation must have failed
                                        Write-VenDebugLog "Discovered Policy does not exist"
                                        Write-VenDebugLog ">>>>> Failed to create new Imperva device [$($NewDeviceName)]"
                                    }
                                }
                            } else {
                                Write-VenDebugLog "ERROR: Parent Account is '$($subAccount.parent_id)', expected '$($wafAccount)'... Skipping!"
                            }
                        }
                        Write-VenDebugLog 'Sub-account discovery complete'
                    }
                } elseif ($BasePolicy.TypeName) {
                    Write-VenDebugLog "$($BaseFolder) is not a policy ($($BasePolicy.TypeName))"
                } else {
                    Write-VenDebugLog "$($BaseFolder) does not exist"
                }
            }
        } elseif ((-not $BaseFolder) -and ($General.VarBool2 -eq $true)) {
            Write-VenDebugLog "WARNING: Sub-Account discovery requested, but no Base Folder provided"
        }
    }

    # Initialize counters, arrays, lists
    $page=$siteCount=$sslSites=$sslFree=$sslLegacyAdded=$sslDiscovered=$inactiveSites=0
    $siteList=@()

    do {
        $batch   = 0
        $apiBody = "$($wafSearch)page_size=$($psize)&page_num=$($page)"

        try {
            Write-VenDebugLog "Requesting sites $(($page*$psize)+1) through $(($page+1)*($psize))"
            $siteInfo = Invoke-ImpervaRestMethod @DiscoveryApi -Body $apiBody
        } catch {
            "API method failure: $($siteInfo)" | Write-VenDebugLog -ThrowException
        }

        foreach($site in $siteInfo.sites) {
            $batch++
            $siteCount++
            if ($site.account_id -notmatch $accountRegex) {
                # Skip site in sub-account when searching parent/root
                #Write-VenDebugLog "Ignored: $($site.display_name) in sub-account #$($site.account_id)"
            } elseif ($site.active -ne 'active') {
                # This site is NOT active...
                $inactiveSites++
                Write-VenDebugLog "Ignored: $($site.display_name) is inactive"
            } else {
                $customCert = Get-ImpervaCustomCertificate -General $General -Website $site
                if ($customCert) {
                    $wafHost = $customCert.wafHost
                    $sslSites++
                    if ($customCert.legacy) {
                        $sslLegacyAdded++
                        Write-VenDebugLog "Discovered: [$($site.display_name)] (Legacy Site #$($site.site_id) at $($wafHost))"
                    } else {
                        $sslDiscovered++
                        Write-VenDebugLog "Discovered: [$($site.display_name)] (Site #$($site.site_id) at $($wafHost))"
                    }
                    $wafSite = @{
                        Name = $site.display_name         # Name of the Adaptable Application object
                        PEM = $customCert.certificate.PEM # Formatted PEM version of the public certificate
                        # Venafi currently fails when trying to validate this way due to weak SNI support
                        ValidationAddress = $wafHost      # FQDN of Imperva WAF Front-End
                        ValidationPort = 443              # TCP port (Currently hard coded to 443)
                        Attributes = @{ 'Text Field 1' = $site.site_id }
                    } # Venafi Application definition for the current site
                    $siteList += $wafSite
                } else { # custom certificate was retrieved
                    $sslFree++
                    Write-VenDebugLog "Ignored: $($site.display_name) is unencrypted or unreachable"
                } # WAF on an HTTP only site.?! Eeew...
            } # site.account_id matches accountRegex
        } # foreach $site
        $page++
    } while ($batch -eq $psize)

    if ($Script:DebugOptions.Discovered) {
        Write-VenDebugLog "Discovered Applications List:`n$($siteList|ConvertTo-Json -Depth 9)"
    }

    # Wait until after the certificate discovery to logout of Venafi because
    # we may need to search the Venafi database to retrieve the public key
    Revoke-VenafiAccessToken

    if ($sslDiscovered+$sslLegacyAdded -gt 0) {
        $logMessage = "Discovered $($sslDiscovered+$sslLegacyAdded) secure sites"
        if ($sslLegacyAdded -gt 0) {
            $logMessage += " ($($sslLegacyAdded) legacy)"
        }
        Write-VenDebugLog $logMessage
    }
    if ($sslFree+$inactiveSites -gt 0) {
        $logMessage = "Ignored $($sslFree+$inactiveSites) sites ("
        if ($sslFree -gt 0)          { $logMessage += "$($sslFree) unencrypted, " }
        if ($inactiveSites -gt 0)    { $logMessage += "$($inactiveSites) inactive, " }
        Write-VenDebugLog "$($logMessage.TrimEnd(', ')))"
    }

    $runtime = New-TimeSpan -Start $started -End (Get-Date)
    Write-VenDebugLog "Scanned $($siteCount) sites (Runtime $($runtime)) - Returning control to Venafi"
 
    return @{ Result='Success'; Applications=$siteList }
}

#
# Private functions for this application driver
#

# Take a message, prepend a timestamp, output it to a debug log ... if DEBUG_FILE is set
# Otherwise do nothing and return nothing
function Write-VenDebugLog
{
    Param(
        [Parameter(Position=0, ValueFromPipeline, Mandatory)]
        [string] $LogMessage,

        [Parameter()]
        [switch] $ThrowException,

        [Parameter()]
        [switch] $NoFunctionTag
    )

    filter Add-TS {"$(Get-Date -Format o): $_"}

    # only write the log message to a file if the logfile is set...
    if ($Script:venDebugFile) {
        if ($NoFunctionTag.IsPresent) {
            $taggedLog = $LogMessage
        } else {
            $taggedLog = "[$((Get-PSCallStack)[1].Command)] $($LogMessage)"
        }

        # write the message to the debug file
        Write-Output "$($taggedLog)" | Add-TS | Add-Content -Path $Script:venDebugFile
    }

    # throw the message as an exception, if requested
    if ($ThrowException.IsPresent) {
        throw $LogMessage
    }
}

function Initialize-VenDebugLog
{
    Param(
        [Parameter(Position=0, Mandatory)]
        [System.Collections.Hashtable]$General,

        [Parameter(Position=1)]
        [System.Collections.Hashtable]$Specific = $null
    )

    $Caller = (Get-PSCallStack)[1].Command

    # if the debugfile is already setup we shouldn't be called again - log a warning
    if ($null -ne $Script:venDebugFile) {
        Write-VenDebugLog "Called by $($Caller)"
        Write-VenDebugLog 'WARNING: Initialize-VenDebugLog() called more than once!'
        return
    }

    if ($null -eq $DEBUG_FILE) {
        # do nothing and return immediately if debug isn't on
        if ($General.VarBool1 -eq $false) { return }

        # pull Venafi base directory from registry for global debug flag
        $logPath = "$((Get-ItemProperty HKLM:\Software\Venafi\Platform).'Base Path')Logs"
    } else {
        # use the path but discard the filename from the DEBUG_FILE variable
        $logPath = "$(Split-Path -Path $DEBUG_FILE)"
    }

    # add a filename to the base log directory path
    $Script:venDebugFile = "$($logPath)\$($Script:AdaptableAppDrv.Replace(' ',''))"
    if ($General.HostAddress -notin ('*','')) {
        $Script:venDebugFile += "-Acct$($General.HostAddress)"
    }
    if ($Caller -eq 'Discover-Certificates') {
        $Script:venDebugFile += '-Discovery'
    }
    $Script:venDebugFile += ".log"
    
    Write-Output '' | Add-Content -Path $Script:venDebugFile

    Write-VenDebugLog -NoFunctionTag -LogMessage "$($Script:AdaptableAppDrv) v$($Script:AdaptableAppVer): Venafi called $($Caller)"
    Write-VenDebugLog -NoFunctionTag -LogMessage "PowerShell Environment: $($PSVersionTable.PSEdition) Edition, Version $($PSVersionTable.PSVersion.Major)"

    # Process advanced debug options
    if ($General.VarText5) {
        $AdvDebugOptions = $General.VarText5.Trim() -split "[ ,|]" | Where-Object -FilterScript { $_ }
        if ($AdvDebugOptions -contains 'CallFunction') {
            Write-VenDebugLog "Called by $($Caller)"
            Write-VenDebugLog "Advanced Debug: Function calls will be output to the debug logs"
            $Script:DebugOptions.CallFunction = $true
        }
        if ($AdvDebugOptions -contains 'UnmaskFields') {
            Write-VenDebugLog "Advanced Debug: Sensitive fields will not be redacted (UnmaskFields)"
            $Script:DebugOptions.RedactData = $false
        }
        if ($AdvDebugOptions -contains 'APIBody') {
            Write-VenDebugLog "Advanced Debug: API body will be output to the debug logs"
            $Script:DebugOptions.APIBody = $true
        }
        if ($AdvDebugOptions -contains 'APICalls') {
            Write-VenDebugLog "Advanced Debug: All API calls will be output to the debug logs"
            $Script:DebugOptions.APICallI = $true
            $Script:DebugOptions.APICallV = $true
        } else {
            if ($AdvDebugOptions -contains 'APICallI') {
                Write-VenDebugLog "Advanced Debug: Imperva API calls will be output to the debug logs"
                $Script:DebugOptions.APICallI = $true
            }
            if ($AdvDebugOptions -contains 'APICallV') {
                Write-VenDebugLog "Advanced Debug: Venafi API calls will be output to the debug logs"
                $Script:DebugOptions.APICallV = $true
            }
        }
        if ($AdvDebugOptions -contains 'APIReplyAll') {
            Write-VenDebugLog "Advanced Debug: All API replies will be output to the debug logs"
            $Script:DebugOptions.APIReplyI = $true
            $Script:DebugOptions.APIReplyV = $true
        } else {
            if ($AdvDebugOptions -contains 'APIReplyI') {
                Write-VenDebugLog "Advanced Debug: Imperva API replies will be output to the debug logs"
                $Script:DebugOptions.APIReplyI = $true
            }
            if ($AdvDebugOptions -contains 'APIReplyV') {
                Write-VenDebugLog "Advanced Debug: Venafi API replies will be output to the debug logs"
                $Script:DebugOptions.APIReplyV = $true
            }
        }
        if ($AdvDebugOptions -contains 'Discovered') {
            Write-VenDebugLog "Advanced Debug: Discovered app list will be output to the debug logs"
            $Script:DebugOptions.Discovered = $true
        }
        if ($AdvDebugOptions -contains 'WAFErrors') {
            Write-VenDebugLog "Advanced Debug: Non-fatal WAF errors will be output to the debug logs"
            $script:DebugPreference.WAFErrors = $true
        }
        if ($AdvDebugOptions -contains 'DumpGeneral') {
            Write-VenDebugLog "Advanced Debug: Including dump of variables from the GENERAL hashtable"
            $RedactedData = $General|Remove-RedactedValues
            foreach ($key in ($RedactedData.Keys|Sort-Object)) {
                if ($null -eq $RedactedData[$key]) {
                    $keytype = 'NULL'
                } else {
                    $keytype = $RedactedData[$key].GetType()
                }
                Add-Content -Path $Script:venDebugFile ">>>>> $($key)[$($keytype)]: [$($RedactedData[$key])]"
            }
        }
        if ($AdvDebugOptions -contains 'DumpSpecific') {
            if ($Specific) {
                Write-VenDebugLog "Advanced Debug: Including dump of variables from the SPECIFIC hashtable"
                # Specific hashtable is never redacted - nothing would be left to log!
                $RedactedData = $Specific
                foreach ($key in ($RedactedData.Keys|Sort-Object)) {
                    if ($null -eq $RedactedData[$key]) {
                        $keytype = 'NULL'
                    } else {
                        $keytype = $RedactedData[$key].GetType()
                    }
                    Add-Content -Path $Script:venDebugFile ">>>>> $($key)[$($keytype)]: [$($RedactedData[$key])]"
                }
            }
        }
    }
}

function Remove-RedactedValues
{
    Param(
        [Parameter(Mandatory,ValueFromPipeline,Position=0)]
        [System.Object] $InputObject
    )

    if ($Script:DebugOptions.CallFunction) {
        Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"
    }

    # Return the original object if sensitive data is not being redacted
    if (-not $Script:DebugOptions.RedactData) {
        Write-VenDebugLog 'Sensitive fields have been unmasked - Doing nothing'
        return $InputObject
    }

    $i=0
    if ($InputObject.GetType().Name -eq 'Hashtable') {
        # Create a shallow copy of the hashtable
        $RedactedData = $InputObject.Clone()

        # Mask sensitive values in the COPY of the input object
        foreach ($key in $InputObject.keys) {
            if ($key -in $Script:SensitiveFields) {
                if ($InputObject[$key]) {
                    $i++
                    $RedactedData[$key] = '<<<REDACTED>>>'
                }
            }
        }
    } elseif ($InputObject.GetType().Name -eq 'PSCustomObject') {
        # Use JSON conversions to force a reasonably accurate copy
        $RedactedData = $InputObject|ConvertTo-Json -Depth 9|ConvertFrom-Json

        # Mask sensitive values in the COPY of the input object
        foreach ($property in $InputObject.psobject.Properties) {
            if ($property.Name -in $Script:SensitiveFields) {
                if ($InputObject.($property.Name)) {
                    $i++
                    $RedactedData.($property.Value) = '<<<REDACTED>>>'
                }
            }
        }
    } else {
        # Return the original object if not a hashtable or PSCustomObject
        Write-VenDebugLog "not a hashtable or pscustomobject (type: $($InputObject.GetType().Name))"
        return $InputObject
    }

    # Log how many fields have been redacted
    if ($i) {
        if ($i -gt 1) { $s = 's' } else { $s = '' }
        Write-VenDebugLog "Redacted $($i) field$($s)"
    }

    # Return the redacted copy of the original object
    $RedactedData
}

function Set-TlsLevels
{
    param(
        [Parameter()]
        [ValidateSet('TLS10','TLS11')]
        [String[]] $Include,

        [Parameter()]
        [ValidateSet('TLS12','TLS13')]
        [String[]] $Exclude
    )

    # Always disable SSL v3
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -band (-bnot [Net.SecurityProtocolType]::Ssl3)

    if ($Include -contains 'TLS10') {
        # Enable TLS 1.0
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls
    } else {
        # Disable TLS 1.0 by default
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -band (-bnot [Net.SecurityProtocolType]::Tls)
    }

    if ($Include -contains 'TLS11') {
        # Enable TLS 1.1
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls11
    } else {
        # Disable TLS 1.1 by default
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -band (-bnot [Net.SecurityProtocolType]::Tls11)
    }

    if ($Exclude -contains 'TLS12') {
        # Disable TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -band (-bnot [Net.SecurityProtocolType]::Tls12)
    } else {
        # Enable TLS 1.2 by default
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }

    if ($Exclude -contains 'TLS13') {
        # Disable TLS 1.3
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -band (-bnot [Net.SecurityProtocolType]::Tls13)
    } else {
        # Enable TLS 1.3 by default
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls13
    }
}

function Invoke-ImpervaRestMethod
{
	Param(
        [Parameter(Mandatory)]
        [System.Collections.Hashtable] $General,

		[Parameter(Mandatory)]
        [Uri] $Uri,

		[Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.WebRequestMethod] $Method,

		[System.Object] $Body,

		[string] $ContentType = 'application/x-www-form-urlencoded',

		[int] $TimeoutSec
	)

    if ($Script:DebugOptions.APICallI -or $Script:DebugOptions.CallFunction) {
        Write-VenDebugLog "$((Get-PSCallStack)[1].Command)/$($Method) as API-ID $($General.UserName): $($Uri)"
    }

    $apiAuth = @{
        'x-API-Id'  = $General.UserName;
        'x-API-Key' = $General.UserPass
    }
    $ImpervaRestApiCall = @{
        Uri         = $Uri
        Method      = $Method
        Headers     = $apiAuth
        ContentType = $ContentType
    }

    # Convert body hashtable to JSON and optionally log the possibly redacted result
    if ($Body)       {
        if ($Body.GetType().Name -eq 'Hashtable') {
            # Convert the hashtable to JSON
            $ImpervaRestApiCall.ContentType = 'application/json'
            $ImpervaRestApiCall.Body        = ($Body|ConvertTo-Json -Depth 9)
            if ($Script:DebugOptions.APIBody) {
                # Log the possibly redacted body json
                Write-VenDebugLog "API Call Body:`n$($Body|Remove-RedactedValues|ConvertTo-Json -Depth 9)"
            }
        } else {
            $ImpervaRestApiCall.Body        = $Body
            if ($Script:DebugOptions.APIBody) {
                # Log the raw body string (cannot be redacted)
                Write-VenDebugLog "API Call Body: $($Body)"
            }
        }
    }
    if ($TimeoutSec) { $ImpervaRestApiCall.TimeoutSec = $TimeoutSec }

    $Attempts=3
    $i=0
    do {
        try {
            $response = Invoke-RestMethod @ImpervaRestApiCall
            if ($Script:DebugOptions.ApiReplyI) {
                Write-VenDebugLog "API Reply:`n$($response|Remove-RedactedValues|ConvertTo-Json -Depth 9)"
            }
        } catch {
            $ErrorResults = "$($_)" | ConvertFrom-Json
            if ($null -ne $ErrorResults.res) {
                $apiError = "API error $($ErrorResults.res): $($ErrorResults.res_message)"
                if ($ErrorResults.debug_info.Error) {
                    $apiError += " ($($ErrorResults.debug_info.Error))"
                } elseif ($ErrorResults.debug_info.problem) {
                    $apiError += " ($($ErrorResults.debug_info.problem))"
                } elseif ($ErrorResults.debug_info.certificate) {
                    $apiError += " ($($ErrorResults.debug_info.certificate))"
                }
                Write-VenDebugLog "Attempt #$($i): $($apiError)"
                Write-VenDebugLog "DEBUG INFO: $($ErrorResults|ConvertTo-Json -Depth 9 -Compress)"
                $response = $ErrorResults
            } else {
                "REST call failed: $($_)" | Write-VenDebugLog -ThrowException
            }
        }

        # return response upon success, otherwise retry
        if ($response.res -eq 0) { return $response }

        # log the entire response if not a success and 'WAFBadRC' option is set
        if ($Script:DebugOptions.WAFBadRC) {
            Write-VenDebugLog "RC<>0: $($response|ConvertTo-Json -Depth 9 -Compress)"
        }

        # error 9415 is "Operation not allowed" - return immediately
        if ($response.res -eq 9415) { return $response }

        # error 4205 indicates that the site is not configured for SSL - throw an error
        if ($response.res -eq 4205) {
            $fatal = "SITE NOT CONFIGURED FOR SSL (Error: 4205)"
            $fatal | Write-VenDebugLog -ThrowException
        }

        # error 9413 indicates that the site does not exist - throw an error
        if ($response.res -eq 9413) {
            $fatal = "SITE DOES NOT EXIST (Error: 9413)"
            $fatal | Write-VenDebugLog -ThrowException
        }

        $i++
        $wait = Get-Random -Minimum ($i+1) -Maximum ($i*3)
        Write-VenDebugLog "Attempt #$($i) failed - sleeping for $($wait) seconds"
        Start-Sleep -Seconds $wait
    } while ($i -lt $Attempts)

    # if API call keeps failing just return bad results
    Write-VenDebugLog "$($i) API call failures - returning results to driver..."
    $response
}

function Convert-ImpervaTimestamp
{
    Param(
        [Parameter(Position=0, ValueFromPipeline, Mandatory)]
        [String]$Timestamp
    )

    if ($Script:DebugOptions.CallFunction) {
        Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"
    }

    # Convert microseconds to seconds and add to 'epoch' date
    ([DateTime]'1/1/1970Z').AddSeconds($Timestamp/1000)
}

function Get-ImpervaCustomCertificate
{
    Param(
        [Parameter(Mandatory)] [System.Collections.Hashtable] $General,
        [Parameter(Mandatory)] [PSCustomObject] $Website
    )

    if ($Script:DebugOptions.CallFunction) {
        Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"
    }

    $Attempts=3
    $siteId     = $Website.site_id
    $siteName   = $Website.display_name
    $siteLegacy = $false
    $apiUrl     = "https://api.imperva.com/certificates/v3/certificates?extSiteId=$($siteId)&certType=CUSTOM_CERT"
    $apiAuth = @{
        'x-API-Id'  = $General.UserName;
        'x-API-Key' = $General.UserPass
    }

    foreach ($dnsBlock in $Website.dns) {
        if ($dnsBlock.dns_record_name -eq $Website.domain) {
            $wafHost = $dnsBlock.set_data_to[0]
            Write-VenDebugLog "Imperva Site $($Website.display_name) uses front-end $($wafHost)"
        }
    }

    try {
        $i=0
        do {
            $response = Invoke-WebRequest -Uri $apiUrl -Method Get -Headers $apiAuth -UseBasicParsing
            if ($response.StatusCode -eq 200) { break }
            # did not receive a 200 OK, retry the request after a brief sleep
            $i++
            $wait = Get-Random -Minimum ($i+1) -Maximum ($i*3)
            Write-VenDebugLog "Attempt #$($i) failed ($($response.StatusCode): $($response.statusDescription)) - sleeping for $($wait) seconds"
            Start-Sleep -Seconds $wait
        } while ($i -lt $Attempts)
        if ($response.StatusCode -ne 200) {
            throw "Failed to retrieve certificate: ($($response.StatusCode): $($response.statusDescription))"
        }
    } catch {
        $fatal = "Failed to retrieve custom certificate data: $($_)"
        Write-VenDebugLog $fatal
        throw $fatal
    }

    $responseData = (($response.Content | ConvertFrom-Json).data)

    # This should only happen during discovery of an unencrypted site
    if ($responseData.Count -eq 0) {
        return $null
    }
    # Getting back more than 1 result should NEVER happen...
    elseif ($responseData.Count -ne 1) {
        $fatal = "Custom certificate count is $($responseData.Count)... This should never happen!"
        Write-VenDebugLog $fatal
        throw $fatal
    }

    if ($responseData.extSiteId -ne $siteId) {
        $fatal = "Data Mismatch! Asked for $($siteName) (site #$($siteId)) but got results for site #$($responseData.extSiteId)..."
        Write-VenDebugLog $fatal
        throw $fatal
    }

    $siteSerial  = $apiSerial = ($responseData.customCertificateDetails.serialNumber -replace ':','')
    $siteThumb   = $apiThumb  = ($responseData.customCertificateDetails.fingerprint -replace 'SHA1 Fingerprint=','' -replace ':','')
    $certExpires = Convert-ImpervaTimestamp "$($responseData.expirationDate)"

    # Imperva will only return data for valid/active certificates... plus the front-end won't work right!
    # This is an attempt to handle the unexpected results for expired/inactive certificates
    $GoodImpervaStatus = @('ACTIVE','NEAR_EXPIRATION')
    if ($responseData.status -eq 'EXPIRED') {
        Write-VenDebugLog "EXPIRED: Certificate for $($siteName) (site #$($siteId)) expired on $($certExpires)"
        return
    } elseif ($responseData.status -notin $GoodImpervaStatus) {
        Write-VenDebugLog "ERROR: Unexpected certificate status '$($responseData.status)' for $($siteName) (site #$($siteId))"
        return
    }

    # Always attempt to pull the public certificate from the WAF front-end
    # This is as much to generate warnings for API bugs as it is to support discovery
    $siteCert = Get-CertFromWaf -WafHost $wafHost -Target $Website.domain

    if (-not $siteCert) {
        # Pull from front-end failed... Search Venafi for a match.
        if (-not $siteSerial) {
            # Give up... no serial from API, no cert from front-end
            Write-VenDebugLog "Legacy certificate (no serial from API) and front-end unresponsive ... ABORT"
            return
        }
        $siteCert = Find-CertInVenafi -General $General -SerialNumber $siteSerial -Thumbprint $siteThumb
    }

    if (($null -eq $siteSerial) -or ($siteSerial -eq '')) {
        $siteLegacy = $true
        Write-VenDebugLog "Legacy website: Certificate data not available via API for $($siteName) (site #$($siteId))"
        $siteSerial = $siteCert.X509.SerialNumber.TrimStart('0')
        $siteThumb  = $siteCert.X509.Thumbprint.TrimStart('0')
    }

    if (($null -eq $siteThumb) -or ($siteThumb -eq '')) {
        Write-VenDebugLog "No fingerprint retrieved from Imperva Cloud WAF for $($siteName) (site #$($siteId)) - $($siteThumb)"
        throw("Fingerprint not available from Imperva Cloud WAF");
    }

    if ($null -eq $responseData.expirationDate) {
        Write-VenDebugLog "No expiration date retrieved from Imperva Cloud WAF for $($siteName) (site #$($siteId))"
        throw("Expiration date not available from Imperva Cloud WAF");
    }

    if ($null -ne $siteCert) {
        Write-VenDebugLog "'$($siteCert.X509.GetNameInfo(0,$false))' issued by '$($siteCert.X509.GetNameInfo(0,$true))' expires $($certExpires)"
        Write-VenDebugLog "Serial=$($siteSerial), Thumbprint=$($siteThumb)"
        if (!$siteLegacy) {
            if (($siteCert.X509.SerialNumber.TrimStart('0') -ne $apiSerial.TrimStart('0')) -or ($siteCert.X509.Thumbprint.TrimStart('0') -ne $apiThumb.TrimStart('0'))) {
                # This is a pretty annoying bug...
                #
                # If you use a certificate on multiple WAF sites (I.E. SANs or wildcards)
                # then you should know that every site tracks details based on a site-specific upload
                # Every site retains its own certificate details...
                # ...BUT uploading a shared certificate on any site actually affects all the others on
                # the backend. To make the saved data validate, you have to upload the certificate to
                # each and every site. This bug also can be seen in the web UI.
                #
                # This is silly, BUT we should at least flag/note this in the debug logs.
                Write-VenDebugLog "WARNING: Imperva Bug - Certificate Mismatch in API vs WAF - Validation will FAIL"
                Write-VenDebugLog "\\-- API: Serial=$($apiSerial), Thumbprint=$($apiThumb)"
                Write-VenDebugLog "\\-- WAF: Serial=$($siteCert.X509.SerialNumber), Thumbprint=$($siteCert.X509.Thumbprint)"
                Write-VenDebugLog "\\-- Reinstall certificate via API or WebUI to fix this issue"
            } # UI/WAF mismatch warning
        }
    }

    if ($responseData.customCertificateDetails.hasMismatchSite -eq $true) {
        Write-VenDebugLog 'WARNING: Imperva reports a "site mismatch" error... The certificate does not match the site name!'
    }

    $certData = @{
        "site_id"      = $siteId
        "wafHost"      = $wafHost
        "serialNumber" = $siteSerial
        "fingerprint"  = $siteThumb
        "certExpires"  = $certExpires
        "legacy"       = $siteLegacy
        "certificate"  = $siteCert
    }

    $certData
}

function Get-CertFromWaf
{
    Param(
        [Parameter(Mandatory=$true)][string]$WafHost,
        [Parameter(Mandatory=$true)][string]$Target,
        [string]$Port='443'
    )

    if ($Script:DebugOptions.CallFunction) {
        Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"
        Write-VenDebugLog "Pulling certificate for $($Target) via front-end $($WafHost)"
    }

    $wafUri = "https://$($WafHost):$($Port)"

    try {
        # open a network connection to the Imperva front-end. Be sure to pass the proper host request header!
        # We're not parsing the webpage so '-UseBasicParsing' helps prevent meaningless IE setup errors messages...
        Set-TlsLevels -Include TLS10,TLS11
        Invoke-WebRequest -Uri "$($wafUri)" -Headers @{Host="$($Target)"} -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop | Out-Null
    } catch {
        if ($Script:DebugOptions.WAFErrors) {
            # Log the error but keep on trucking... We only want the TLS handshake anyway.
            Write-VenDebugLog "Ignoring Error: $($_)"
        }
    } finally {
        Set-TlsLevels
    }

    # find the open network connection then import the raw certificate data 
    $sp = [System.Net.ServicePointManager]::FindServicePoint("$($wafUri)")

    # failure was so complete that no certificate was returned by the front-end!!
    if (-not $sp.Certificate) {
#        Write-VenDebugLog "FAILED to pull certificate for $($Target) from $($WafHost)"
        return
    }

    $wafCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $wafCert.Import($sp.Certificate.GetRawCertData())

    # create a base-64 formatted string from the certificate (aka PEM data format)
    $pemData = [Convert]::ToBase64String($wafCert.GetRawCertData(),'InsertLineBreaks')
    $FormattedPEM = "-----BEGIN CERTIFICATE-----`n$($pemData -replace "`r`n","`n")`n-----END CERTIFICATE-----"

    # build an object that contains both the certificate object and PEM string data
    $results = @{
        X509   = $wafCert
        PEM    = $FormattedPem
    }

    $results
}

#region FindVenafiCert
function Find-CertInVenafi
{
    Param(
        [Parameter(Mandatory)]
        [System.Collections.Hashtable] $General,

        [Parameter(Mandatory)]
        [string]$SerialNumber,

        [Parameter(Mandatory)]
        [string]$Thumbprint
    )

    if ($Script:DebugOptions.CallFunction) {
        Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"
        Write-VenDebugLog "Search the vault for SN: $($SerialNumber)"
    }

    # Get an access token for Venafi or abort immediately
    if (-not ($General|Get-VenafiAccessToken)) { return }

    $vSearchBody = @{
        Name        = 'Serial'
        StringValue = $SerialNumber
    }
    $vSearchParms = @{
        Method = 'Post'
        Uri    = "https://$($Script:vAuth.ApiHost)/vedsdk/SecretStore/LookupByAssociation"
        Body   = $vSearchBody
    }
    try {
        $vSearchReply = Invoke-VenafiRestMethod @vSearchParms
        if ($vSearchReply.Result -ne 0) {
            Write-VenDebugLog "Vault ID Lookup Failure (RC=$($vSearchReply.Result)): $($vSearchReply.Error)"
            return
        }
    } catch {
        Write-VenDebugLog "Vault ID Lookup Failure: $($_)"
        return
    }

    # This should be modified to loop in case multiple results are returned...
    $VaultID = $vSearchReply.VaultIDs[0]

    if (-not $VaultID) {
        Write-VenDebugLog "Could not find a certificate with Serial# $($SerialNumber) in Venafi vault"
        return
    }

    $vGetCert = @{
        'ContentType' = 'application/json'
        'Method'       = 'Get'
        'Uri'          = "https://$($Script:vAuth.ApiHost)/vedsdk/Certificates/Retrieve/$($VaultID)?Format=Base64"
    }
    Write-VenDebugLog "Retrieving Certificate from the Venafi vault (ID $($VaultID))"
    $CertPEM = Invoke-VenafiRestMethod @vGetCert

    # Convert PEM formatted certificate to a Base64 encoded string without line breaks
    $CertB64 = (($CertPEM -split '\r?\n' | Where-Object { $_ -notmatch 'BEGIN|END' }) -join '')

    # Convert Base64 encoded string into raw binary bytes
    $CertRaw = [System.Convert]::FromBase64String($CertB64)

    # Convert byte array into an X509Certificate2 object
    $CertObj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertRaw)


    if ($CertObj.Thumbprint -ne $Thumbprint) {
        Write-VenDebugLog "Vault ID #$($VaultID) - Thumbprint mismatch (Looking for $($Thumbprint) but found $($CertObj.Thumbprint))"
        return
    }

    # build an object that contains both the certificate object and PEM string data
    $results = @{
        X509   = $CertObj
        PEM    = ($CertPEM -replace "`r`n","`n")
    }

    $results
}
#endregion

#region Venafi REST API
function Invoke-VenafiRestMethod
{
	Param(
		[Parameter(Mandatory)]
        [Uri] $Uri,

		[Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.WebRequestMethod] $Method,

		[System.Object] $Body,

		[string] $ContentType = 'application/json',

		[int] $TimeoutSec,

        [switch] $NoAuth
	)

    if ($Script:DebugOptions.APICallV -or $Script:DebugOptions.CallFunction) {
        if ($NoAuth) {
            $WhoAmI = '[nobody]'
        } else {
            $WhoAmI = $Script:vAuth.username
        }
        Write-VenDebugLog "$((Get-PSCallStack)[1].Command)/$($Method) as $($WhoAmI): $($Uri)"
    }

    if ((-not $NoAuth) -and (-not $Script:vAuth.access_token)) {
        Write-VenDebugLog 'No Access Token: API OAUTH token must be created before calling this function'
        return
    }

    $VenafiRestApiCall = @{
        Uri         = $Uri
        Method      = $Method
        ContentType = $ContentType
    }

    if ((-not $NoAuth) -and ($Script:vAuth.Headers)) {
        $VenafiRestApiCall.Headers = $Script:vAuth.Headers
    }

    # Convert body hashtable to JSON and optionally log the possibly redacted result
    if ($Body)       {
        if ($Body.GetType().Name -eq 'Hashtable') {
            # Convert the hashtable to JSON
            $VenafiRestApiCall.Body        = ($Body|ConvertTo-Json -Depth 9)
            if ($Script:DebugOptions.APIBody) {
                # Log the possibly redacted body json
                Write-VenDebugLog "API Call Body:`n$($Body|Remove-RedactedValues|ConvertTo-Json -Depth 9)"
            }
        } else {
            $VenafiRestApiCall.Body        = $Body
            if ($Script:DebugOptions.APIBody) {
                # Log the raw body string (cannot be redacted)
                Write-VenDebugLog "API Call Body: $($Body)"
            }
        }
    }
    if ($TimeoutSec) { $VenafiRestApiCall.TimeoutSec = $TimeoutSec }

    try {
        $response = Invoke-RestMethod @VenafiRestApiCall
        if ($Script:DebugOptions.ApiReplyV) {
            Write-VenDebugLog "API Reply:`n$($response|Remove-RedactedValues|ConvertTo-Json -Depth 9)"
        }
    } catch {
        # Do nothing on error
    }

    # Return the API response
    $response
}
#endregion

#region Venafi Tokens
function Get-VenafiAccessToken
{
    Param(
        [Parameter(Mandatory,ValueFromPipeline)]
        [System.Collections.Hashtable] $General
    )

    if ($Script:DebugOptions.CallFunction) {
        Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"
    }

    # Do nothing if access token is already defined
    if ($Script:vAuth.access_token) {
        $true
        return
    }

    # Verify that an Aux User has been defined for Venafi API access
    if (-not ($General.AuxUser.Trim())) {
        Write-VenDebugLog "No auxilliary user defined - cannot access Venafi API"
        return
    }

    # Venafi API login body
    $vAuthBody = @{
        username  = $General.AuxUser.Trim()
        password  = $General.AuxPass.Trim()
        client_id = 'imperva'
        scope     = 'certificate:manage;configuration:manage;restricted:manage'
    }

    # Venafi API hostname defaults to the FQDN of the localhost
    $apiHost = $env:COMPUTERNAME

    # Try to get the FQDN from an A/AAAA (or CNAME)
    $lookup = $apiHost | Resolve-DnsName -Type A_AAAA
    if ($lookup.Count) {
        # valid record, use the first FQDN returned
        $vApi = $lookup[0].Name
    } else {
        # name couldn't be resolved...
        Write-VenDebugLog "Couldn't resolve API hostname $($env:COMPUTERNAME)"
        return
    }

    # Venafi API login parameters (OAUTH)
    $vAuthParms = @{
        Method = 'Post'
        NoAuth = $true
        Uri    = "https://$($vApi)/vedauth/authorize/oauth"
        Body   = $vAuthBody
    }

    # Get an OAUTH token from Venafi
    try {
        $vAuthReply = Invoke-VenafiRestMethod @vAuthParms
        if (-not $vAuthReply.access_token) {
            Write-VenDebugLog "Access Token is NULL"
            return
        }
    } catch {
        Write-VenDebugLog "Venafi Login Failure: $($_)"
        return
    }

    $vAuthReply | Add-Member -MemberType NoteProperty -Name Headers   -Value @{ Authorization = "Bearer $($vAuthReply.access_token)" }
    $vAuthReply | Add-Member -MemberType NoteProperty -Name ApiHost   -Value $vApi
    $vAuthReply | Add-Member -MemberType NoteProperty -Name username  -Value $vAuthBody.username
    $vAuthReply | Add-Member -MemberType NoteProperty -Name password  -Value $vAuthBody.password
    $vAuthReply | Add-Member -MemberType NoteProperty -Name client_id -Value $vAuthBody.client_id
    $Script:vAuth = $vAuthReply

#    Write-VenDebugLog "vAuth:`n$($Script:vAuth|ConvertTo-Json)"

    # return $true upon success
    $true
}

function Revoke-VenafiAccessToken
{
    if ($Script:DebugOptions.CallFunction) {
        Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"
    }

    # Do nothing if no access token is defined
    if (-not $Script:vAuth.access_token) { return }

    $vRevoke = @{
        'ContentType' = 'application/json'
        'Method'      = 'Get'
        'Uri'         = "https://$($Script:vAuth.ApiHost)/vedauth/Revoke/token"
    }

    try {
        Invoke-VenafiRestMethod @vRevoke | Out-Null
    } catch {
        # Ignore errors
    }
}
#endregion

# END OF SCRIPT