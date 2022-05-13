#
# Imperva Cloud WAF - An Adaptable Application Driver for Venafi
#
# CCamacho Template Driver Version: 202006101700
#
$Script:AdaptableAppVer = '202205121743'
$Script:AdaptableAppDrv = "Imperva Cloud WAF"

# Import Legacy Imperva sites?
#
# We now spoof the API validation using the workaround mechanism
# employed to enable discovery by this driver. It's ugly to look
# at (if you're a programmer), but it makes this function well.
$Script:ImportLegacy    = $true

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
Text3|Text Label #3|000
Text4|Text Label #4|000
Text5|Text Label #5|000
Option1|Debug Imperva Cloud WAF Driver|110
Option2|Yes/No #2|000
Passwd|Password Field|000
-----END FIELD DEFINITIONS-----

#>

#
# REQUIRED FUNCTIONS
#
# Extract-Certificate >>> must always be implemented. it is required for validation.
#
# Install-Certificate >>> generally required to be implemented. You can optionally
# return "NotUsed" for this function *ONLY* if you instead implement Install-PrivateKey
# for your driver. In most cases, you will need Install-Certificate only. The function
# Install-Chain is also available if you need to implement certificate installation
# using 3 different functions for the public, private, and chain certificates.
#

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

# MANDATORY FUNCTION
function Install-Certificate
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    Initialize-VenDebugLog -General $General

#    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $siteId =$General.VarText1

    $rawCert="$($Specific.CertPem)$($Specific.ChainPem)"
    $rawKey ="$($Specific.PrivKeyPem)"

    $certB64=[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($rawCert.Replace("`r`n","`n")))
    $keyB64 =[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($rawKey.Replace("`r`n","`n")))

    $apiUrl ="https://my.imperva.com/api/prov/v1/sites/customCertificate/upload"

    $apiBody=@{'site_id'=$siteId; 'certificate'=$certB64; 'private_key'=$keyB64}

    try {
        $siteInfo=Invoke-ImpervaRestMethod -General $General -Method Post -Uri $apiUrl -Body $apiBody
    }
    catch {
        Write-VenDebugLog "Install Failure: $($_)"
        throw("Install Failure: $($_)")
    }

    if ($siteInfo.res -ne 0) {
        $apiError=Get-ImpervaErrorMessage -Code $siteInfo.res
        Write-VenDebugLog "API error: $($apiError): $($siteInfo.debug_info.Error)"
        Write-VenDebugLog "Install FAILED - Returning control to Venafi"
        throw "API error: $($apiError): $($siteInfo.debug_info.Error)"
    }

    $certExpires=Convert-ImpervaTimestamp $siteInfo.debug_info.details.expirationDate
    Write-VenDebugLog "Certificate Valid Until $($certExpires)"

    Write-VenDebugLog "Certificate Installed - Returning control to Venafi"
    return @{ Result="Success"; }
}

function Update-Binding
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )

    return @{ Result="NotUsed"; }
}

function Activate-Certificate
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )

    return @{ Result="NotUsed"; }
}

# MANDATORY FUNCTION
function Extract-Certificate
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )

    Initialize-VenDebugLog -General $General

#    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $siteId=$General.VarText1

    Write-VenDebugLog "Imperva Site #$($siteId)"

    $apiUrl="https://my.imperva.com/api/prov/v1/sites/status"
    $apiBody="site_id=$($siteId)"

    try {
        $siteInfo=Invoke-ImpervaRestMethod -General $General -Method Post -Uri $apiUrl -Body $apiBody
    }
    catch {
        Write-VenDebugLog "Failed to retrieve site status: $($_)"
        throw("Failed to retrieve site status: $($_)")
    }

    if ($siteInfo.res -ne 0) {
        $apiError=Get-ImpervaErrorMessage -Code $siteInfo.res
        Write-VenDebugLog "API error: $($apiError)"
        throw $apiError
    }

    foreach ($dnsBlock in $siteInfo.dns) {
        if ($dnsBlock.dns_record_name -eq $siteInfo.domain) {
            $wafHost = $dnsBlock.set_data_to[0]
            Write-VenDebugLog "Imperva Site $($siteInfo.domain) uses front-end $($wafHost)"
        }
    }

    $siteSerial=($siteInfo.ssl.custom_certificate.serialNumber -replace ':','')
    $siteThumb=($siteInfo.ssl.custom_certificate.fingerPrint -replace 'SHA1 Fingerprint=','' -replace ':','')

    if (($Script:ImportLegacy -eq $true) -and ($siteSerial -eq '')) {
        Write-VenDebugLog "Legacy Site: Pulling serial number and thumbprint from WAF front-end (API spoof)"
        $siteCert = Get-CertFromWaf -WafHost $wafHost -Target $siteInfo.domain

        $siteSerial = $siteCert.X509.SerialNumber.TrimStart('0')
        $siteThumb  = $siteCert.X509.Thumbprint.TrimStart('0')
    }

    if ($siteSerial -eq $null) {
        Write-VenDebugLog "No serial number retrieved from Imperva Cloud WAF"
        throw("Serial Number not available from Imperva Cloud WAF");
    }

    if ($siteThumb -eq $null) {
        Write-VenDebugLog "No fingerprint retrieved from Imperva Cloud WAF"
        throw("Fingerprint not available from Imperva Cloud WAF");
    }

    if ($siteInfo.ssl.custom_certificate.expirationDate -eq $null) {
        Write-VenDebugLog "No expiration date retrieved from Imperva Cloud WAF"
        throw("Expiration date not available from Imperva Cloud WAF");
    } else {
        $certExpires=Convert-ImpervaTimestamp $siteInfo.ssl.custom_certificate.expirationDate
        Write-VenDebugLog "Certificate Valid Until $($certExpires)"
    }

    Write-VenDebugLog "Extracted Thumbprint and Serial Number - Returning control to Venafi"
    return @{ Result="Success"; Serial=$siteSerial; Thumbprint=$siteThumb }
}

function Extract-PrivateKey
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General,
        [Parameter(Mandatory=$true,HelpMessage="Function Specific Parameters")]
        [System.Collections.Hashtable]$Specific
    )

    return @{ Result="NotUsed"; }
}

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

#
# Discover-Certificates function is used for onboard discovery
#
# Note that Imperva does not provide a mechanism to export either
# the public or private certificate via API forcing us to spoof
# Venafi's intended behavior. Tolerable, but far from ideal.
#
function Discover-Certificates
{
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )
 
    $started=Get-Date

    Initialize-VenDebugLog -General $General
#    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $wafId  =$General.UserName
    $wafKey =$General.UserPass
    $apiUrl ="https://my.imperva.com/api/prov/v1/sites/list"
    $apiAuth=@{'x-API-Id'=$wafId; 'x-API-Key'=$wafKey}

    if (($General.HostAddress -eq '') -or ($General.HostAddress -eq '*')) {
        $wafAccount="*"
    }
    else {
        $wafAccount=$General.HostAddress
#        Write-VenDebugLog "Imperva Account: [$($WafAccount)]"
    }

#    Write-VenDebugLog "Imperva API ID:  [$($wafId)]"
#    Write-VenDebugLog "Imperva API Key: [$($wafKey)]"
#    Write-VenDebugLog "Imperva API URL: [$($apiUrl)]"
    if ($General.AuxUser -gt 9) {
        $wafLegacy = $General.AuxUser
    Write-VenDebugLog "Legacy Import?:  YES ($($wafLegacy) days)"
    }
    else {
        $wafLegacy = $null
    }

    $siteList=@()

    # How many sites to pull per API call
    # 10 is a reasonably small/quick chunk
    # maximum supported by Imperva is 100
    $psize=10

    # Initialize Counters to 0
    $page=$siteCount=$skipped=$sslSites=$sslFree=$sslLegacyIgnored=$sslLegacyAdded=$sslDiscovered=$inactiveSites=$errorSites=0

    do {
        $batch=0
        if ($WafAccount -eq '*') {
            $apiBody="page_size=$($psize)&page_num=$($page)"
        }
        else {
            $apiBody="account_id=$($WafAccount)&page_size=$($psize)&page_num=$($page)"
        }

        try {
            Write-VenDebugLog "Requesting sites $(($page*$psize)+1) through $(($page+1)*($psize))"
            $siteInfo=Invoke-ImpervaRestMethod -General $General -Method Post -Uri $apiUrl -Body $apiBody
        }
        catch {
            Write-VenDebugLog "API method failure: $($siteInfo)"
            throw("API method failure: $($siteInfo)")
        }

        foreach($site in $siteInfo.sites) {
            $batch++
            $siteCount++
            $accountRegex="^$($WafAccount)$"
            if ($site.account_id -notmatch $accountRegex) {
                # this site is in a sub-account ... skipping
                $skipped++
                Write-VenDebugLog "Ignored: $($site.display_name) in sub-account #$($site.account_id)"
            }
            else {
                if ($site.ssl.custom_certificate.active -eq $true) {
                    $siteError=''
                    $sslSites++
                    if ($site.ssl.custom_certificate.hostnameMismatchError -eq $true) {
                        $siteError += 'Hostname Mismatch, '
                    }
                    if ($site.ssl.custom_certificate.validityError -eq $true) {
                        $siteError += 'Validity, '
                    }
                    if ($site.active -ne 'active') {
                        $inactiveSites++
                        Write-VenDebugLog "Ignored: $($site.display_name) is inactive"
                    } # site is NOT active
                    elseif ($siteError -ne '') {
                        $errorSites++
                        Write-VenDebugLog "Ignored: $($site.display_name) has errors ($($siteError.TrimEnd(' ,')))"
                    } # certificate has errors
                    else {
                        foreach($entry in $site.dns) {
                            if ($entry.dns_record_name -eq $site.display_name) {
                                if (($site.ssl.custom_certificate.serialNumber -eq $null) -and ($Script:ImportLegacy -ne $true)) {
                                    Write-VenDebugLog "Ignored: $($site.display_name) is a legacy SSL site"
                                    $sslLegacyIgnored++
                                } # legacy site - no serial/thumbprint
                                else {
                                    if ($site.ssl.custom_certificate.serialNumber -eq $null) {
                                        $sslLegacyAdded++
                                        Write-VenDebugLog "Discovered: [$($site.display_name)] (Legacy Site #$($site.site_id) at $($entry.set_data_to[0]))"
                                    }
                                    else {
                                        $sslDiscovered++
                                        Write-VenDebugLog "Discovered: [$($site.display_name)] (Site #$($site.site_id) at $($entry.set_data_to[0]))"
                                    }
                                    $siteCert = Get-CertFromWaf -WafHost $entry.set_data_to[0] -Target $site.display_name
                                    if ($site.ssl.custom_certificate.serialNumber -eq $null) {
                                        $siteSerial=($siteCert.X509.SerialNumber.TrimStart('0'))
                                        $siteThumb=($siteCert.X509.Thumbprint.TrimStart('0'))
                                    } # Spoof API for Legacy site
                                    else {
                                        $siteSerial=($site.ssl.custom_certificate.serialNumber -replace ':','')
                                        $siteThumb=($site.ssl.custom_certificate.fingerPrint -replace 'SHA1 Fingerprint=','' -replace ':','')
                                    } # Read/Use serial number and thumbprint provided by API
#                                    Write-VenDebugLog "\\-- Common Name:   [$($siteCert.X509.GetNameInfo(0,$false))]"
#                                    Write-VenDebugLog "\\-- Issuer (CA):   [$($siteCert.X509.GetNameInfo(0,$true))]"
                                    Write-VenDebugLog "Certificate '$($siteCert.X509.GetNameInfo(0,$false))' issued by '$($siteCert.X509.GetNameInfo(0,$true))'"
                                    if (($site.ssl.custom_certificate.serialNumber -ne $null) -and (($siteCert.X509.SerialNumber.TrimStart('0') -ne $siteSerial.TrimStart('0')) -or ($siteCert.X509.Thumbprint.TrimStart('0') -ne $siteThumb.TrimStart('0')))) {
                                        # This is a pretty annoying bug for wildcard users
                                        # Every site retains its own certificate details...
                                        # ...BUT uploading a wildcard on any site affects all
                                        # To make the info "look" right you have to upload the
                                        # wildcard to each and every site which is silly...
                                        #
                                        # ...BUT we should at least flag/note this in the logs.
                                        Write-VenDebugLog "WARNING: Imperva Bug - Certificate Mismatch in API vs WAF - Validation will FAIL"
                                        Write-VenDebugLog "\\-- API: Serial=$($siteSerial) Thumbprint=$($siteThumb)"
                                        Write-VenDebugLog "\\-- WAF: Serial=$($siteCert.X509.SerialNumber) Thumbprint=$($siteCert.X509.Thumbprint)"
                                        Write-VenDebugLog "\\-- Reinstall certificate via API or WebUI to fix this issue"
                                    } # UI/WAF mismatch warning
#                                    else {
#                                        Write-VenDebugLog "\\-- Serial Number: [$($siteSerial)]"
#                                        Write-VenDebugLog "\\-- Thumbprint:    [$($siteThumb)]"
#                                    }
                                    if ($site.ssl.custom_certificate.chainError -eq $true) {
                                        Write-VenDebugLog 'WARNING: Imperva reports a "chain error" for this certificate...'
                                    }
                                    $wafSite = @{
                                        Name = "$($site.display_name)" # Name of the Adaptable Application object
                                        PEM = $siteCert.PEM            # Formatted PEM version of the public certificate
                                        # Venafi currently fails when trying to validate this way ... SNI issue..?
                                        ValidationAddress = "$($entry.set_data_to[0])" # FQDN of Imperva WAF Front-End
                                        ValidationPort = 443           # TCP port (Currently hard coded to 443)
                                        Attributes = @{
                                            "Text Field 1" = "$($site.site_id)"
    #                                        "Text Field 2" = ""
    #                                        "Text Field 3" = ""
    #                                        "Text Field 4" = ""
    #                                        "Text Field 5" = ""
    #                                        "Certificate Name" = ""
                                        }
                                    } # Venafi Application definition for the current site
                                    $siteList += $wafSite
                                } # API returned serial & thumbprint
                            } # dns_record_name entry matches site_name
                        } # foreach $site.dns entry
                    } # else ... site is active
                } # $site.ssl.custom_certificate.active TRUE
                else {
                    $sslFree++
                    Write-VenDebugLog "Ignored: $($site.display_name) is unencrypted"
                } # WAF on an HTTP only site.?! Eeew...
            } # site.account_id matches accountRegex
        } # foreach $site
        $page++
    } while ($batch -eq $psize)

    if ($sslDiscovered+$sslLegacyAdded -gt 0) {
        $logMessage = "Discovered $($sslDiscovered+$sslLegacyAdded) secure sites"
        if ($sslLegacyAdded -gt 0) {
            $logMessage += " ($($sslLegacyAdded) legacy)"
        }
        Write-VenDebugLog $logMessage
    }
    if ($sslLegacyIgnored+$errorSites+$sslFree+$inactiveSites+$skipped -gt 0) {
        $logMessage = "Ignored $($sslLegacyIgnored+$errorSites+$sslFree+$inactiveSites+$skipped) sites ("
        if ($sslFree -gt 0)          { $logMessage += "$($sslFree) unencrypted, " }
        if ($sslLegacyIgnored -gt 0) { $logMessage += "$($sslLegacyIgnored) legacy, " }
        if ($errorSites -gt 0)       { $logMessage += "$($errorSites) cert errors, " }
        if ($inactiveSites -gt 0)    { $logMessage += "$($inactiveSites) inactive, " }
        if ($skipped -gt 0)          { $logMessage += "$($skipped) sub-account sites" }
        Write-VenDebugLog "$($logMessage.TrimEnd(', ')))"
    }

    $finished = Get-Date
    $runtime = New-TimeSpan -Start $started -End $finished
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
        [Parameter(Position=0, Mandatory)][string]$LogMessage,
        [switch]$NoFunctionTag
    )

    filter Add-TS {"$(Get-Date -Format o): $_"}

    # if the logfile isn't initialized then do nothing and return immediately
    if ($Script:venDebugFile -eq $null) { return }

    if ($NoFunctionTag.IsPresent) {
        $taggedLog = $LogMessage
    }
    else {
        $taggedLog = "[$((Get-PSCallStack)[1].Command)] $($LogMessage)"
    }

    # write the message to the debug file
    Write-Output "$($taggedLog)" | Add-TS | Add-Content -Path $Script:venDebugFile
}

function Initialize-VenDebugLog
{
    Param(
        [Parameter(Position=0, Mandatory)][System.Collections.Hashtable]$General
    )

    if ($Script:venDebugFile -ne $null) {
        Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"
        Write-VenDebugLog 'WARNING: Initialize-VenDebugLog() called more than once!'
        return
    }

    if ($DEBUG_FILE -eq $null) {
        # do nothing and return immediately if debug isn't on
        if ($General.VarBool1 -eq $false) { return }
        # pull Venafi base directory from registry for global debug flag
        $logPath = "$((Get-ItemProperty HKLM:\Software\Venafi\Platform).'Base Path')Logs"
    }
    else {
        # use the path but discard the filename from the DEBUG_FILE variable
        $logPath = "$(Split-Path -Path $DEBUG_FILE)"
    }

    $Script:venDebugFile = "$($logPath)\$($Script:AdaptableAppDrv.Replace(' ',''))"
    if ($General.HostAddress -ne '') {
        $Script:venDebugFile += "-Acct$($General.HostAddress)"
    }
    $Script:venDebugFile += ".log"
    
    Write-Output '' | Add-Content -Path $Script:venDebugFile

    Write-VenDebugLog -NoFunctionTag -LogMessage "$($Script:AdaptableAppDrv) v$($Script:AdaptableAppVer): Venafi called $((Get-PSCallStack)[1].Command)"
    Write-VenDebugLog -NoFunctionTag -LogMessage "PowerShell Environment: $($PSVersionTable.PSEdition) Edition, Version $($PSVersionTable.PSVersion.Major)"

    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"
}

function Invoke-ImpervaRestMethod
{
	Param(
        [Parameter(Mandatory)] [System.Collections.Hashtable] $General,
		[Parameter(Mandatory)] [Uri] $Uri,
		[Parameter(Mandatory)] [Microsoft.PowerShell.Commands.WebRequestMethod] $Method,
		[System.Object] $Body,
		[string] $ContentType = 'application/x-www-form-urlencoded',
		[int] $TimeoutSec
	)

    Write-VenDebugLog "$((Get-PSCallStack)[1].Command)/$($Method) as API-ID $($General.UserName): $($Uri)"

    $apiAuth = @{
        'x-API-Id'  = $General.UserName;
        'x-API-Key' = $General.UserPass
    }

    try {
        $response = Invoke-RestMethod -Uri $Uri -Method $Method -Headers $apiAuth -Body $Body -ContentType $ContentType -TimeoutSec $TimeoutSec
    }
    catch {
        Write-VenDebugLog "REST call failed to '$($Uri)'"
		throw $_
    }

    $response
}

function Convert-ImpervaTimestamp
{
    Param( [Parameter(Position=0, Mandatory)][String]$Timestamp )

    # Convert Imperva microseconds to seconds
    $epoch=$Timestamp/1000

    ([DateTime]'1/1/1970Z').AddSeconds($epoch)
}

function Get-ImpervaErrorMessage
{
    Param( [Parameter(Position=0, Mandatory)][string]$Code )

    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    $ImpervaError = @{
        '1'='The server has encountered an unexpected error'
        '2'='Input missing or incorrect'
        '4'='The server is not available or reached a time-out while processing the operation'
        '3015'='Internal error, please try again'
        '4205'='The site does not support SSL (HTTPS)'
        '9403'='The specified account is unknown or client is not authorized to operate on it'
        '9411'='Authentication parameters missing or incorrect'
        '9413'='The specified site is unknown or client is not authorized to operate on it'
        '9414'="Feature is not available on account's plan"
        '9415'='The requested operation is not allowed'
    }

    if ($ImpervaError[$Code] -eq $null) {
        return "Unknown Imperva Error Code: $($Code)"
    }

    $ImpervaError[$Code]
}

function Get-CertFromWaf
{
    Param(
        [Parameter(Mandatory=$true)][string]$WafHost,
        [Parameter(Mandatory=$true)][string]$Target,
        [string]$Port='443'
    )

    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

    $wafUri = "https://$($WafHost):$($Port)"

    Write-VenDebugLog "Pulling certificate for $($Target) via front-end $($WafHost)"

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

    try {
        # We're not parsing the webpage so '-UseBasicParsing' helps
        # prevent meaningless IE setup errors messages here...
        Invoke-WebRequest -Uri "$($wafUri)" -Headers @{Host="$($Target)"} -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop | Out-Null
    }
    catch {
        # Log the error but keep on trucking...
        # We only want the TLS handshake anyway.
        Write-VenDebugLog "Get-CertFromWaf Error: $($_) (ignoring)"
    }

    $sp = [System.Net.ServicePointManager]::FindServicePoint("$($wafUri)")

    $wafCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $wafCert.Import($sp.Certificate.GetRawCertData())

    $pemData = [Convert]::ToBase64String($wafCert.GetRawCertData(),'InsertLineBreaks')

    $FormattedPEM = "-----BEGIN CERTIFICATE-----`n$($pemData)`n-----END CERTIFICATE-----"

    $results = @{
        X509   = $wafCert
        PEM    = $FormattedPem
    }

    $results
}

# END OF SCRIPT