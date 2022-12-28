#
# Imperva Cloud WAF - An Adaptable Application Driver for Venafi
#
# CCamacho Template Driver Version: 202006101700
#
$Script:AdaptableAppVer = '202212281709'
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
        if ($siteInfo.res -eq 3015) {
            Write-VenDebugLog "Temporary Error - Returning control to Venafi (Resume Later)"
            return @{ Result="ResumeLater"; }
        }
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
    # This line tells VS Code to not flag this function's name as a "problem"
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseApprovedVerbs', '', Justification='Forced by Venafi', Scope='function')]
    
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )

    return @{ Result="NotUsed"; }
}

# MANDATORY FUNCTION
function Extract-Certificate
{
    # This line tells VS Code to not flag this function's name as a "problem"
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseApprovedVerbs', '', Justification='Forced by Venafi', Scope='function')]
    
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

    $customCert = Get-ImpervaCustomCertificate -General $General -Website $siteInfo

    Write-VenDebugLog "Extracted Thumbprint and Serial Number - Returning control to Venafi"
    return @{ Result="Success"; Serial=$($customCert.serialNumber); Thumbprint=$($customCert.fingerprint) }
}

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
    # This line tells VS Code to not flag this function's name as a "problem"
    [Diagnostics.CodeAnalysis.SuppressMessage('PSUseApprovedVerbs', '', Justification='Forced by Venafi', Scope='function')]
    
    Param(
        [Parameter(Mandatory=$true,HelpMessage="General Parameters")]
        [System.Collections.Hashtable]$General
    )
 
    $started=Get-Date

    Initialize-VenDebugLog -General $General

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $apiUrl ="https://my.imperva.com/api/prov/v1/sites/list"

    if (($General.HostAddress -eq '') -or ($General.HostAddress -eq '*')) {
        $wafAccount='*'
    }
    else {
        $wafAccount=$General.HostAddress
    }

    # How many sites to pull per API call - 10 is a reasonably small/quick chunk
    # maximum supported by Imperva is 100
    $psize=10

    # Initialize counters, arrays, lists
    $page=$siteCount=$skipped=$sslSites=$sslFree=$sslLegacyIgnored=$sslLegacyAdded=$sslDiscovered=$inactiveSites=0
    $siteList=@()

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
            elseif ($site.active -ne 'active') {
                # This site is NOT active...
                $inactiveSites++
                Write-VenDebugLog "Ignored: $($site.display_name) is inactive"
            }
            else {
                $customCert = Get-ImpervaCustomCertificate -General $General -Website $site
                if ($customCert) {
                    $wafHost = $customCert.wafHost
                    $sslSites++
                    if ($customCert.legacy) {
                        $sslLegacyAdded++
                        Write-VenDebugLog "Discovered: [$($site.display_name)] (Legacy Site #$($site.site_id) at $($wafHost))"
                    }
                    else {
                        $sslDiscovered++
                        Write-VenDebugLog "Discovered: [$($site.display_name)] (Site #$($site.site_id) at $($wafHost))"
                    }
                    $wafSite = @{
                        Name = "$($site.display_name)"      # Name of the Adaptable Application object
                        PEM = $customCert.certificate.PEM   # Formatted PEM version of the public certificate
                        # Venafi currently fails when trying to validate this way due to weak SNI support
                        ValidationAddress = $wafHost        # FQDN of Imperva WAF Front-End
                        ValidationPort = 443                # TCP port (Currently hard coded to 443)
                        Attributes = @{
                            "Text Field 1" = "$($site.site_id)"
#                           "Certificate Name" = ""
                        }
                    } # Venafi Application definition for the current site
                    $siteList += $wafSite
                } # custom certificate was retrieved
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
    if ($sslLegacyIgnored+$sslFree+$inactiveSites+$skipped -gt 0) {
        $logMessage = "Ignored $($sslLegacyIgnored+$sslFree+$inactiveSites+$skipped) sites ("
        if ($sslFree -gt 0)          { $logMessage += "$($sslFree) unencrypted, " }
        if ($sslLegacyIgnored -gt 0) { $logMessage += "$($sslLegacyIgnored) legacy, " }
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
    if ($null -eq $Script:venDebugFile) { return }

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

    # if the debugfile is already setup we shouldn't be called again - log a warning
    if ($null -ne $Script:venDebugFile) {
        Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"
        Write-VenDebugLog 'WARNING: Initialize-VenDebugLog() called more than once!'
        return
    }

    if ($null -eq $DEBUG_FILE) {
        # do nothing and return immediately if debug isn't on
        if ($General.VarBool1 -eq $false) { return }

        # pull Venafi base directory from registry for global debug flag
        $logPath = "$((Get-ItemProperty HKLM:\Software\Venafi\Platform).'Base Path')Logs"
    }
    else {
        # use the path but discard the filename from the DEBUG_FILE variable
        $logPath = "$(Split-Path -Path $DEBUG_FILE)"
    }

    # add a filename to the base log directory path
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

    $Attempts=3
    $i=0
    do {
        try {
            $response = Invoke-RestMethod -Uri $Uri -Method $Method -Headers $apiAuth -Body $Body -ContentType $ContentType -TimeoutSec $TimeoutSec
        }
        catch {
            Write-VenDebugLog "REST call failed to '$($Uri)'"
            throw $_
        }
        # return response upon success, otherwise retry
        if ($response.res -eq 0) { return $response }
        $i++
        $wait = Get-Random -Minimum ($i+1) -Maximum ($i*3)
        Write-VenDebugLog "Attempt #$($i) failed ($($response.debug_info.Error)) - sleeping for $($wait) seconds"
        Start-Sleep -Seconds $wait
    } while ($i -lt $Attempts)

    # if API call keeps failing just return bad results
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

    if ($null -eq $ImpervaError[$Code]) {
        return "Unknown Imperva Error Code: $($Code)"
    }

    $ImpervaError[$Code]
}

function Get-ImpervaCustomCertificate
{
    Param(
        [Parameter(Mandatory)] [System.Collections.Hashtable] $General,
        [Parameter(Mandatory)] [PSCustomObject] $Website
    )

    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"

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
    }
    catch {
        $fatal = "Failed to retrieve custom certificate data: $($_)"
        Write-VenDebugLog $fatal
        throw $fatal
    }

    $responseData = (($response.Content | ConvertFrom-Json).data)

    # This should only happen during discovery of an unencrypted site
    if ($responseData.Count -eq 0) {
#        Write-VenDebugLog "No custom certificate found for $($siteName) (site #$($siteId))"
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
        return $null
    }
    elseif ($responseData.status -notin $GoodImpervaStatus) {
        Write-VenDebugLog "ERROR: Unexpected certificate status '$($responseData.status)' for $($siteName) (site #$($siteId))"
        return $null
    }

    # Always attempt to pull the public certificate from the WAF front-end
    # This is as much to generate warnings for API bugs as it is to support discovery
    $siteCert = Get-CertFromWaf -WafHost $wafHost -Target $Website.domain

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
        Write-VenDebugLog "Certificate '$($siteCert.X509.GetNameInfo(0,$false))' issued by '$($siteCert.X509.GetNameInfo(0,$true))'"
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

    Write-VenDebugLog "Serial=$($siteSerial), Thumbprint=$($siteThumb)"

    if ($responseData.customCertificateDetails.hasMismatchSite -eq $true) {
        Write-VenDebugLog 'WARNING: Imperva reports a "site mismatch" error... The certificate does not match the site name!'
    }

    Write-VenDebugLog "Certificate Valid Until $($certExpires)"

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

    Write-VenDebugLog "Called by $((Get-PSCallStack)[1].Command)"
    Write-VenDebugLog "Pulling certificate for $($Target) via front-end $($WafHost)"

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
    $wafUri = "https://$($WafHost):$($Port)"

    try {
        # open a network connection to the Imperva front-end. Be sure to pass the proper host request header!
        # We're not parsing the webpage so '-UseBasicParsing' helps prevent meaningless IE setup errors messages...
        Invoke-WebRequest -Uri "$($wafUri)" -Headers @{Host="$($Target)"} -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop | Out-Null
    }
    catch {
        # Log the error but keep on trucking... We only want the TLS handshake anyway.
        Write-VenDebugLog "Ignoring Error: $($_)"
    }

    # find the open network connection then import the raw certificate data 
    $sp = [System.Net.ServicePointManager]::FindServicePoint("$($wafUri)")
    $wafCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $wafCert.Import($sp.Certificate.GetRawCertData())

    # create a base-64 formatted string from the certificate (aka PEM data format)
    $pemData = [Convert]::ToBase64String($wafCert.GetRawCertData(),'InsertLineBreaks')
    $FormattedPEM = "-----BEGIN CERTIFICATE-----`n$($pemData)`n-----END CERTIFICATE-----"

    # build an object that contains both the certificate object and PEM string data
    $results = @{
        X509   = $wafCert
        PEM    = $FormattedPem
    }

    $results
}

# END OF SCRIPT