# Windows Location & Network Exposure Audit v3.4
# Free to share and adapt. Provided as-is, without warranty.
# Requires: Windows 11, Windows PowerShell 5.1 (or compatible PowerShell on Windows).
# Read-only for Windows settings. Creates TXT and HTML files in OutputDirectory.
# OutputDirectory defaults to the script directory. Opens the HTML after completion.
# Use -NoBrowserProbe for a quiet run, or -OutputDirectory to override the destination.
#
# Examples:
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\WindowsLocationAudit_v3_4.ps1
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\WindowsLocationAudit_v3_4.ps1 -Online -WindowsLocation -OpenBrowserProbe
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\WindowsLocationAudit_v3_4.ps1 -Online -ShareSafe
#
# Network providers contacted only with -Online:
#   api64.ipify.org (IP echo); www.cloudflare.com/cdn-cgi/trace (IP echo + country);
#   ipwho.is, ipinfo.io, ip-api.com (IP geolocation; ip-api.com free tier is plain HTTP);
#   akahelp.net, o-o.myaddr.l.google.com, example.com, www.wikipedia.org (DNS diagnostics).
# -WindowsLocation requests location from the Windows provider (which may itself use a network service).
# Browser probe contacts cloudflare.com, ipify.org, ipwho.is and public STUN servers ONLY after a click.
# -ShareSafe redacts common identifiers in the text output and avoids embedding IPs or
# coordinates in the HTML, but manually review any report before publishing.

[CmdletBinding()]
param(
    [switch]$Online,
    [switch]$WindowsLocation,
    [switch]$OpenBrowserProbe = $true,
    [switch]$NoBrowserProbe,
    [switch]$ShareSafe,
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
# Resolve script automatic variables in the body. Windows PowerShell 5.1 -File
# can evaluate parameter defaults before $PSScriptRoot has been populated.
if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) {
    $OutputDirectory = $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($OutputDirectory) -and $PSCommandPath) {
        $OutputDirectory = [System.IO.Path]::GetDirectoryName($PSCommandPath)
    }
    if ([string]::IsNullOrWhiteSpace($OutputDirectory) -and $MyInvocation.MyCommand.Path) {
        $OutputDirectory = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
    }
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    throw 'Cannot determine output directory. Supply a non-empty -OutputDirectory path.'
}
$report = New-Object 'System.Collections.Generic.List[string]'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
    throw "Output directory not found: $OutputDirectory"
}
$OutputDirectory = (Get-Item -LiteralPath $OutputDirectory).FullName
$txtFile = Join-Path $OutputDirectory "WindowsLocationAudit_v3_4_$stamp.txt"
$htmlFile = Join-Path $OutputDirectory "BrowserLocationProbe_v3_4_$stamp.html"

$script:dnsResults = New-Object 'System.Collections.Generic.List[object]'
$script:signals = New-Object 'System.Collections.Generic.List[object]'
$script:routeSummary = New-Object 'System.Collections.Generic.List[string]'
$script:windowsFix = $null
$script:windowsLocationStatus = 'SKIPPED'
$script:geoCache = @{}
$script:geoCache2 = @{}
$script:homeIso = $null
$script:sysOffsetSec = [int][TimeZoneInfo]::Local.GetUtcOffset([DateTime]::Now).TotalSeconds
$script:fakeIp = $null
$script:proxyClients = @()
$script:envProxySet = [bool]([Environment]::GetEnvironmentVariable('HTTPS_PROXY', 'Process') -or
                             [Environment]::GetEnvironmentVariable('ALL_PROXY', 'Process'))

# Offline fallback Windows GeoID -> ISO 3166-1 alpha-2 for major countries/regions.
# IDs: https://learn.microsoft.com/en-us/windows/win32/intl/table-of-geographical-locations
# Get-GeoIdCountry also supplements this table from the installed .NET region data.
$script:GeoIdMap = @{
    # Americas
    '244' = @('US', 'United States');  '39'  = @('CA', 'Canada');     '166' = @('MX', 'Mexico')
    '32'  = @('BR', 'Brazil');         '11'  = @('AR', 'Argentina');  '46'  = @('CL', 'Chile')
    '51'  = @('CO', 'Colombia');       '187' = @('PE', 'Peru')
    '66'  = @('EC', 'Ecuador');        '249' = @('VE', 'Venezuela'); '246' = @('UY', 'Uruguay')
    '26'  = @('BO', 'Bolivia');        '185' = @('PY', 'Paraguay');  '54'  = @('CR', 'Costa Rica')
    '192' = @('PA', 'Panama');         '99'  = @('GT', 'Guatemala'); '56'  = @('CU', 'Cuba')
    '65'  = @('DO', 'Dominican Republic'); '124' = @('JM', 'Jamaica'); '225' = @('TT', 'Trinidad and Tobago')
    '72'  = @('SV', 'El Salvador');    '106' = @('HN', 'Honduras');  '182' = @('NI', 'Nicaragua')
    '22'  = @('BS', 'Bahamas');        '24'  = @('BZ', 'Belize');    '202' = @('PR', 'Puerto Rico')
    # Asia, including Western and Central Asia
    '45'  = @('CN', 'China');          '104' = @('HK', 'Hong Kong SAR'); '151' = @('MO', 'Macao SAR')
    '237' = @('TW', 'Taiwan');         '122' = @('JP', 'Japan');      '134' = @('KR', 'Korea')
    '215' = @('SG', 'Singapore');      '113' = @('IN', 'India');      '111' = @('ID', 'Indonesia')
    '167' = @('MY', 'Malaysia');       '227' = @('TH', 'Thailand');   '251' = @('VN', 'Vietnam')
    '201' = @('PH', 'Philippines');    '224' = @('AE', 'United Arab Emirates')
    '205' = @('SA', 'Saudi Arabia');   '117' = @('IL', 'Israel');     '235' = @('TR', 'Turkey')
    '23'  = @('BD', 'Bangladesh');     '190' = @('PK', 'Pakistan');  '42'  = @('LK', 'Sri Lanka')
    '178' = @('NP', 'Nepal');          '40'  = @('KH', 'Cambodia');  '138' = @('LA', 'Laos')
    '27'  = @('MM', 'Myanmar');        '154' = @('MN', 'Mongolia');  '137' = @('KZ', 'Kazakhstan')
    '247' = @('UZ', 'Uzbekistan');     '197' = @('QA', 'Qatar');     '136' = @('KW', 'Kuwait')
    '17'  = @('BH', 'Bahrain');        '164' = @('OM', 'Oman');      '116' = @('IR', 'Iran')
    '121' = @('IQ', 'Iraq');           '126' = @('JO', 'Jordan');    '139' = @('LB', 'Lebanon')
    '37'  = @('BN', 'Brunei');         '165' = @('MV', 'Maldives');  '34'  = @('BT', 'Bhutan')
    '5'   = @('AZ', 'Azerbaijan');     '7'   = @('AM', 'Armenia');   '88'  = @('GE', 'Georgia')
    # Europe (Russia and Turkey span Europe and Asia)
    '203' = @('RU', 'Russia')
    '242' = @('GB', 'United Kingdom'); '94'  = @('DE', 'Germany');   '84'  = @('FR', 'France')
    '118' = @('IT', 'Italy');          '217' = @('ES', 'Spain');     '193' = @('PT', 'Portugal')
    '176' = @('NL', 'Netherlands');    '21'  = @('BE', 'Belgium');   '223' = @('CH', 'Switzerland')
    '14'  = @('AT', 'Austria');        '68'  = @('IE', 'Ireland');   '221' = @('SE', 'Sweden')
    '177' = @('NO', 'Norway');         '61'  = @('DK', 'Denmark');   '77'  = @('FI', 'Finland')
    '191' = @('PL', 'Poland');         '75'  = @('CZ', 'Czechia');   '143' = @('SK', 'Slovakia')
    '109' = @('HU', 'Hungary');        '200' = @('RO', 'Romania');   '35'  = @('BG', 'Bulgaria')
    '98'  = @('GR', 'Greece');         '108' = @('HR', 'Croatia');   '212' = @('SI', 'Slovenia')
    '271' = @('RS', 'Serbia');         '241' = @('UA', 'Ukraine');   '29'  = @('BY', 'Belarus')
    '70'  = @('EE', 'Estonia');        '140' = @('LV', 'Latvia');    '141' = @('LT', 'Lithuania')
    '110' = @('IS', 'Iceland');        '147' = @('LU', 'Luxembourg'); '163' = @('MT', 'Malta')
    '59'  = @('CY', 'Cyprus')
    # Oceania
    '12'  = @('AU', 'Australia');      '183' = @('NZ', 'New Zealand')
}
$script:geoIdMapExpanded = $false

$script:VirtualAdapterPattern = '(?i)wintun|tap-windows|\btap\b|wireguard|\btun\b|tun\d|\bmeta\b|clash|mihomo|sing-?box|v2ray|xray|openvpn|nekoray|hiddify|zerotier|tailscale|outline|vpn'
$script:ProxyProcessPattern = '(?i)clash|mihomo|sing-?box|v2ray|xray|nekoray|nekobox|hiddify|shadowsocks|ss-local|trojan|naive|tun2socks|wireguard|openvpn|outline|tailscale|zerotier|psiphon|lantern|astrill|expressvpn|nordvpn|surfshark|protonvpn|karing|flclash'

# ---------------------------------------------------------------- helpers

function Read-Reg {
    param([string]$Path, [string]$Name)
    try {
        $v = (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name
        if ($null -eq $v) { return '(not set)' }
        return [string]$v
    }
    catch { return '(not present or inaccessible)' }
}

function Protect-IP {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return '(unavailable)' }
    if (-not $ShareSafe) { return $Address }
    try {
        $parsed = [System.Net.IPAddress]::Parse($Address)
        if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            $octets = $Address.Split('.')
            return ($octets[0] + '.' + $octets[1] + '.x.x')
        }
        $parts = $parsed.ToString().Split(':')
        return ($parts[0] + ':' + $parts[1] + ':... [IPv6 redacted]')
    }
    catch { return '(redacted)' }
}

function Section {
    param([string]$Title, [scriptblock]$Body)
    $script:report.Add('')
    $script:report.Add("===== $Title =====")
    try {
        $v = (& $Body 2>&1 | Out-String -Width 200).Trim()
        if (-not $v) { $v = '(no data)' }
        $script:report.Add($v)
    }
    catch { $script:report.Add("CHECK FAILED: $($_.Exception.Message)") }
}

function Test-IPAddress {
    param([string]$Text)
    $parsed = $null
    if ([System.Net.IPAddress]::TryParse($Text, [ref]$parsed)) { return $parsed }
    return $null
}

function Initialize-GeoIdMap {
    if ($script:geoIdMapExpanded) { return }
    $script:geoIdMapExpanded = $true
    try {
        foreach ($culture in [System.Globalization.CultureInfo]::GetCultures([System.Globalization.CultureTypes]::SpecificCultures)) {
            try {
                $region = New-Object System.Globalization.RegionInfo($culture.Name)
                $iso = $region.TwoLetterISORegionName
                $id = [string]$region.GeoId
                if ($region.GeoId -gt 0 -and $iso -match '^[A-Z]{2}$' -and $iso -notin @('ZZ', 'XX') -and
                    -not $script:GeoIdMap.ContainsKey($id)) {
                    $script:GeoIdMap[$id] = @($iso, $region.EnglishName)
                }
            }
            catch { } # One unsupported culture must not stop country recognition.
        }
    }
    catch { } # Keep the offline fallback table if system region data is unavailable.
}

function Get-GeoIdCountry {
    param([string]$GeoId)
    $id = 0
    if (-not [int]::TryParse($GeoId, [ref]$id) -or $id -le 0) { return $null }
    Initialize-GeoIdMap
    $key = [string]$id
    if ($script:GeoIdMap.ContainsKey($key)) {
        $e = $script:GeoIdMap[$key]
        return [PSCustomObject]@{ ISO = $e[0]; Name = $e[1] }
    }
    return $null
}

function Get-RegionFromCultureName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    try {
        $culture = [System.Globalization.CultureInfo]::GetCultureInfo($Name)
        if ($culture.IsNeutralCulture -or -not $culture.Name) { return $null }
        $region = New-Object System.Globalization.RegionInfo($culture.Name)
        $iso = $region.TwoLetterISORegionName
        if ($iso -match '^[A-Za-z]{2}$') { return $iso.ToUpperInvariant() }
    }
    catch { } # Unknown or unsupported culture: no country inference.
    return $null
}

function Add-Signal {
    param([string]$Name, [string]$Value, [string]$Country, [string]$Strength = 'Medium', [string]$Status)
    $c = if ($Country) { $Country.ToUpperInvariant() } else { $null }
    $script:signals.Add([PSCustomObject]@{ Name = $Name; Value = $Value; Country = $c; Strength = $Strength; Status = $Status })
}

# Runs an external program without letting stderr become a terminating error in PS 5.1.
function Invoke-Native {
    param([string]$FilePath, [string[]]$ArgumentList)
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = (& $FilePath @ArgumentList 2>&1 | ForEach-Object { [string]$_ } | Out-String).Trim()
        return [PSCustomObject]@{ ExitCode = $LASTEXITCODE; Output = $out }
    }
    finally { $ErrorActionPreference = $old }
}

function Invoke-CurlText {
    param([string]$Url, [ValidateSet(0, 4, 6)][int]$Family = 0, [switch]$UseEnvProxy)
    $cmd = Get-Command curl.exe -ErrorAction SilentlyContinue
    if (-not $cmd) { throw 'curl.exe not found' }
    $curlArgs = @('-sS', '-f', '--connect-timeout', '8', '--max-time', '16')
    if ($Family -eq 4) { $curlArgs += '--ipv4' }
    elseif ($Family -eq 6) { $curlArgs += '--ipv6' }
    if (-not $UseEnvProxy) { $curlArgs += @('--noproxy', '*') }
    $curlArgs += $Url
    $r = Invoke-Native -FilePath $cmd.Source -ArgumentList $curlArgs
    if ($r.ExitCode -ne 0) { throw "curl exit code $($r.ExitCode): $($r.Output)" }
    return $r.Output
}

# GET through the Windows system proxy (WinINET/PAC), i.e. the path browsers normally use.
function Invoke-SystemProxyGet {
    param([string]$Url)
    $uri = [Uri]$Url
    $sys = [System.Net.WebRequest]::GetSystemWebProxy()
    $sys.Credentials = [System.Net.CredentialCache]::DefaultCredentials
    $p = $sys.GetProxy($uri)
    $isDirect = ($null -eq $p) -or ($p.AbsoluteUri -eq $uri.AbsoluteUri) -or $sys.IsBypassed($uri)
    $params = @{ Uri = $uri; TimeoutSec = 16; ErrorAction = 'Stop' }
    if (-not $isDirect) {
        $params['Proxy'] = $p
        $params['ProxyUseDefaultCredentials'] = $true
        $content = Invoke-RestMethod @params
    }
    elseif ($PSVersionTable.PSVersion.Major -ge 6) {
        # Do not let HttpClient fall back to HTTPS_PROXY/ALL_PROXY.
        $params['NoProxy'] = $true
        $content = Invoke-RestMethod @params
    }
    else {
        # Windows PowerShell 5.1 has no -NoProxy switch.
        $request = [System.Net.WebRequest]::Create($uri)
        $request.Proxy = $null
        $request.Timeout = 16000
        $request.ReadWriteTimeout = 16000
        $response = $null; $reader = $null
        try {
            $response = $request.GetResponse()
            $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
            $content = $reader.ReadToEnd()
            if ($response.ContentType -match '(?i)json') {
                $content = $content | ConvertFrom-Json -ErrorAction Stop
            }
        }
        finally {
            if ($reader) { $reader.Dispose() }
            if ($response) { $response.Dispose() }
        }
    }
    $proxyLabel = if ($isDirect) { 'DIRECT' } else { $p.AbsoluteUri }
    return [PSCustomObject]@{ Content = $content; Proxy = $proxyLabel }
}

function ConvertFrom-Trace {
    param([string]$Text)
    $h = @{}
    foreach ($line in ($Text -split "`n")) {
        $kv = $line.Trim() -split '=', 2
        if ($kv.Count -eq 2) { $h[$kv[0]] = $kv[1] }
    }
    return [PSCustomObject]@{ IP = $h['ip']; Loc = $h['loc']; Colo = $h['colo'] }
}

function Get-GeoInfo {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $null }
    if ($script:geoCache.ContainsKey($Address)) { return $script:geoCache[$Address] }
    $g = $null
    try {
        $g = Invoke-RestMethod -Uri ("https://ipwho.is/" + $Address) -TimeoutSec 12 -ErrorAction Stop
        if ($g.success -eq $false) { $g = $null }
    }
    catch { $g = $null }
    $script:geoCache[$Address] = $g
    return $g
}

# Second-opinion geolocation databases. Used for egress addresses only (rate limits).
function Get-GeoSecondary {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $null }
    if ($script:geoCache2.ContainsKey($Address)) { return $script:geoCache2[$Address] }
    $ipinfoCountry = $null; $ipinfoOrg = $null; $ipapi = $null
    try {
        $i = Invoke-RestMethod -Uri ("https://ipinfo.io/" + $Address + "/json") -TimeoutSec 10 -ErrorAction Stop
        $ipinfoCountry = [string]$i.country
        $ipinfoOrg = [string]$i.org
    }
    catch { }
    try {
        $a = Invoke-RestMethod -Uri ("http://ip-api.com/json/" + $Address +
                "?fields=status,countryCode,isp,org,as,proxy,hosting,mobile") -TimeoutSec 10 -ErrorAction Stop
        if ($a.status -eq 'success') { $ipapi = $a }
    }
    catch { }
    $o = [PSCustomObject]@{ IpInfoCountry = $ipinfoCountry; IpInfoOrg = $ipinfoOrg; IpApi = $ipapi }
    $script:geoCache2[$Address] = $o
    return $o
}

function Get-DistanceKm {
    param([double]$Lat1, [double]$Lon1, [double]$Lat2, [double]$Lon2)
    $rad = [Math]::PI / 180.0
    $deltaLat = ($Lat2 - $Lat1) * $rad
    $deltaLon = ($Lon2 - $Lon1) * $rad
    $a = [Math]::Pow([Math]::Sin($deltaLat / 2.0), 2) +
         [Math]::Cos($Lat1 * $rad) * [Math]::Cos($Lat2 * $rad) *
         [Math]::Pow([Math]::Sin($deltaLon / 2.0), 2)
    $a = [Math]::Min(1.0, [Math]::Max(0.0, $a))
    return 12742.0 * [Math]::Asin([Math]::Sqrt($a))
}

function Test-GeoCoordinate {
    param([double]$Latitude, [double]$Longitude, [double]$Accuracy)
    if ([double]::IsNaN($Latitude) -or [double]::IsNaN($Longitude)) { return $false }
    if ([Math]::Abs($Latitude) -gt 90 -or [Math]::Abs($Longitude) -gt 180) { return $false }
    if ($Latitude -eq 0 -and $Longitude -eq 0) { return $false } # Common unavailable-value sentinel.
    if ([double]::IsNaN($Accuracy) -or $Accuracy -le 0 -or $Accuracy -gt 100000) { return $false }
    return $true
}

function Test-FakeAddress {
    param([string]$Address)
    $p = Test-IPAddress $Address
    if (-not $p) { return $false }
    $b = $p.GetAddressBytes()
    if ($p.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return ($b[0] -eq 198 -and ($b[1] -eq 18 -or $b[1] -eq 19))   # 198.18.0.0/15
    }
    return (($b[0] -band 0xFE) -eq 0xFC)                              # fc00::/7 (ULA)
}

function New-EgressResult {
    param([string]$Path, [string]$Status = 'SKIPPED')
    return [PSCustomObject]@{
        Path = $Path; Status = $Status; Address = $null; Geo = $null; Country = $null
        Agreement = $null; Votes = $null; Secondary = $null; TraceIP = $null; TraceLoc = $null
        ProxyUri = $null; Error = $null
    }
}

function Complete-EgressResult {
    param($Result, [string]$Address, $Trace)
    $Result.Address = $Address
    $Result.Geo = Get-GeoInfo $Address
    $Result.Secondary = Get-GeoSecondary $Address
    if ($Trace) { $Result.TraceIP = $Trace.IP; $Result.TraceLoc = $Trace.Loc }
    $votes = [ordered]@{}
    if ($Result.Geo -and $Result.Geo.country_code) { $votes['ipwho.is'] = ([string]$Result.Geo.country_code).ToUpperInvariant() }
    if ($Result.Secondary -and $Result.Secondary.IpInfoCountry) { $votes['ipinfo.io'] = $Result.Secondary.IpInfoCountry.ToUpperInvariant() }
    if ($Result.Secondary -and $Result.Secondary.IpApi -and $Result.Secondary.IpApi.countryCode) {
        $votes['ip-api.com'] = ([string]$Result.Secondary.IpApi.countryCode).ToUpperInvariant()
    }
    if ($Trace -and $Trace.IP -eq $Address -and $Trace.Loc -and $Trace.Loc -notin @('XX', 'T1')) {
        $votes['cloudflare'] = $Trace.Loc.ToUpperInvariant()
    }
    $Result.Votes = $votes
    $groups = @($votes.Values | Group-Object | Sort-Object Count -Descending)
    if ($groups.Count -eq 0) { $Result.Agreement = 'NO_DATA' }
    elseif ($votes.Count -eq 1) { $Result.Agreement = 'SINGLE_SOURCE'; $Result.Country = $groups[0].Name }
    elseif ($groups.Count -eq 1) { $Result.Agreement = 'AGREE'; $Result.Country = $groups[0].Name }
    else {
        $Result.Agreement = 'DISAGREE'
        if ($groups[0].Count -gt ($votes.Count / 2)) { $Result.Country = $groups[0].Name }
    }
    $Result.Status = 'OK'
}

function Test-DirectEgress {
    param([ValidateSet(4, 6)][int]$Family)
    # curl --ipv4/--ipv6 forces the remote connection family. --noproxy bypasses
    # application-level proxy environment settings but NOT the Windows TUN route.
    $res = New-EgressResult "Direct IPv$Family (curl --noproxy)" 'FAILED'
    try {
        $raw = Invoke-CurlText -Url 'https://api64.ipify.org?format=json' -Family $Family
        $address = [string](($raw | ConvertFrom-Json -ErrorAction Stop).ip)
        $parsed = Test-IPAddress $address
        if (-not $parsed) { throw 'IP response could not be parsed' }
        $expected = if ($Family -eq 4) { [System.Net.Sockets.AddressFamily]::InterNetwork }
                    else { [System.Net.Sockets.AddressFamily]::InterNetworkV6 }
        if ($parsed.AddressFamily -ne $expected) { throw 'Unexpected IP address family' }
        $trace = $null
        try { $trace = ConvertFrom-Trace (Invoke-CurlText -Url 'https://www.cloudflare.com/cdn-cgi/trace' -Family $Family) } catch { }
        Complete-EgressResult $res $address $trace
    }
    catch { $res.Error = $_.Exception.Message }
    return $res
}

function Test-SystemProxyEgress {
    $res = New-EgressResult 'System proxy (WinINET/PAC, browser-like)' 'FAILED'
    try {
        $r = Invoke-SystemProxyGet 'https://api64.ipify.org?format=json'
        $res.ProxyUri = $r.Proxy
        $address = [string]$r.Content.ip
        if (-not (Test-IPAddress $address)) { throw 'IP response could not be parsed' }
        $trace = $null
        try { $trace = ConvertFrom-Trace ([string](Invoke-SystemProxyGet 'https://www.cloudflare.com/cdn-cgi/trace').Content) } catch { }
        Complete-EgressResult $res $address $trace
    }
    catch { $res.Error = $_.Exception.Message }
    return $res
}

function Test-EnvProxyEgress {
    $res = New-EgressResult 'Environment proxy (curl HTTPS_PROXY/ALL_PROXY)' 'FAILED'
    try {
        $raw = Invoke-CurlText -Url 'https://api64.ipify.org?format=json' -UseEnvProxy
        $address = [string](($raw | ConvertFrom-Json -ErrorAction Stop).ip)
        if (-not (Test-IPAddress $address)) { throw 'IP response could not be parsed' }
        $trace = $null
        try { $trace = ConvertFrom-Trace (Invoke-CurlText -Url 'https://www.cloudflare.com/cdn-cgi/trace' -UseEnvProxy) } catch { }
        Complete-EgressResult $res $address $trace
    }
    catch { $res.Error = $_.Exception.Message }
    return $res
}

function Format-EgressLines {
    param($R)
    "$($R.Path): $($R.Status)"
    if ($R.Status -ne 'OK') {
        if ($R.Error) { "  Error: $($R.Error)" }
        return
    }
    "  Public address: $(Protect-IP $R.Address)"
    if ($R.ProxyUri) {
        "  Proxy decision: $(if ($ShareSafe -and $R.ProxyUri -ne 'DIRECT') { '(proxy, hidden in ShareSafe mode)' } else { $R.ProxyUri })"
    }
    if ($R.Votes -and $R.Votes.Count) {
        $v = @($R.Votes.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; '
        "  Country votes: $v"
    }
    "  Consensus country: $(if ($R.Country) { $R.Country } else { '(undetermined)' }) [$($R.Agreement)]"
    if ($R.Geo) {
        "  Region: $($R.Geo.country), $($R.Geo.region)"
        "  ISP / ASN: $($R.Geo.connection.isp) / $($R.Geo.connection.asn)"
        if ($R.Geo.timezone) { "  IP timezone: $($R.Geo.timezone.id) (UTC$($R.Geo.timezone.utc))" }
    }
    $api = if ($R.Secondary) { $R.Secondary.IpApi } else { $null }
    if ($api) { "  ip-api flags: hosting=$($api.hosting); proxy=$($api.proxy); mobile=$($api.mobile)" }
    if ($R.TraceIP) {
        if ($R.TraceIP -eq $R.Address) { "  Cloudflare trace: same IP; loc=$($R.TraceLoc)" }
        else { "  Cloudflare trace: DIFFERENT IP $(Protect-IP $R.TraceIP); loc=$($R.TraceLoc). Exit may rotate or split per destination." }
    }
}

# Browser-like path first, then direct IPv4, then direct IPv6.
function Get-ReferenceEgress {
    foreach ($r in @($script:proxyPath, $script:v4, $script:v6)) {
        if ($r -and $r.Status -eq 'OK' -and $r.Country) { return $r }
    }
    return $null
}

function Get-ResolverRecords {
    param([string]$Domain)
    # Akamai TXT replies often have separate "ns", "ecs" and "ip" TXT RRs,
    # with multiple Strings per record. Do not assume the first RR contains all fields.
    # Google replies with a bare resolver IP and "edns0-client-subnet <subnet>".
    $entries = New-Object 'System.Collections.Generic.List[object]'
    $records = @(Resolve-DnsName -Name $Domain -Type TXT -DnsOnly -ErrorAction Stop |
                 Where-Object { $_.Type -eq 'TXT' })
    foreach ($record in $records) {
        $parts = @($record.Strings | ForEach-Object { [string]$_ })
        $joined = (($parts -join ' ') -replace '["'']', '').Trim()
        if ($joined -match '(?i)edns0-client-subnet\s+([^\s]+)') {
            $entries.Add([PSCustomObject]@{ Kind = 'ecs'; Value = $Matches[1] })
        }
        elseif ($joined -match '(?i)\b(ns|ecs|ip)\s+([^\s]+)') {
            $entries.Add([PSCustomObject]@{ Kind = $Matches[1].ToLowerInvariant(); Value = $Matches[2] })
        }
        elseif ($Domain -eq 'o-o.myaddr.l.google.com') {
            $ip = Test-IPAddress $joined
            if ($ip) { $entries.Add([PSCustomObject]@{ Kind = 'ns'; Value = $joined }) }
        }
    }
    return @($entries.ToArray())
}

function ConvertTo-SafeScriptJson {
    param([string]$Json)
    return $Json.Replace('<', '\u003c').Replace('>', '\u003e').Replace('&', '\u0026').
                 Replace([string][char]0x2028, '\u2028').Replace([string][char]0x2029, '\u2029')
}

$script:v4 = New-EgressResult 'Direct IPv4 (curl --noproxy)'
$script:v6 = New-EgressResult 'Direct IPv6 (curl --noproxy)'
$script:proxyPath = New-EgressResult 'System proxy (WinINET/PAC, browser-like)'
$script:envPath = New-EgressResult 'Environment proxy (curl HTTPS_PROXY/ALL_PROXY)'

# ---------------------------------------------------------------- report

$report.Add('WINDOWS LOCATION & NETWORK EXPOSURE AUDIT v3.4')
$report.Add("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$report.Add("PowerShell: $($PSVersionTable.PSVersion)")
$report.Add("Options: Online=$Online; WindowsLocation=$WindowsLocation; ShareSafe=$ShareSafe")
$report.Add('Read-only Windows configuration audit; optional network queries contact third parties.')

Section '0. WINDOWS VERSION' {
    Get-CimInstance Win32_OperatingSystem |
        Select-Object Caption, Version, BuildNumber, OSArchitecture | Format-List
}

Section '1. DEVICE SETUP REGION' {
    $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\DeviceRegion'
    $v = Read-Reg $p 'DeviceRegion'
    $c = Get-GeoIdCountry $v
    "DeviceRegion GeoID: $v"
    "Recognized region: $(if ($c) { "$($c.ISO) - $($c.Name)" } else { 'Other/Unknown (no country mapping for this GeoID)' })"
    'This is mutable stored data; it does not prove historical setup location.'
    Add-Signal 'Device setup region (DeviceRegion)' "GeoID $v" $(if ($c) { $c.ISO } else { $null }) 'Medium'
}

Section '2. CURRENT GEOGRAPHIC REGION' {
    $homeLoc = Get-WinHomeLocation
    $homeLoc | Format-List *
    $geo = 'HKCU:\Control Panel\International\Geo'
    $intl = 'HKCU:\Control Panel\International'
    $geoName = Read-Reg $geo 'Name'
    "Geo Nation: $(Read-Reg $geo 'Nation')"
    "Geo Name: $geoName"
    "Regional Country Code: $(Read-Reg $intl 'iCountry')"
    "Locale Name: $(Read-Reg $intl 'LocaleName')"
    "Locale ID: $(Read-Reg $intl 'Locale')"
    $mapped = Get-GeoIdCountry ([string]$homeLoc.GeoId)
    if ($geoName -match '^[A-Za-z]{2}$') { $script:homeIso = $geoName.ToUpperInvariant() }
    elseif ($mapped) { $script:homeIso = $mapped.ISO }
    "Home location ISO: $(if ($script:homeIso) { $script:homeIso } else { '(unrecognized)' })"
    Add-Signal 'Windows home location' "GeoID $($homeLoc.GeoId) $($homeLoc.HomeLocation)" $script:homeIso 'Strong'
}

Section '3. TIMEZONE' {
    Get-TimeZone | Select-Object Id, DisplayName, BaseUtcOffset, SupportsDaylightSavingTime |
        Format-List
    $cur = [TimeZoneInfo]::Local.GetUtcOffset([DateTime]::Now)
    "Current UTC offset (includes DST): $($cur.ToString())"
    "Local time: $([DateTimeOffset]::Now.ToString('o'))"
    "UTC time: $([DateTimeOffset]::UtcNow.ToString('o'))"
    $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate'
    "Automatic timezone service Start: $(Read-Reg $p 'Start')"
}

Section '4. LANGUAGES AND INPUT METHODS' {
    $ui = (Get-UICulture).Name
    $fmt = (Get-Culture).Name
    $sysLoc = (Get-WinSystemLocale).Name
    "UI Culture: $ui"
    "Formatting Culture: $fmt"
    "System Locale: $sysLoc"
    foreach ($lang in @(Get-WinUserLanguageList)) {
        "Language: $($lang.LanguageTag)"
        "  English Name: $($lang.EnglishName)"
        "  Input Methods: $($lang.InputMethodTips -join ', ')"
    }
    if (Get-Command Get-SystemPreferredUILanguage -ErrorAction SilentlyContinue) {
        "System Preferred UI Language: $(Get-SystemPreferredUILanguage)"
    }
    $override = Get-WinUILanguageOverride
    if ($override) { "UI Language Override: $($override.Name)" }
    else { 'UI Language Override: None' }
    Add-Signal 'Regional format (user culture)' $fmt (Get-RegionFromCultureName $fmt) 'Medium'
    Add-Signal 'Display language (UI culture)' $ui (Get-RegionFromCultureName $ui) 'Weak'
    Add-Signal 'System locale (non-Unicode)' $sysLoc (Get-RegionFromCultureName $sysLoc) 'Weak'
}

Section '5. INSTALLED LANGUAGES' {
    if (Get-Command Get-InstalledLanguage -ErrorAction SilentlyContinue) {
        Get-InstalledLanguage | Format-List LanguageId, LanguagePacks, LanguageFeatures
    }
    $p = 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language'
    "NLS Default: $(Read-Reg $p 'Default')"
    "NLS InstallLanguage: $(Read-Reg $p 'InstallLanguage')"
    'NLS language identifiers do not establish physical location.'
}

Section '6. LOCATION SERVICES AND PERMISSIONS' {
    $suffix = 'SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
    $machine = "HKLM:\$suffix"
    $user = "HKCU:\$suffix"
    "Machine consent: $(Read-Reg $machine 'Value')"
    "User consent: $(Read-Reg $user 'Value')"
    $sensor = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}'
    "Sensor permission state: $(Read-Reg $sensor 'SensorPermissionState')"
    foreach ($name in @('lfsvc', 'tzautoupdate')) {
        $svc = Get-Service $name -ErrorAction SilentlyContinue
        if ($svc) { "Service ${name}: $($svc.Status)" }
    }
    if (Test-Path -LiteralPath $user) {
        $apps = @(Get-ChildItem -LiteralPath $user -ErrorAction SilentlyContinue)
        if ($ShareSafe) {
            "Per-app permission entries: $($apps.Count) (names hidden)"
        }
        else {
            'Per-app location permissions:'
            foreach ($app in $apps) { "  $($app.PSChildName): $(Read-Reg $app.PSPath 'Value')" }
        }
    }
}

Section '7. LOCATION POLICIES' {
    $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
    foreach ($name in @('DisableLocation', 'DisableWindowsLocationProvider', 'DisableSensors')) {
        "${name}: $(Read-Reg $p $name)"
    }
    $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
    "LetAppsAccessLocation: $(Read-Reg $p 'LetAppsAccessLocation')"
}

Section '8. NETWORK ADAPTERS AND ROUTES' {
    $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue)
    $adapters | Select-Object Name, InterfaceDescription, Status,
        @{ N = 'Virtual/TUN'; E = { ("$($_.Name) $($_.InterfaceDescription)") -match $script:VirtualAdapterPattern } } |
        Format-Table -AutoSize

    'Default routes sorted by effective metric (RouteMetric + InterfaceMetric):'
    $ifMetrics = @{}
    Get-NetIPInterface -ErrorAction SilentlyContinue | ForEach-Object {
        $ifMetrics["$($_.InterfaceIndex)|$($_.AddressFamily)"] = $_.InterfaceMetric
    }
    $routes = @(Get-NetRoute -ErrorAction SilentlyContinue |
        Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0', '::/0') } | ForEach-Object {
            $fam = if ($_.DestinationPrefix -eq '::/0') { 'IPv6' } else { 'IPv4' }
            $im = $ifMetrics["$($_.InterfaceIndex)|$fam"]
            [PSCustomObject]@{
                Prefix = $_.DestinationPrefix; InterfaceAlias = $_.InterfaceAlias; NextHop = $_.NextHop
                RouteMetric = $_.RouteMetric; InterfaceMetric = $im
                EffectiveMetric = [int]$_.RouteMetric + [int]$im
            }
        } | Sort-Object Prefix, EffectiveMetric)
    if ($ShareSafe) {
        $routes | Select-Object Prefix, InterfaceAlias, RouteMetric, InterfaceMetric, EffectiveMetric | Format-Table -AutoSize
    }
    else { $routes | Format-Table -AutoSize }

    'Route actually selected for public destinations (Find-NetRoute; catches TUN 0.0.0.0/1 split routes):'
    foreach ($target in @(@{ L = 'IPv4'; A = '1.1.1.1' }, @{ L = 'IPv6'; A = '2606:4700:4700::1111' })) {
        try {
            $fr = @(Find-NetRoute -RemoteIPAddress $target.A -ErrorAction Stop)
            $route = $fr | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetRoute' } | Select-Object -First 1
            $src = $fr | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_NetIPAddress' } | Select-Object -First 1
            if (-not $route) { "  $($target.L): no route selected."; continue }
            $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
            $desc = if ($adapter) { $adapter.InterfaceDescription } else { '' }
            $isVirtual = ("$($route.InterfaceAlias) $desc") -match $script:VirtualAdapterPattern
            "  $($target.L): interface '$($route.InterfaceAlias)' ($desc), prefix $($route.DestinationPrefix), virtual/TUN=$isVirtual"
            if (-not $ShareSafe) {
                "    NextHop: $($route.NextHop); Source address: $(if ($src) { $src.IPAddress } else { '(n/a)' })"
            }
            $script:routeSummary.Add("$($target.L) via '$($route.InterfaceAlias)' (virtual/TUN=$isVirtual)")
            if ($isVirtual) { "    NOTICE: public $($target.L) traffic is routed into a virtual/TUN adapter." }
        }
        catch { "  $($target.L): no usable route ($($_.Exception.Message))" }
    }
    'IPv6 adapter bindings (enabled alone does not mean IPv6 connectivity):'
    Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue |
        Select-Object Name, Enabled | Format-Table -AutoSize
}

Section '9. WINDOWS-MANAGED VPN CONNECTIONS' {
    $vpn = @()
    $vpn += @(Get-VpnConnection -ErrorAction SilentlyContinue)
    $vpn += @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue)
    if ($vpn.Count) {
        if ($ShareSafe) { "Windows-managed VPN entries: $($vpn.Count) (names hidden)" }
        else { $vpn | Select-Object Name, ConnectionStatus, TunnelType | Format-Table -AutoSize }
    }
    else { 'No Windows-managed VPN connection found.' }
    'Third-party TUN connections may appear only as network adapters (see section 8).'
}

Section '10. PROXY CONFIGURATION' {
    $p = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    "ProxyEnable: $(Read-Reg $p 'ProxyEnable')"
    if ($ShareSafe) { 'ProxyServer: (hidden in ShareSafe mode)' }
    else { "ProxyServer: $(Read-Reg $p 'ProxyServer')" }
    $pacValue = Read-Reg $p 'AutoConfigURL'
    $pacConfigured = ($pacValue -ne '(not present or inaccessible)' -and
                      $pacValue -ne '(not set)' -and
                      -not [string]::IsNullOrWhiteSpace($pacValue))
    "AutoConfigURL configured: $pacConfigured"
    if ($ShareSafe) { 'WinHTTP proxy details: (hidden in ShareSafe mode)' }
    else {
        'WinHTTP:'
        (Invoke-Native -FilePath 'netsh.exe' -ArgumentList @('winhttp', 'show', 'proxy')).Output
    }

    'Environment proxy variables (used by curl, git, pip, many CLI tools):'
    $anyEnv = $false
    foreach ($n in @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY')) {
        foreach ($scope in @('Process', 'User', 'Machine')) {
            $val = [Environment]::GetEnvironmentVariable($n, $scope)
            if ($val) {
                $anyEnv = $true
                "  $n [$scope]: $(if ($ShareSafe) { '(set, value hidden)' } else { $val })"
            }
        }
    }
    if (-not $anyEnv) { '  (none set)' }

    'Running proxy/VPN client processes (name match only; configs are not read):'
    $script:proxyClients = @(Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessName -match $script:ProxyProcessPattern } |
        ForEach-Object { $_.ProcessName } | Sort-Object -Unique)
    if ($script:proxyClients.Count -eq 0) { '  (none detected)' }
    elseif ($ShareSafe) { "  $($script:proxyClients.Count) process name(s) matched (hidden in ShareSafe mode)" }
    else { foreach ($n in $script:proxyClients) { "  $n" } }
    'System proxy settings do not describe TUN interception.'
}

Section '11. UCPD CONFIGURATION' {
    $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\UCPD'
    "Start: $(Read-Reg $p 'Start')"
    "ImagePath: $(Read-Reg $p 'ImagePath')"
    'Read-only; no Windows protection settings were changed.'
}

Section '12. MICROSOFT ACCOUNT REGION' {
    'Account-registered country: NOT AUTOMATICALLY VERIFIED.'
    'This cannot be reliably inferred from local Windows geographic settings.'
    'For personal accounts, manually check https://account.microsoft.com/profile'
    'This tool does not inspect credentials, tokens, or private account data.'
}

Section '13. DNS CONFIGURATION' {
    $entries = @(Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses.Count -gt 0 })
    if ($ShareSafe) {
        $entries | Select-Object InterfaceAlias, AddressFamily,
          @{N = 'ServerCount'; E = { $_.ServerAddresses.Count } } | Format-Table -AutoSize
    }
    else {
        $entries | Select-Object InterfaceAlias, AddressFamily,
          @{N = 'Servers'; E = { $_.ServerAddresses -join ', ' } } | Format-Table -Wrap -AutoSize
    }
    'Configured DNS servers are not necessarily the actual recursive resolver egress.'
    'Browser DoH can use separate DNS paths.'
}

if ($Online) {
    Section '14. PUBLIC EGRESS - DIRECT PATH' {
        $script:v4 = Test-DirectEgress 4
        $script:v6 = Test-DirectEgress 6
        Format-EgressLines $script:v4
        Format-EgressLines $script:v6
        'curl --noproxy bypasses env/app proxies but NOT a TUN adapter; in TUN mode this path is still tunnelled.'
        'Failures are not classified as no IPv6 or as a leak.'
    }

    Section '15. PUBLIC EGRESS - SYSTEM PROXY PATH (BROWSER-LIKE)' {
        $script:proxyPath = Test-SystemProxyEgress
        Format-EgressLines $script:proxyPath
        if ($script:envProxySet) {
            $script:envPath = Test-EnvProxyEgress
            Format-EgressLines $script:envPath
        }
        else { 'Environment proxy path: HTTPS_PROXY/ALL_PROXY not set in this process; skipped.' }
        'Browsers normally follow the system proxy; extensions or browser-specific proxy settings can still differ.'
    }

    Section '16. FAKE-IP / DNS INTERCEPTION CHECK' {
        $hits = 0; $total = 0
        foreach ($domain in @('example.com', 'www.wikipedia.org')) {
            foreach ($type in @('A', 'AAAA')) {
                try {
                    $ans = @(Resolve-DnsName -Name $domain -Type $type -DnsOnly -ErrorAction Stop |
                             Where-Object { $_.Type -eq $type })
                    foreach ($a in $ans) {
                        $total++
                        if (Test-FakeAddress ([string]$a.IPAddress)) { $hits++ }
                    }
                }
                catch { }
            }
        }
        if ($total -eq 0) {
            $script:fakeIp = $null
            'Result: INCONCLUSIVE. Public test domains did not resolve.'
        }
        elseif ($hits -gt 0) {
            $script:fakeIp = $true
            "Result: FAKE_IP_DETECTED. $hits of $total answers fall in 198.18.0.0/15 or fc00::/7."
            'A TUN proxy core (Clash/mihomo/sing-box etc.) is answering system DNS.'
            'Resolver results in section 17 then reflect the proxy core upstream, not your ISP resolver.'
        }
        else {
            $script:fakeIp = $false
            "Result: NO_FAKE_IP. $total answers checked; none in reserved fake-IP ranges."
        }
    }

    Section '17. RECURSIVE DNS RESOLVER DIAGNOSTIC' {
        if ($script:fakeIp) { 'WARNING: Fake-IP DNS detected; results below are produced via the proxy core.' }
        $queries = @('whoami.ds.akahelp.net', 'whoami.ipv4.akahelp.net',
                     'whoami.ipv6.akahelp.net', 'o-o.myaddr.l.google.com')
        $seen = @{}
        foreach ($domain in $queries) {
            "Query: $domain"
            try {
                $answers = @(Get-ResolverRecords $domain)
                $ns = @($answers | Where-Object { $_.Kind -eq 'ns' })
                $ecs = @($answers | Where-Object { $_.Kind -eq 'ecs' })
                "  Recursive resolver IP candidates: $($ns.Count)"
                "  ECS record present: $($ecs.Count -gt 0)"
                foreach ($item in $ecs) {
                    "  ECS client subnet: $(if ($ShareSafe) { '(hidden in ShareSafe mode)' } else { $item.Value })"
                }
                foreach ($item in $ns) {
                    $parsed = Test-IPAddress $item.Value
                    if (-not $parsed) { continue }
                    $addr = $parsed.ToString()
                    if ($seen.ContainsKey($addr)) { continue }
                    $seen[$addr] = $true
                    # Limit third-party geolocation lookups from this test.
                    $geo = if ($seen.Count -le 6) { Get-GeoInfo $addr } else { $null }
                    $script:dnsResults.Add([PSCustomObject]@{ Address = $addr; Geo = $geo; Source = $domain })
                    "  Resolver exit: $(Protect-IP $addr)"
                    if ($geo) {
                        "  Resolver geolocation: $($geo.country) ($($geo.country_code)); ISP: $($geo.connection.isp)"
                    }
                }
            }
            catch { "  Lookup failed: $($_.Exception.Message)" }
        }
        if ($script:dnsResults.Count -eq 0) {
            'Result: INCONCLUSIVE. No resolver egress address could be identified.'
        }
        'This is a sample, NOT a complete DNS-leak test. Browser DoH may differ.'
        'DNS resolver geography differing from HTTPS egress is not by itself a leak.'
        'ECS, when present, discloses an approximate client subnet to authoritative DNS servers.'
    }
}
else {
    Section '14. PUBLIC EGRESS - DIRECT PATH' { 'Skipped; use -Online.' }
    Section '15. PUBLIC EGRESS - SYSTEM PROXY PATH (BROWSER-LIKE)' { 'Skipped; use -Online.' }
    Section '16. FAKE-IP / DNS INTERCEPTION CHECK' { 'Skipped; use -Online.' }
    Section '17. RECURSIVE DNS RESOLVER DIAGNOSTIC' { 'Skipped; use -Online.' }
}

Section '18. NETWORK LOCATION COMPARISON' {
    '[A] Direct IPv4 vs IPv6'
    if ($script:v4.Status -eq 'OK' -and $script:v6.Status -eq 'OK') {
        if ($script:v4.Country -and $script:v6.Country) {
            "  IPv4 country: $($script:v4.Country); IPv6 country: $($script:v6.Country)"
            if ($script:v4.Country -ne $script:v6.Country) {
                '  STATUS: COUNTRY_MISMATCH. IPv4/IPv6 exits differ; IPv6 may bypass the tunnel.'
            }
            else { '  STATUS: COUNTRIES_MATCH.' }
        }
        else { '  STATUS: GEOLOCATION_UNAVAILABLE.' }
    }
    elseif ($script:v4.Status -eq 'OK' -and $script:v6.Status -eq 'FAILED') {
        '  STATUS: IPV6_TEST_FAILED. No assertion about leaks or permanent IPv6 support.'
    }
    elseif ($script:v4.Status -eq 'SKIPPED') { '  STATUS: NOT_TESTED.' }
    else { '  STATUS: INCONCLUSIVE. One or both connection tests failed.' }

    '[B] Direct path vs system proxy path'
    if ($script:proxyPath.Status -eq 'OK') {
        $directAddrs = @(@($script:v4.Address, $script:v6.Address) | Where-Object { $_ })
        $directCountries = @(@($script:v4.Country, $script:v6.Country) | Where-Object { $_ } | Sort-Object -Unique)
        if ($directAddrs -contains $script:proxyPath.Address) {
            '  STATUS: SAME_EXIT. Browser-like and direct traffic leave via the same IP.'
            if ($script:proxyPath.ProxyUri -ne 'DIRECT') {
                '  Note: a system proxy is configured but exits identically (TUN likely active as well).'
            }
        }
        elseif ($directAddrs.Count -eq 0) { '  STATUS: DIRECT_PATH_UNAVAILABLE. Cannot compare.' }
        elseif ($script:proxyPath.Country -and $directCountries -contains $script:proxyPath.Country) {
            "  STATUS: DIFFERENT_IP_SAME_COUNTRY ($($script:proxyPath.Country))."
        }
        else {
            "  STATUS: PATH_COUNTRY_MISMATCH. Browser-like path = $($script:proxyPath.Country); direct path = $($directCountries -join '/')."
            '  Apps that ignore the system proxy (games, CLI tools, UDP, WebRTC) appear in the direct-path country.'
        }
    }
    else { "  STATUS: $($script:proxyPath.Status)." }

    if ($script:envPath.Status -eq 'OK') {
        '[B2] Environment proxy path vs system proxy path'
        if ($script:envPath.Address -eq $script:proxyPath.Address) { '  STATUS: SAME_EXIT.' }
        elseif ($script:envPath.Country -eq $script:proxyPath.Country) { '  STATUS: DIFFERENT_IP_SAME_COUNTRY.' }
        else { "  STATUS: COUNTRY_MISMATCH. env=$($script:envPath.Country); system=$($script:proxyPath.Country)." }
    }

    '[C] Geolocation database agreement and network type'
    $anyEgress = $false
    foreach ($r in @($script:v4, $script:v6, $script:proxyPath, $script:envPath)) {
        if ($r.Status -ne 'OK') { continue }
        $anyEgress = $true
        "  $($r.Path): $($r.Agreement)"
        if ($r.Agreement -eq 'DISAGREE') { '    NOTICE: geolocation databases disagree; sites may classify this IP differently.' }
        if ($r.Agreement -eq 'SINGLE_SOURCE') { '    NOTICE: country is from one source only; no independent agreement verified.' }
        if ($r.TraceIP -and $r.TraceIP -ne $r.Address) { '    NOTICE: exit IP differs between destinations (rotating or split exit).' }
        if ($r.Secondary -and $r.Secondary.IpApi -and $r.Secondary.IpApi.hosting) {
            '    NOTICE: flagged as hosting/datacenter by ip-api.com; many services treat this as VPN/proxy.'
        }
    }
    if (-not $anyEgress) { '  (no egress data)' }

    '[D] Recursive DNS vs egress'
    $dnsRef = if ($script:v4.Country) { $script:v4 } elseif ($script:v6.Country) { $script:v6 } else { $null }
    if ($script:dnsResults.Count -gt 0) {
        $dnsCountries = @($script:dnsResults | Where-Object { $_.Geo } |
            ForEach-Object { ([string]$_.Geo.country_code).ToUpperInvariant() } | Sort-Object -Unique)
        "  Observed recursive DNS countries (sample): $($dnsCountries -join ', ')"
        if ($dnsRef -and @($dnsCountries | Where-Object { $_ -ne $dnsRef.Country }).Count -gt 0) {
            "  NOTICE: a sampled resolver is geolocated outside the $($dnsRef.Path) country ($($dnsRef.Country))."
            '  Investigate DNS policy; a country difference is not conclusive proof of a leak.'
        }
        elseif ($dnsRef) { "  Resolvers match the $($dnsRef.Path) country ($($dnsRef.Country))." }
    }
    else { '  (no resolver data)' }

    '[E] System timezone vs IP timezone'
    $ref = Get-ReferenceEgress
    $sysLabel = [TimeSpan]::FromSeconds($script:sysOffsetSec).ToString()
    if ($ref -and $ref.Geo -and $ref.Geo.timezone -and $null -ne $ref.Geo.timezone.offset) {
        $ipOff = [int]$ref.Geo.timezone.offset
        "  System: $((Get-TimeZone).Id), UTC offset $sysLabel"
        "  IP ($($ref.Path)): $($ref.Geo.timezone.id), UTC offset $([TimeSpan]::FromSeconds($ipOff).ToString())"
        if ($ipOff -eq $script:sysOffsetSec) {
            '  STATUS: TIMEZONE_MATCH.'
            Add-Signal 'Time zone (current UTC offset)' "UTC $sysLabel" $null 'Strong' 'MATCH'
        }
        else {
            $diffH = [Math]::Round(($script:sysOffsetSec - $ipOff) / 3600.0, 2)
            "  STATUS: TIMEZONE_MISMATCH. System differs from IP location by $diffH h."
            Add-Signal 'Time zone (current UTC offset)' "UTC $sysLabel vs IP $([TimeSpan]::FromSeconds($ipOff).ToString())" $null 'Strong' 'MISMATCH'
        }
    }
    else {
        '  No IP timezone available; use -Online.'
        Add-Signal 'Time zone (current UTC offset)' "UTC $sysLabel" $null 'Strong' 'NO_REF'
    }
}

if ($WindowsLocation) {
    $script:windowsLocationStatus = 'UNAVAILABLE'
    Section '19. WINDOWS LOCATION PROVIDER (OPT-IN)' {
        $watcher = $null
        try {
            Add-Type -AssemblyName System.Device -ErrorAction Stop
            $watcher = New-Object System.Device.Location.GeoCoordinateWatcher
            $started = $watcher.TryStart($false, [TimeSpan]::FromSeconds(12))
            "Provider started: $started"
            "Permission: $($watcher.Permission)"
            if ([string]$watcher.Permission -eq 'Denied') {
                'Result: ACCESS_DENIED. No usable coordinate requested.'
            }
            elseif (-not $started) { 'Result: UNAVAILABLE. Provider did not start.' }
            else {
                $deadline = (Get-Date).AddSeconds(15)
                $fix = $watcher.Position
                while (($fix.Location.IsUnknown -or [string]$watcher.Status -ne 'Ready') -and
                       (Get-Date) -lt $deadline -and [string]$watcher.Permission -ne 'Denied') {
                    Start-Sleep -Milliseconds 500
                    $fix = $watcher.Position
                }
                "Final provider status: $($watcher.Status)"
                if ([string]$watcher.Permission -eq 'Denied') { 'Result: ACCESS_DENIED.' }
                elseif ([string]$watcher.Status -ne 'Ready' -or $fix.Location.IsUnknown) {
                    'Result: NO_VALID_FIX. No reliable current location returned.'
                }
                else {
                    $lat = [double]$fix.Location.Latitude
                    $lon = [double]$fix.Location.Longitude
                    $acc = [double]$fix.Location.HorizontalAccuracy
                    $age = ([DateTimeOffset]::Now - $fix.Timestamp).TotalMinutes
                    "Fix age (minutes): $([Math]::Round($age,1))"
                    "Reported accuracy (meters): $acc"
                    if (-not (Test-GeoCoordinate $lat $lon $acc) -or $age -gt 15 -or $age -lt -2) {
                        'Result: INVALID_OR_STALE_FIX. Skipping position comparison.'
                    }
                    else {
                        $script:windowsFix = [PSCustomObject]@{ Lat = $lat; Lon = $lon; Accuracy = $acc }
                        $script:windowsLocationStatus = 'VALID_FRESH_FIX'
                        'Result: VALID_FRESH_FIX. Exact coordinates are NEVER stored in TXT report.'
                        $ref = Get-ReferenceEgress
                        if ($ref -and $ref.Geo) {
                            $km = Get-DistanceKm $lat $lon ([double]$ref.Geo.latitude) ([double]$ref.Geo.longitude)
                            $kmR = [Math]::Round($km, 0)
                            "Distance from approximate IP location of $($ref.Path) (km): $kmR"
                            if ($km -gt 300) { 'NOTICE: Large difference; device location and IP geolocation are separate signals.' }
                            'IP-geolocation is approximate; distance is not a proof of location leakage.'
                            $st = if ($km -gt 300) { 'MISMATCH' } else { 'MATCH' }
                            Add-Signal 'Windows location provider' "$kmR km from IP location" $null 'Strong' $st
                        }
                        else { 'No IP geolocation reference available; use -Online to compare.' }
                    }
                }
            }
        }
        catch { "Result: PROVIDER_ERROR. $($_.Exception.Message)" }
        finally { if ($watcher) { $watcher.Dispose() } }
    }
}
else { Section '19. WINDOWS LOCATION PROVIDER (OPT-IN)' { 'Skipped; use -WindowsLocation.' } }

# ---------------------------------------------------------------- browser probe
# The page makes no network request until the user clicks a button.
$refEgress = Get-ReferenceEgress
$refGeo = if ($refEgress) { $refEgress.Geo } else { $null }
Initialize-GeoIdMap
$psAudit = [ordered]@{
    signals = @($script:signals | Where-Object { $_.Name -notin @('Time zone (current UTC offset)', 'Windows location provider') } |
        Select-Object Name, Value, Country, Strength)
    egress = @(foreach ($r in @($script:v4, $script:v6, $script:proxyPath, $script:envPath)) {
        [ordered]@{ path = $r.Path; status = $r.Status; country = $r.Country; agreement = $r.Agreement; votes = $r.Votes }
    })
    dnsCountries = @($script:dnsResults | Where-Object { $_.Geo -and $_.Geo.country_code } |
        ForEach-Object { ([string]$_.Geo.country_code).ToUpperInvariant() } | Sort-Object -Unique)
    online = [bool]$Online
    windowsLocation = [ordered]@{
        status = $script:windowsLocationStatus
        distanceKm = $null
        accuracyMeters = if ($script:windowsFix) { $script:windowsFix.Accuracy } else { $null }
    }
}
if ($script:windowsFix -and $refGeo -and $null -ne $refGeo.latitude -and $null -ne $refGeo.longitude) {
    $psAudit.windowsLocation.distanceKm = [Math]::Round((Get-DistanceKm $script:windowsFix.Lat $script:windowsFix.Lon $refGeo.latitude $refGeo.longitude))
}
$psRef = [ordered]@{
    supportedCountries      = @($script:GeoIdMap.Values | ForEach-Object { $_[0] } | Sort-Object -Unique)
    audit                   = $psAudit
    generated               = (Get-Date).ToString('o')
    shareSafe               = [bool]$ShareSafe
    homeLocation            = $script:homeIso
    systemTimezoneId        = (Get-TimeZone).Id
    systemUtcOffsetMinutes  = [int]($script:sysOffsetSec / 60)
    referencePath           = if ($refEgress) { $refEgress.Path } else { $null }
    referenceCountry        = if ($refEgress) { $refEgress.Country } else { $null }
    ipTimezoneId            = if ($refGeo -and $refGeo.timezone) { [string]$refGeo.timezone.id } else { $null }
    ipTimezoneOffsetSeconds = if ($refGeo -and $refGeo.timezone -and $null -ne $refGeo.timezone.offset) { [int]$refGeo.timezone.offset } else { $null }
    directIPv4Country       = $script:v4.Country
    directIPv6Country       = $script:v6.Country
    systemProxyCountry      = $script:proxyPath.Country
    fakeIpDns               = $script:fakeIp
    directIPv4              = $null
    directIPv6              = $null
    systemProxyIP           = $null
    latitude                = $null
    longitude               = $null
}
if (-not $ShareSafe) {
    $psRef['directIPv4'] = $script:v4.Address
    $psRef['directIPv6'] = $script:v6.Address
    $psRef['systemProxyIP'] = $script:proxyPath.Address
    if ($refGeo) {
        $psRef['latitude'] = [double]$refGeo.latitude
        $psRef['longitude'] = [double]$refGeo.longitude
    }
}
$psRefJson = ConvertTo-SafeScriptJson ($psRef | ConvertTo-Json -Compress -Depth 8)

$html = @'
<!doctype html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Windows 与浏览器地区检查 v3.4</title>
<meta name="description" content="Local probe comparing browser language, timezone, HTTP egress, WebRTC exposure and geolocation.">
<style>
:root{--bg:#0d1117;--card:#161b22;--line:#30363d;--fg:#e6edf3;--mute:#8b949e;--acc:#58a6ff;--ok:#3fb950;--bad:#f85149;--warn:#d29922}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1100px 560px at 8% -12%,#1f2a44 0%,transparent 60%),radial-gradient(900px 500px at 110% 10%,#2a1f44 0%,transparent 55%),var(--bg);color:var(--fg);font:15px/1.6 "Segoe UI",system-ui,sans-serif;min-height:100vh}
main{max-width:1280px;margin:0 auto;padding:36px 18px 64px}
h1{font-size:28px;margin:0 0 6px;background:linear-gradient(90deg,#79c0ff,#d2a8ff);-webkit-background-clip:text;background-clip:text;color:transparent}
h2{font-size:16px;margin:0 0 10px;letter-spacing:.2px}
.note{color:var(--mute);margin:0 0 24px}
section{background:rgba(22,27,34,.85);backdrop-filter:blur(6px);border:1px solid var(--line);border-radius:14px;padding:18px 20px;margin:0 0 16px;transition:border-color .2s,transform .2s;animation:rise .4s ease both}
section:hover{border-color:#484f58}
@keyframes rise{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0b0f14;border:1px solid var(--line);padding:12px;border-radius:8px;margin:10px 0 0;font:13px/1.5 Consolas,monospace;max-height:420px;overflow:auto}
button{background:#21262d;color:var(--fg);border:1px solid var(--line);padding:9px 14px;margin:4px 6px 4px 0;border-radius:8px;cursor:pointer;font:inherit;transition:all .15s}
button:hover{border-color:var(--acc);color:var(--acc);transform:translateY(-1px)}
button.primary{background:linear-gradient(135deg,#1f6feb,#8957e5);border-color:transparent;color:#fff}
button.primary:hover{filter:brightness(1.15);color:#fff}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mute);font-weight:600}
tr:hover td{background:rgba(88,166,255,.04)}
.tag{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;font-weight:600}
.tag.MATCH{background:rgba(63,185,80,.15);color:var(--ok)}
.tag.MISMATCH{background:rgba(248,81,73,.15);color:var(--bad)}
.tag.NA{background:rgba(139,148,158,.15);color:var(--mute)}
#overall{font-weight:600;margin-top:12px}
.table-scroll{overflow-x:auto}#regionTable,#pairTable{min-width:850px}tr.MISMATCH td{background:rgba(248,81,73,.08)}
select{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:9px 12px;font:inherit;max-width:100%;margin:6px}
.tag.WARN{background:rgba(210,153,34,.15);color:var(--warn)}.tag.REFERENCE{background:rgba(88,166,255,.15);color:var(--acc)}
.summary{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0}.summary span{padding:8px 14px;border:1px solid var(--line);border-radius:8px}
details{margin-top:14px}summary{cursor:pointer;color:var(--mute)}#reference{color:var(--acc)}
label{color:var(--mute);margin-left:6px;cursor:pointer}
</style></head><body><main>
<header><h1>Windows 与浏览器地区检查</h1>
<p class="note">PowerShell 结果已载入。点击“运行浏览器全部检查”后会补入浏览器结果。下面分别检查“是否符合所选国家”和“两个实测结果是否一致”；IP 地址不同本身不计作地区不一致。</p></header>
<section><h2>1. 与基准国家对比</h2>
<label for="baselineCountry">基准国家 / 地区：</label><select id="baselineCountry" aria-describedby="reference"></select><p id="reference"></p>
<div class="summary"><span id="countMismatch"></span><span id="countMatch"></span><span id="countUnknown"></span></div>
<button class="primary" id="btnAll">运行浏览器全部检查</button><button id="saveHtml">保存汇总 HTML（隐藏 IP 和坐标）</button>
<div id="overall" role="status" aria-live="polite"></div>
<p class="note">这张表只判断检测到的国家是否符合上面所选的国家。切换后立即重新判断，无需重跑测试。语言与 DNS 地区可因正常配置不同，不能单凭差异判断泄露。</p>
<p class="note" id="dnsLeakHint">完整 DNS 泄露检查：本脚本只抽样检查系统 DNS。请使用正在检查的浏览器，自行打开 <a href="https://browserleaks.com/dns" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer" style="color:var(--acc)">BrowserLeaks DNS 泄露测试</a>，进一步检查浏览器的 DNS 出口；浏览器 DoH 等路径可能与系统 DNS 不同。</p>
<div class="table-scroll"><table id="regionTable"><thead><tr><th>来源</th><th>检查项目</th><th>检测结果</th><th>比较基准</th><th>结论</th><th>说明</th></tr></thead><tbody id="matrix"></tbody></table></div></section>
<section><h2>2. 两个测试结果互相对比</h2>
<p class="note">这张表直接比较检测 A 与检测 B，不使用上面的基准国家。切换国家不会改变这些结论。时区比较当前 UTC 偏移；定位比较距离，不能由此判定国家。</p>
<div class="summary"><span id="pairMismatch"></span><span id="pairMatch"></span><span id="pairUnknown"></span></div>
<div id="pairOverall" role="status" aria-live="polite"></div>
<div class="table-scroll"><table id="pairTable"><thead><tr><th>来源</th><th>比较项目</th><th>检测 A</th><th>检测 B / 判断条件</th><th>结论</th><th>说明</th></tr></thead><tbody id="pairMatrix"></tbody></table></div></section>
<details><summary>浏览器测试操作与原始详情</summary>
<section><h2>1. Browser HTTP egress</h2><button class="primary" id="btnEgress">Check browser egress IP</button><pre id="egress">Not checked.</pre></section>
<section><h2>2. WebRTC exposure</h2><button class="primary" id="btnWebrtc">Run WebRTC leak test</button><pre id="webrtc">Not checked.</pre></section>
<section><h2>3. Geolocation API</h2><button class="primary" id="btnGeo">Request location</button>
<input type="checkbox" id="highAcc"><label for="highAcc">High accuracy (GPS/Wi-Fi, slower)</label><pre id="geo">Not requested.</pre></section>
<section><h2>Browser-visible information</h2><pre id="browser"></pre></section>
<section><h2>PowerShell reference (embedded)</h2><pre id="ref"></pre></section>
<section><h2>Run and export</h2>
<button id="saveSafe">Save redacted JSON</button><button id="saveFull">Save full JSON (IPs and exact coordinates)</button></section>
</details><p class="note">浏览器联网和 WebRTC 测试仅在点击后联系 Cloudflare、ipify、ipwho.is 和 STUN 服务；定位需要浏览器权限。测试完成后点击“保存汇总 HTML”，可保留两边的结果供下次打开。</p></main>
<script type="application/json" id="savedResults">null</script>
<script>
'use strict';
const ref = __PS_REFERENCE__ || {};
const $ = id => document.getElementById(id);
const show = (id, d) => { $(id).textContent = typeof d === 'string' ? d : JSON.stringify(d, null, 2); };
const regionOf = tag => { try { return new Intl.Locale(tag).region || null; } catch (e) { return null; } };
const num = v => (typeof v === 'number' && Number.isFinite(v)) ? v : null;
const firstNum = (...v) => { for (const x of v) { const n = num(x); if (n !== null) return n; } return null; };
const errText = e => (e && e.name === 'AbortError') ? 'timeout' : String((e && e.message) || e);
const isIP = s => typeof s === 'string' && /^[0-9a-fA-F:.]+$/.test(s) && (s.includes('.') || s.includes(':'));

const resolved = Intl.DateTimeFormat().resolvedOptions();
const info = {
  language: navigator.language, languages: Array.from(navigator.languages || []),
  languageRegion: regionOf(navigator.language),
  intlLocale: resolved.locale, intlLocaleRegion: regionOf(resolved.locale),
  timezone: resolved.timeZone, utcOffsetMinutes: -new Date().getTimezoneOffset(),
  userAgent: navigator.userAgent, secureContext: window.isSecureContext,
  geolocationAvailable: !!navigator.geolocation, webrtcAvailable: typeof RTCPeerConnection === 'function'
};
const sessionInfo = { ...info };
const results = { browser: info, psReference: ref, baselineCountry: 'AUTO', egress: null, webrtc: null, geolocation: { status: 'not requested' }, matrix: null };
try {
  const saved = JSON.parse($('savedResults').textContent || 'null');
  if (saved) {
    Object.assign(results, saved);
    // Restored browser results describe the saved run, not this browser session.
    if (saved.browser) Object.assign(info, saved.browser);
  }
} catch (e) { }
show('browser', info); show('ref', ref);

function getData(url, asText) {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 10000);
  return fetch(url, { signal: ctl.signal, cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' })
    .then(r => { if (!r.ok) throw new Error('HTTP ' + r.status); return asText ? r.text() : r.json(); })
    .finally(() => clearTimeout(t));
}
const geoCache = new Map();
async function geoLookup(ip) {
  if (!isIP(ip)) return null;
  if (geoCache.has(ip)) return geoCache.get(ip);
  let out = null;
  try {
    const g = await getData('https://ipwho.is/' + ip);
    if (g && g.success !== false) out = {
      countryCode: g.country_code || null, country: g.country || null, region: g.region || null,
      isp: g.connection ? g.connection.isp : null, asn: g.connection ? g.connection.asn : null,
      timezoneId: g.timezone ? g.timezone.id : null, timezoneOffsetSeconds: g.timezone ? g.timezone.offset : null,
      latitude: g.latitude, longitude: g.longitude };
  } catch (e) { out = null; }
  geoCache.set(ip, out); return out;
}
function parseTrace(text) {
  const kv = {};
  text.split('\n').forEach(l => { const i = l.indexOf('='); if (i > 0) kv[l.slice(0, i).trim()] = l.slice(i + 1).trim(); });
  return kv;
}
function browserCountry(e) {
  if (!e) return null;
  return (e.ipv4 && e.ipv4.geo && e.ipv4.geo.countryCode) ||
         ((e.cloudflare && e.cloudflare.loc && !['XX', 'T1'].includes(e.cloudflare.loc)) ? e.cloudflare.loc : null) ||
         (e.ipv6 && e.ipv6.geo && e.ipv6.geo.countryCode) || null;
}

async function runEgress() {
  show('egress', 'Checking...');
  const [tr, v4, v6] = await Promise.allSettled([
    getData('https://www.cloudflare.com/cdn-cgi/trace', true),
    getData('https://api.ipify.org?format=json'),
    getData('https://api6.ipify.org?format=json')]);
  const out = { cloudflare: null, ipv4: null, ipv6: null, notes: [] };
  if (tr.status === 'fulfilled') { const kv = parseTrace(tr.value); out.cloudflare = { ip: kv.ip || null, loc: kv.loc || null, colo: kv.colo || null, warp: kv.warp || null }; }
  else out.cloudflare = { error: errText(tr.reason) };
  out.ipv4 = v4.status === 'fulfilled' ? { ip: v4.value.ip } : { error: errText(v4.reason) };
  out.ipv6 = v6.status === 'fulfilled' ? { ip: v6.value.ip } : { error: errText(v6.reason) };
  for (const k of ['ipv4', 'ipv6']) if (out[k].ip) out[k].geo = await geoLookup(out[k].ip);
  if (out.cloudflare.ip && out.cloudflare.ip !== out.ipv4.ip && out.cloudflare.ip !== out.ipv6.ip) {
    out.cloudflare.geo = await geoLookup(out.cloudflare.ip);
    out.notes.push('Cloudflare saw a different exit IP than ipify: exit may rotate or be split per destination.');
  }
  if (out.cloudflare.loc && out.ipv4.geo && out.ipv4.geo.countryCode && out.cloudflare.ip === out.ipv4.ip &&
      out.cloudflare.loc !== out.ipv4.geo.countryCode)
    out.notes.push('Cloudflare and ipwho.is disagree on the country of the same IP (' + out.cloudflare.loc + ' vs ' + out.ipv4.geo.countryCode + ').');
  const bIPs = [out.ipv4.ip, out.ipv6.ip, out.cloudflare.ip].filter(Boolean);
  const directIPs = [ref.directIPv4, ref.directIPv6].filter(Boolean);
  const proxyDiffers = ref.systemProxyIP && !directIPs.includes(ref.systemProxyIP);
  if (ref.systemProxyIP || directIPs.length) {
    if (ref.systemProxyIP && bIPs.includes(ref.systemProxyIP)) out.notes.push('Browser exit matches the Windows system-proxy exit.');
    else if (directIPs.some(ip => bIPs.includes(ip)))
      out.notes.push(proxyDiffers ? 'Browser exit matches the PowerShell direct path and differs from the sampled system-proxy exit. Possible proxy bypass, PAC routing, exit rotation or settings changes; this does not prove bypass.' : 'Browser exit matches the PowerShell direct path.');
    else out.notes.push('Browser exit matches none of the PowerShell-observed exits. Possible browser proxy, extension, VPN, PAC routing, exit rotation or settings changes; IP differences alone do not identify the cause.');
  } else {
    const bc = browserCountry(out);
    if (ref.referenceCountry && bc)
      out.notes.push(bc === ref.referenceCountry ? 'Browser exit country matches the PowerShell reference country.' : 'Browser exit country (' + bc + ') differs from PowerShell reference (' + ref.referenceCountry + ').');
  }
  results.egress = out; show('egress', out); renderMatrix(); return out;
}

async function runWebRTC() {
  if (typeof RTCPeerConnection !== 'function') { results.webrtc = { status: 'API_UNAVAILABLE' }; show('webrtc', results.webrtc); renderMatrix(); return; }
  if (!results.egress) { try { await runEgress(); } catch (e) { } }
  show('webrtc', 'Gathering ICE candidates (up to 8 s)...');
  const raw = []; let pc = null;
  try {
    pc = new RTCPeerConnection({ iceServers: [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478'] }] });
    const done = new Promise(resolve => {
      const timer = setTimeout(resolve, 8000);
      pc.onicecandidate = ev => {
        if (!ev.candidate) { clearTimeout(timer); resolve(); }
        else if (ev.candidate.candidate) raw.push(ev.candidate.candidate);
      };
    });
    pc.createDataChannel('probe');
    await pc.setLocalDescription(await pc.createOffer());
    await done;
  } catch (e) {
    results.webrtc = { status: 'ERROR', message: errText(e) }; show('webrtc', results.webrtc); renderMatrix(); return;
  } finally { if (pc) pc.close(); }
  const seen = new Set(), candidates = [];
  for (const c of raw) {
    const p = c.trim().split(/\s+/), ti = p.indexOf('typ');
    const cand = { protocol: (p[2] || '').toLowerCase(), address: p[4] || '', type: ti > 0 ? p[ti + 1] : 'unknown' };
    const key = cand.type + '|' + cand.address + '|' + cand.protocol;
    if (!seen.has(key)) { seen.add(key); candidates.push(cand); }
  }
  const publicIPs = [...new Set(candidates.filter(c => c.type === 'srflx' || c.type === 'prflx').map(c => c.address).filter(isIP))];
  const hostIPs = [...new Set(candidates.filter(c => c.type === 'host' && isIP(c.address)).map(c => c.address))];
  const pub = [];
  for (const ip of publicIPs) pub.push({ ip, geo: await geoLookup(ip) });
  const e = results.egress || {};
  const httpIPs = [e.ipv4 && e.ipv4.ip, e.ipv6 && e.ipv6.ip, e.cloudflare && e.cloudflare.ip].filter(Boolean);
  const out = { status: null, candidates, publicIPs: pub, localHostIPsExposed: hostIPs,
    mdnsObfuscation: candidates.some(c => c.type === 'host' && /\.local$/i.test(c.address)), notes: [] };
  if (!publicIPs.length) {
    out.status = 'NO_PUBLIC_CANDIDATE';
    out.notes.push('No STUN-reflexive address: WebRTC/UDP is blocked or restricted by the browser.');
  } else if (!httpIPs.length) {
    out.status = 'UNVERIFIED'; out.notes.push('HTTP egress unknown; cannot compare.');
  } else {
    const unknown = publicIPs.filter(ip => !httpIPs.includes(ip));
    if (unknown.length) {
      out.status = 'LEAK_SUSPECTED';
      out.notes.push(unknown.length + ' public IP(s) exposed by WebRTC are not seen on the HTTP path.');
      if ([ref.directIPv4, ref.directIPv6].some(ip => ip && unknown.includes(ip)))
        out.notes.push('An exposed IP equals the PowerShell DIRECT exit: websites can see your underlying network via WebRTC.');
    } else out.status = 'MATCHES_HTTP_EGRESS';
  }
  if (hostIPs.length) out.notes.push('Local interface addresses are exposed (mDNS obfuscation not in use).');
  results.webrtc = out; show('webrtc', out); renderMatrix();
}

function distanceKm(lat1, lon1, lat2, lon2) {
  const r = Math.PI / 180, a = Math.sin((lat2 - lat1) * r / 2) ** 2 +
    Math.cos(lat1 * r) * Math.cos(lat2 * r) * Math.sin((lon2 - lon1) * r / 2) ** 2;
  return 12742 * Math.asin(Math.sqrt(Math.min(1, Math.max(0, a))));
}
const errorNames = { 1: 'PERMISSION_DENIED', 2: 'POSITION_UNAVAILABLE', 3: 'TIMEOUT' };
function runGeo() {
  const high = $('highAcc').checked, mode = high ? 'high-accuracy' : 'low-power';
  if (!navigator.geolocation) { results.geolocation = { status: 'API_UNAVAILABLE' }; show('geo', results.geolocation); renderMatrix(); return Promise.resolve(); }
  results.geolocation = { status: 'WAITING', mode }; show('geo', results.geolocation);
  return new Promise(resolve => navigator.geolocation.getCurrentPosition(pos => {
    const c = pos.coords;
    const out = { status: 'SUCCESS', mode, latitude: c.latitude, longitude: c.longitude,
      accuracyMeters: Math.round(c.accuracy), timestamp: new Date(pos.timestamp).toISOString() };
    if (num(ref.latitude) !== null && num(ref.longitude) !== null)
      out.distanceToPowerShellIPKm = Math.round(distanceKm(c.latitude, c.longitude, ref.latitude, ref.longitude));
    const bg = results.egress && results.egress.ipv4 && results.egress.ipv4.geo;
    if (bg && num(bg.latitude) !== null && num(bg.longitude) !== null)
      out.distanceToBrowserIPKm = Math.round(distanceKm(c.latitude, c.longitude, bg.latitude, bg.longitude));
    out.note = 'IP geolocation is approximate; a large distance is a signal, not proof.';
    results.geolocation = out; show('geo', out); renderMatrix(); resolve();
  }, err => {
    results.geolocation = { status: errorNames[err.code] || 'ERROR', mode, errorCode: err.code, message: err.message };
    show('geo', results.geolocation); renderMatrix(); resolve();
  }, { enableHighAccuracy: high, timeout: high ? 30000 : 20000, maximumAge: 0 }));
}

function offLabel(min) {
  if (num(min) === null) return 'n/a';
  const a = Math.abs(min);
  return 'UTC' + (min < 0 ? '-' : '+') + String(Math.floor(a / 60)).padStart(2, '0') + ':' + String(a % 60).padStart(2, '0');
}
function renderMatrix() {
  const e = results.egress, w = results.webrtc, g = results.geolocation;
  const bc = browserCountry(e);
  const auto = !results.baselineCountry || results.baselineCountry === 'AUTO';
  const refC = auto ? bc || ref.referenceCountry || null : results.baselineCountry;
  const refSrc = auto ? bc ? '自动：浏览器 HTTP 出口' : (ref.referenceCountry ? '自动：PowerShell 出口' : null) : '用户选择';
  const audit = ref.audit || {};
  const rows = [];
  const countryLabel = code => {
    if (!code) return '未知';
    try { return new Intl.DisplayNames(['zh-CN'], { type: 'region' }).of(code) + ' (' + code + ')'; }
    catch (e) { return code; }
  };
  const defaultCountries = 'US CN GB DE FR IT ES PT NL BE CH AT IE SE NO DK FI PL CZ SK HU RO BG GR HR SI RS UA BY EE LV LT IS LU MT CY RU TR JP KR HK MO TW SG IN ID MY TH VN PH AE SA IL BD PK LK NP KH LA MM MN KZ UZ QA KW BH OM IR IQ JO LB BN MV BT AZ AM GE CA MX BR AR CL CO PE EC VE UY BO PY CR PA GT CU DO JM TT SV HN NI BS BZ PR AU NZ'.split(' ');
  const codes = new Set(ref.supportedCountries || defaultCountries);
  for (const s of audit.signals || []) if (s.Country) codes.add(s.Country);
  for (const r of audit.egress || []) if (r.country) codes.add(r.country);
  for (const c of [refC, bc, ref.referenceCountry, ...(audit.dnsCountries || [])]) if (c) codes.add(c);
  const select = $('baselineCountry'); select.textContent = '';
  const option = (value, label) => {
    const o = document.createElement('option'); o.value = value; o.textContent = label; select.appendChild(o);
  };
  option('AUTO', '自动（检测到的出口国家）');
  [...codes].filter(c => /^[A-Z]{2}$/.test(c)).sort((a, b) => countryLabel(a).localeCompare(countryLabel(b), 'zh-CN'))
    .forEach(c => option(c, countryLabel(c)));
  select.value = auto ? 'AUTO' : results.baselineCountry;
  const stateText = s => ({ SKIPPED: '未测试', FAILED: '检测失败', UNAVAILABLE: '定位不可用',
    VALID_FRESH_FIX: '已获取有效定位', SUCCESS: '已获取定位', WAITING: '等待定位',
    'not requested': '未请求定位', PERMISSION_DENIED: '定位权限被拒绝', TIMEOUT: '定位超时',
    POSITION_UNAVAILABLE: '定位不可用', API_UNAVAILABLE: '浏览器不支持', ERROR: '检测失败',
    NO_PUBLIC_CANDIDATE: '无公开候选地址', UNVERIFIED: '无法比较' }[s] || s || '未测试');
  const add = (source, name, value, reference, status, note = '', mode = 'country') =>
    rows.push({ mode, source, name, value: value || '未知', reference: reference || '无可用基准', status, note });
  const cmp = (source, name, countries, note = '', missing = '无法确定地区', referenceRow = false) => {
    const cs = [...new Set((Array.isArray(countries) ? countries : [countries]).filter(Boolean))];
    add(source, name, cs.length ? cs.map(countryLabel).join('、') : missing, countryLabel(refC),
      !cs.length || !refC ? 'NA' : cs.some(c => c !== refC) ? 'MISMATCH' : auto && referenceRow ? 'REFERENCE' : 'MATCH', note);
  };
  const stat = (source, name, value, reference, ok, note = '') =>
    add(source, name, value, reference, ok === null ? 'NA' : ok ? 'MATCH' : 'MISMATCH', note, 'pair');
  const pairCountries = (source, name, left, right, leftLabel, rightLabel, note = '', partial = false) => {
    const unique = v => [...new Set((Array.isArray(v) ? v : [v]).filter(Boolean))].sort();
    const a = unique(left), b = unique(right);
    const ok = !a.length || !b.length ? null : a.length === b.length && a.every((c, i) => c === b[i]);
    stat(source, name, leftLabel + '：' + (a.length ? a.map(countryLabel).join('、') : '未知 / 未测试'),
      rightLabel + '：' + (b.length ? b.map(countryLabel).join('、') : '未知 / 未测试'), ok, note);
    if (partial && rows[rows.length - 1].status !== 'MISMATCH') {
      rows[rows.length - 1].status = 'WARN'; rows[rows.length - 1].note += '部分地区数据未知。';
    }
  };
  const names = {
    'Device setup region (DeviceRegion)': '设备设置地区', 'Windows home location': 'Windows 当前地区',
    'Regional format (user culture)': '区域格式', 'Display language (UI culture)': '显示语言地区',
    'System locale (non-Unicode)': '非 Unicode 程序地区'
  };
  for (const s of audit.signals || []) {
    cmp('PowerShell', names[s.Name] || s.Name, s.Country,
      s.Value + (s.Strength === 'Weak' ? '；语言偏好仅供参考，不代表物理位置。' : ''),
      '未识别到国家/地区');
  }
  // Support reports without the new audit payload.
  if (!audit.signals) cmp('PowerShell', 'Windows 当前地区', ref.homeLocation);
  const pathNames = ['直连 IPv4 出口', '直连 IPv6 出口', '系统代理出口', '环境代理出口'];
  (audit.egress || []).forEach((r, i) => {
    const votes = Object.entries(r.votes || {}).map(([provider, c]) => provider + '=' + c).join('；');
    const note = r.agreement === 'SINGLE_SOURCE' ? '仅一个定位来源，尚未交叉验证。' :
      r.agreement === 'DISAGREE' ? '定位数据库意见不同：' + votes : votes;
    cmp('PowerShell', pathNames[i] || r.path, r.country, note,
      r.status === 'OK' ? '定位数据库未能确定国家' : stateText(r.status), !bc && r.path === ref.referencePath);
    if (['SINGLE_SOURCE', 'DISAGREE'].includes(r.agreement) && rows[rows.length - 1].status !== 'MISMATCH')
      rows[rows.length - 1].status = 'WARN';
  });
  cmp('PowerShell', '递归 DNS 出口地区（抽样）', audit.dnsCountries || [],
    'DNS 地区不同可能是正常解析策略；浏览器 DoH 可能另走路径。', audit.online ? '未能获得 DNS 地区' : '未测试（未启用 -Online）');
  stat('PowerShell', 'Windows 时区 vs PowerShell IP 时区',
    (ref.systemTimezoneId || '未知') + ' ' + offLabel(ref.systemUtcOffsetMinutes),
    (ref.ipTimezoneId || '未知') + ' ' + offLabel(num(ref.ipTimezoneOffsetSeconds) === null ? null : ref.ipTimezoneOffsetSeconds / 60),
    num(ref.ipTimezoneOffsetSeconds) === null || num(ref.systemUtcOffsetMinutes) === null ? null :
      ref.systemUtcOffsetMinutes === ref.ipTimezoneOffsetSeconds / 60,
    '比较当前 UTC 偏移（含夏令时）；偏移相同不能证明属于同一国家。');
  const fix = audit.windowsLocation || {};
  const fixDistance = num(fix.distanceKm);
  stat('PowerShell', 'Windows 定位 vs PowerShell IP 定位',
    fixDistance === null ? stateText(fix.status) : fixDistance + ' km；精度 ±' + Math.round(fix.accuracyMeters) + ' m',
    'PowerShell 参考出口的近似 IP 位置；距离 ≤300 km', fixDistance === null ? null : fixDistance <= 300,
    '此项只比较距离，不从坐标猜测国家。');
  add('PowerShell', 'Microsoft 账户注册地区', '需手动核对', countryLabel(refC), 'NA', '本脚本无法自动读取账户注册国家。');

  for (const [key, name] of [['ipv4', 'IPv4 出口地区'], ['ipv6', 'IPv6 出口地区']]) {
    const item = e && e[key];
    cmp('Browser', name, item && item.geo && item.geo.countryCode, 'ipwho.is 定位。',
      !e ? '未测试' : item && item.error ? '出口检测失败' : '未能确定国家', bc && browserCountry({ [key]: item }) === bc && key === 'ipv4');
  }
  const cfl = e && e.cloudflare && e.cloudflare.loc && !['XX', 'T1'].includes(e.cloudflare.loc) ? e.cloudflare.loc : null;
  cmp('Browser', 'Cloudflare 出口地区', cfl, 'loc 表示客户端 IP 的国家，不是机房所在地。', !e ? '未测试' : '未能确定国家');
  const publicCandidates = w && w.publicIPs || [];
  const wcs = publicCandidates.map(p => p.geo && p.geo.countryCode).filter(Boolean);
  cmp('Browser', 'WebRTC 公开地址地区', wcs, '只按国家判断地区差异；不同 IP 但同国家不会标红。', stateText(w && w.status));
  if (publicCandidates.length && wcs.length < publicCandidates.length && rows[rows.length - 1].status !== 'MISMATCH') {
    rows[rows.length - 1].status = 'WARN';
    rows[rows.length - 1].note += '部分候选地址的地区未知。';
  }
  cmp('Browser', '浏览器语言地区', info.languageRegion, info.language + '；语言偏好仅供参考。', '语言未指定国家/地区');
  cmp('Browser', 'Intl 格式地区', info.intlLocaleRegion, info.intlLocale + '；格式偏好仅供参考。', '格式未指定国家/地区');
  const ipOffSec = firstNum(e && e.ipv4 && e.ipv4.geo && e.ipv4.geo.timezoneOffsetSeconds,
                            e && e.ipv6 && e.ipv6.geo && e.ipv6.geo.timezoneOffsetSeconds, ref.ipTimezoneOffsetSeconds);
  const offsetFromBrowser = firstNum(e && e.ipv4 && e.ipv4.geo && e.ipv4.geo.timezoneOffsetSeconds,
    e && e.ipv6 && e.ipv6.geo && e.ipv6.geo.timezoneOffsetSeconds) !== null;
  stat('Browser', '浏览器时区 vs IP 时区', info.timezone + ' ' + offLabel(info.utcOffsetMinutes),
    (offsetFromBrowser ? '浏览器 IP：' : 'PowerShell IP：') + offLabel(ipOffSec === null ? null : ipOffSec / 60),
    ipOffSec === null ? null : info.utcOffsetMinutes === ipOffSec / 60, '比较当前 UTC 偏移。');
  stat('Browser / PowerShell', '浏览器时区 vs Windows 时区', offLabel(info.utcOffsetMinutes),
    (ref.systemTimezoneId || 'Windows') + ' ' + offLabel(ref.systemUtcOffsetMinutes),
    num(ref.systemUtcOffsetMinutes) === null ? null : info.utcOffsetMinutes === ref.systemUtcOffsetMinutes);
  const d = g && g.status === 'SUCCESS' ? firstNum(g.distanceToBrowserIPKm, g.distanceToPowerShellIPKm) : null;
  stat('Browser', '网页定位 vs IP 定位', d === null ? stateText(g && g.status) : d + ' km；精度 ±' + g.accuracyMeters + ' m',
    (g && num(g.distanceToBrowserIPKm) !== null ? '浏览器' : 'PowerShell') + ' IP 近似位置；距离 ≤300 km',
    d === null ? null : d <= 300, '距离是近似信号，不是国家归属判定。');
  const psPaths = audit.egress || [];
  const ps4 = psPaths[0] ? psPaths[0].country : ref.directIPv4Country;
  const ps6 = psPaths[1] ? psPaths[1].country : ref.directIPv6Country;
  const psProxy = psPaths[2] ? psPaths[2].country : ref.systemProxyCountry;
  const psEnv = psPaths[3] && psPaths[3].country;
  const browser4 = e && e.ipv4 && e.ipv4.geo && e.ipv4.geo.countryCode;
  const browser6 = e && e.ipv6 && e.ipv6.geo && e.ipv6.geo.countryCode;
  pairCountries('PowerShell', '直连 IPv4 vs IPv6 地区', ps4, ps6, '直连 IPv4', '直连 IPv6');
  pairCountries('PowerShell', '直连 vs 系统代理地区', ps4, psProxy, '直连 IPv4', '系统代理');
  pairCountries('PowerShell', '环境代理 vs 系统代理地区', psEnv, psProxy, '环境代理', '系统代理');
  pairCountries('PowerShell', 'DNS vs PowerShell 出口地区', audit.dnsCountries || [], ref.referenceCountry,
    '递归 DNS（抽样）', 'PowerShell 参考出口', 'DNS 国家不同可能是正常配置，并不证明泄露。');
  pairCountries('Browser / PowerShell', '浏览器 vs 系统代理地区', bc, psProxy, '浏览器 HTTP 参考出口', '系统代理');
  pairCountries('Browser', '浏览器 IPv4 vs IPv6 地区', browser4, browser6, '浏览器 IPv4', '浏览器 IPv6');
  pairCountries('Browser', 'WebRTC vs HTTP 出口地区', wcs, bc, 'WebRTC 公开地址', '浏览器 HTTP 参考出口',
    '只比较国家，不比较 IP 是否相同。', publicCandidates.length > wcs.length);

  const rank = { MISMATCH: 0, WARN: 1, REFERENCE: 2, MATCH: 3, NA: 4 };
  const countryRows = rows.filter(r => r.mode === 'country').sort((a, b) => rank[a.status] - rank[b.status]);
  const pairRows = rows.filter(r => r.mode === 'pair').sort((a, b) => rank[a.status] - rank[b.status]);
  const draw = (id, data) => {
    const tb = $(id); tb.textContent = '';
    for (const r of data) {
      const tr = document.createElement('tr'); tr.className = r.status;
      for (const t of [r.source, r.name, r.value, r.reference]) { const td = document.createElement('td'); td.textContent = String(t); tr.appendChild(td); }
      const td = document.createElement('td'), s = document.createElement('span'); s.className = 'tag ' + r.status;
      s.textContent = (r.mode === 'country' ?
        { NA: '未验证', WARN: '证据不足', MATCH: '符合基准', MISMATCH: '不符合基准', REFERENCE: '自动参考' } :
        { NA: '未验证', WARN: '证据不足', MATCH: '一致', MISMATCH: '不一致' })[r.status];
      td.appendChild(s); tr.appendChild(td);
      const note = document.createElement('td'); note.textContent = r.note; tr.appendChild(note); tb.appendChild(tr);
    }
  };
  draw('matrix', countryRows); draw('pairMatrix', pairRows);
  const bad = countryRows.filter(r => r.status === 'MISMATCH');
  const compared = countryRows.filter(r => r.status === 'MATCH' || r.status === 'MISMATCH');
  const unknown = countryRows.filter(r => ['NA', 'WARN'].includes(r.status));
  const summaryStatus = bad.length ? 'MISMATCH' : !refC || !compared.length ? 'INSUFFICIENT_DATA' : unknown.length ? 'PARTIAL' : 'CONSISTENT';
  $('reference').textContent = '当前国家基准：' + (refSrc ? countryLabel(refC) + '（' + refSrc + '）' : '暂无；请选择国家或运行出口检查') +
    (auto ? '。自动模式会随检测到的出口更新。' : '。手动选择会保持不变，后续测试也沿用此国家。');
  $('countMismatch').textContent = '不符合基准 ' + bad.length + ' 项';
  $('countMatch').textContent = '符合基准 ' + countryRows.filter(r => r.status === 'MATCH').length + ' 项';
  $('countUnknown').textContent = '未验证 / 证据不足 ' + unknown.length + ' 项';
  $('overall').textContent = bad.length ? '有 ' + bad.length + ' 项国家与基准不同，已置顶。' :
    summaryStatus === 'INSUFFICIENT_DATA' ? '数据不足，尚不能判断是否符合基准国家。' :
    summaryStatus === 'PARTIAL' ? '已比较的国家符合基准，仍有未验证或证据不足的项目。' : '已比较的国家均符合基准。';
  const pairBad = pairRows.filter(r => r.status === 'MISMATCH');
  const pairKnown = pairRows.filter(r => r.status === 'MATCH');
  const pairUnknown = pairRows.filter(r => ['NA', 'WARN'].includes(r.status));
  const pairSummaryStatus = pairBad.length ? 'MISMATCH' : !pairKnown.length ? 'INSUFFICIENT_DATA' : pairUnknown.length ? 'PARTIAL' : 'CONSISTENT';
  $('pairMismatch').textContent = '互相不一致 ' + pairBad.length + ' 项';
  $('pairMatch').textContent = '互相一致 ' + pairKnown.length + ' 项';
  $('pairUnknown').textContent = '未验证 / 证据不足 ' + pairUnknown.length + ' 项';
  $('pairOverall').textContent = pairBad.length ? '有 ' + pairBad.length + ' 组实测结果不同，已置顶。这些结论与所选国家无关。' :
    !pairKnown.length ? '暂无可比较的两组结果；结论与所选国家无关。' : '可比较的结果互相一致' + (pairUnknown.length ? '，仍有未验证项目。' : '。');
  results.matrix = { reference: refC, referenceSource: refSrc, referenceMode: auto ? 'auto' : 'manual',
    summaryStatus, pairSummaryStatus, countryRows, pairRows, rows: [...countryRows, ...pairRows] };
}

function downloadBlob(blob, name) {
  const url = URL.createObjectURL(blob), link = document.createElement('a');
  link.href = url; link.download = name; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function download(data, name) {
  downloadBlob(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }), name);
}
function redact(obj) {
  const s = JSON.parse(JSON.stringify(obj));
  const drop = ['ip', 'address', 'directIPv4', 'directIPv6', 'systemProxyIP', 'latitude', 'longitude'];
  const walk = o => {
    if (Array.isArray(o)) { o.forEach(walk); return; }
    if (!o || typeof o !== 'object') return;
    for (const k of Object.keys(o)) {
      if (drop.includes(k)) delete o[k];
      else if (k === 'localHostIPsExposed' && Array.isArray(o[k])) o[k] = o[k].length + ' address(es) redacted';
      else walk(o[k]);
    }
  };
  walk(s);
  return s; // Browser language, timezone and user agent are retained; review before sharing.
}
function saveHtml() {
  renderMatrix();
  const safe = redact(results), clone = document.documentElement.cloneNode(true);
  const json = value => JSON.stringify(value).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
  clone.querySelector('#savedResults').textContent = json(safe);
  const script = clone.querySelector('script:not([type])');
  script.textContent = script.textContent.replace(/const ref = [^\n]*\|\| \{\};/, () => 'const ref = ' + json(redact(ref)) + ' || {};');
  for (const [id, value] of [['browser', safe.browser], ['ref', safe.psReference], ['egress', safe.egress], ['webrtc', safe.webrtc], ['geo', safe.geolocation]]) {
    clone.querySelector('#' + id).textContent = JSON.stringify(value, null, 2);
  }
  downloadBlob(new Blob(['<!doctype html>\n' + clone.outerHTML], { type: 'text/html;charset=utf-8' }), 'WindowsBrowserRegionSummary.html');
}
const guard = (fn, id) => () => Promise.resolve().then(() => {
  Object.assign(info, sessionInfo); results.browser = info;
  return fn();
}).catch(err => show(id, 'ERROR: ' + errText(err)));
$('btnEgress').onclick = guard(runEgress, 'egress');
$('btnWebrtc').onclick = guard(runWebRTC, 'webrtc');
$('btnGeo').onclick = guard(runGeo, 'geo');
$('btnAll').onclick = guard(async () => { await runEgress(); await runWebRTC(); await runGeo(); }, 'egress');
$('saveSafe').onclick = () => download(redact(results), 'BrowserLocationResults_redacted.json');
$('saveHtml').onclick = saveHtml;
$('baselineCountry').onchange = () => {
  results.baselineCountry = $('baselineCountry').value;
  renderMatrix();
};
$('saveFull').onclick = () => {
  if (confirm('Full JSON may contain precise device coordinates and your public IPs. Save privately?'))
    download(results, 'BrowserLocationResults_full.json');
};
renderMatrix();
</script></body></html>
'@
$html = $html.Replace('__PS_REFERENCE__', $psRefJson)
$html | Set-Content -LiteralPath $htmlFile -Encoding UTF8

Section '20. BROWSER PROBE' {
    "HTML filename: $(Split-Path -Leaf $htmlFile)"
    'Open locally in the browser you want to inspect, then click "Run all checks".'
    'It checks browser HTTP egress (IPv4/IPv6/Cloudflare), WebRTC exposure, timezone, language and geolocation.'
    'Network requests are made only after a click. Save a redacted or full JSON afterwards.'
    'Local files (file://) may have browser-dependent permission behavior.'
}

Section '21. CONSISTENCY MATRIX' {
    $ref = Get-ReferenceEgress
    $refCountry = if ($ref) { $ref.Country } else { $null }
    "Reference: $(if ($ref) { "$($ref.Path) = $refCountry" } else { 'none (run with -Online)' })"
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($s in $script:signals) {
        $st = if ($s.Status) { $s.Status }
              elseif (-not $s.Country) { 'N/A' }
              elseif (-not $refCountry) { 'NO_REF' }
              elseif ($s.Country -eq $refCountry) { 'MATCH' }
              else { 'MISMATCH' }
        $val = if ($s.Country) { "$($s.Country) ($($s.Value))" } else { $s.Value }
        $rows.Add([PSCustomObject]@{ Signal = $s.Name; Value = $val; Strength = $s.Strength; Status = $st })
    }
    foreach ($r in @($script:v4, $script:v6, $script:proxyPath, $script:envPath)) {
        if ($r.Status -eq 'SKIPPED') { continue }
        $val = if ($r.Status -eq 'OK') { "$($r.Country) [$($r.Agreement)]" } else { $r.Status }
        $st = if ($r.Status -ne 'OK' -or -not $r.Country) { 'N/A' }
              elseif ($ref -and [object]::ReferenceEquals($r, $ref)) { 'REFERENCE' }
              elseif ($r.Country -eq $refCountry) { 'MATCH' }
              else { 'MISMATCH' }
        $rows.Add([PSCustomObject]@{ Signal = "Egress: $($r.Path)"; Value = $val; Strength = 'Strong'; Status = $st })
    }
    $dnsCountries = @($script:dnsResults | Where-Object { $_.Geo } |
        ForEach-Object { ([string]$_.Geo.country_code).ToUpperInvariant() } | Sort-Object -Unique)
    if ($dnsCountries.Count) {
        $st = if (-not $refCountry) { 'NO_REF' }
              elseif (@($dnsCountries | Where-Object { $_ -ne $refCountry }).Count) { 'MISMATCH' }
              else { 'MATCH' }
        $rows.Add([PSCustomObject]@{ Signal = 'Recursive DNS resolvers (sample)'; Value = ($dnsCountries -join ', '); Strength = 'Medium'; Status = $st })
    }
    $rows | Format-Table Signal, Value, Strength, Status -AutoSize -Wrap
    $mis = @($rows | Where-Object { $_.Status -eq 'MISMATCH' })
    $compared = @($rows | Where-Object { $_.Status -in @('MATCH', 'MISMATCH') })
    $unavailable = @($rows | Where-Object { $_.Status -in @('N/A', 'NO_REF') })
    $failedEgress = @($script:v4, $script:v6, $script:proxyPath, $script:envPath |
        Where-Object { $_.Status -eq 'FAILED' })
    if ($mis.Count -gt 0) {
        "OVERALL: $($mis.Count) SIGNAL DIFFERENCE(S):"
        foreach ($m in $mis) { "  - [$($m.Strength)] $($m.Signal): $($m.Value)" }
    }
    elseif (-not $refCountry -or $compared.Count -eq 0) {
        'OVERALL: INSUFFICIENT_DATA. Regional consistency has not been verified.'
    }
    elseif ($unavailable.Count -gt 0 -or $failedEgress.Count -gt 0) {
        'OVERALL: PARTIAL. No differences among compared signals; some checks are unavailable or failed.'
    }
    else { 'OVERALL: CONSISTENT. All compared signals match.' }
    'Coverage: optional skipped checks are not verified. Signal differences alone do not prove location leakage.'
    'Strength: Strong = commonly used by sites/services for region decisions; Weak = informational only.'
    'Browser-side signals (browser egress, WebRTC, browser timezone) are in the HTML probe matrix.'
}

Section '22. AUDIT SUMMARY' {
    'Microsoft account registered country: manual verification required.'
    foreach ($r in @($script:v4, $script:v6, $script:proxyPath, $script:envPath)) {
        "$($r.Path): $($r.Status)$(if ($r.Country) { " -> $($r.Country) [$($r.Agreement)]" })"
    }
    "Fake-IP DNS: $(if ($null -eq $script:fakeIp) { 'not tested / inconclusive' } elseif ($script:fakeIp) { 'DETECTED' } else { 'not detected' })"
    if ($script:routeSummary.Count) { "Selected routes: $($script:routeSummary -join '; ')" }
    "Proxy/VPN client processes detected: $($script:proxyClients.Count)"
    "Recursive DNS egress addresses sampled: $($script:dnsResults.Count)"
    if ($script:windowsFix) { 'Windows location provider: valid recent fix; coordinates not in text.' }
    elseif ($WindowsLocation) { 'Windows location provider: no accepted recent fix.' }
    'Interpret egress-IP tests, resolver tests, and device geolocation separately.'
    if ($ShareSafe) { 'ShareSafe enabled: manual review is still needed before publication.' }
}

$report | Set-Content -LiteralPath $txtFile -Encoding UTF8
Write-Output ($report -join [Environment]::NewLine)
Write-Host ''
Write-Host 'Audit finished. No Windows settings changed.' -ForegroundColor Green
Write-Host "Report: $txtFile" -ForegroundColor Cyan
Write-Host "Browser page: $htmlFile" -ForegroundColor Cyan
if ($OpenBrowserProbe -and -not $NoBrowserProbe) {
    try { Start-Process -FilePath $htmlFile -ErrorAction Stop }
    catch { Write-Warning "Cannot open browser automatically: $($_.Exception.Message)" }
}
