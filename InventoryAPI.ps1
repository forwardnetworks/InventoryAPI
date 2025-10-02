<#  InventoryApi.ps1  — tiny HTTPS JSON endpoint for Windows inventory
    - Serves GET /inventory
    - Auth: Basic; validated against AD (DOMAIN\user or user@domain)
    - TLS: use http.sys cert binding (see setup section below)
    - License: MIT (see LICENSE)
    - Disclaimer: Provided "AS IS" without warranty of any kind.
#>

[CmdletBinding()]
param(
  [ValidateSet('http','https')]
  [string]$Scheme = 'https',
  [int]$Port = 8443,
  [string]$Endpoint = "inventory",
  [string]$CertificateThumbprint,
  [string]$CertificateDnsName,
  [switch]$AutoConfigureHttps,
  [switch]$EnableDebug
)

$script:EnableDebug = $EnableDebug.IsPresent
$script:CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$script:CurrentAccountName = $script:CurrentIdentity.Name

if (-not $PSBoundParameters.ContainsKey('CertificateDnsName') -or [string]::IsNullOrWhiteSpace($CertificateDnsName)) {
  $defaultDns = $env:COMPUTERNAME
  if ($env:USERDNSDOMAIN) {
    $defaultDns = "$env:COMPUTERNAME.$($env:USERDNSDOMAIN)".TrimEnd('.')
  }
  $CertificateDnsName = $defaultDns
}

$script:CertificateDnsName = $CertificateDnsName
$script:AutoConfigureHttps = $AutoConfigureHttps.IsPresent

$endpointValue = if ($null -eq $Endpoint) { '' } else { $Endpoint }
$normalizedEndpoint = $endpointValue.Trim('/')
if ($normalizedEndpoint) {
  $script:EndpointPath = "/$normalizedEndpoint"
  $Prefix = "${Scheme}://+:$Port$($script:EndpointPath)/"
} else {
  $script:EndpointPath = '/'
  $Prefix = "${Scheme}://+:$Port/"
}
$script:ExpectedPath = if ($script:EndpointPath -eq '/') { '/' } else { $script:EndpointPath }

# --- Imports ---
Add-Type -AssemblyName System.DirectoryServices.AccountManagement

function Write-DebugLog {
  param([string]$Message)
  if ($script:EnableDebug) {
    Write-Host "[DEBUG] $Message"
  }
}

Write-DebugLog "Configured prefix '${Prefix}' for endpoint path '$($script:ExpectedPath)' on port $Port using scheme '$Scheme'."

function Test-IsAdministrator {
  try {
    $principal = New-Object Security.Principal.WindowsPrincipal($script:CurrentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    return $false
  }
}

function Get-UrlAclAccounts {
  param([string]$Prefix)

  try {
    $output = & netsh http show urlacl url=$Prefix 2>&1
  } catch {
    Write-DebugLog "Failed to query URL ACL for ${Prefix}: $($_.Exception.Message)"
    return @()
  }

  if ($LASTEXITCODE -ne 0) {
    Write-DebugLog "netsh returned $LASTEXITCODE when checking URL ACL for ${Prefix}."
    return @()
  }

  $users = @()
  foreach ($line in $output) {
    if ($line -match 'User:\s*(.+)$') {
      $users += $matches[1].Trim()
    }
  }

  if ($users.Count -eq 0) {
    Write-DebugLog "No URL ACL entries found for ${Prefix}."
  } else {
    Write-DebugLog "URL ACL entries for ${Prefix}: $($users -join ', ')."
  }

  return $users
}

function Ensure-UrlAcl {
  param([string]$Prefix)

  $accounts = Get-UrlAclAccounts -Prefix $Prefix

  if ($accounts -contains $script:CurrentAccountName) {
    Write-DebugLog "URL ACL already grants access to $($script:CurrentAccountName)."
    return $true
  }

  if ($accounts.Count -gt 0) {
    Write-Error "URL ACL for ${Prefix} is reserved for: $($accounts -join ', '). Adjust or remove it before running the listener."
    return $false
  }

  if (-not (Test-IsAdministrator)) {
    Write-Error "URL ACL for ${Prefix} is missing and the script is not running elevated. Run in an elevated shell or execute 'netsh http add urlacl url=${Prefix} user=$($script:CurrentAccountName)'."
    return $false
  }

  Write-DebugLog "Attempting to reserve URL ACL for ${Prefix} as $($script:CurrentAccountName)."
  try {
    $netshOutput = & netsh http add urlacl url=${Prefix} user=$script:CurrentAccountName 2>&1
  } catch {
    Write-Error "Failed to add URL ACL for ${Prefix}: $($_.Exception.Message)"
    return $false
  }

  foreach ($line in $netshOutput) { Write-DebugLog $line }

  if ($LASTEXITCODE -ne 0) {
    if ($netshOutput -match 'Error:\s*183') {
      Write-DebugLog "URL ACL appears to already exist; verifying ownership."
      $accounts = Get-UrlAclAccounts -Prefix $Prefix
      if ($accounts -contains $script:CurrentAccountName) {
        Write-DebugLog "Existing URL ACL already grants access to $($script:CurrentAccountName)."
        return $true
      }

      if ($accounts.Count -gt 0) {
        Write-Error "URL ACL for ${Prefix} already exists for: $($accounts -join ', '). Remove it manually or run the script under that account."
        return $false
      }

      Write-Error "URL ACL for ${Prefix} already exists but ownership could not be determined. Remove it with 'netsh http delete urlacl url=${Prefix}' and rerun."
      return $false
    }

    Write-Error "netsh failed to add URL ACL for ${Prefix} (exit $LASTEXITCODE)."
    return $false
  }

  Write-DebugLog "URL ACL reservation created for ${Prefix}."
  return $true
}

function Get-NormalizedThumbprint {
  param([string]$Thumbprint)
  if ([string]::IsNullOrWhiteSpace($Thumbprint)) { return $null }
  return ($Thumbprint -replace '\s','').ToUpperInvariant()
}

function Get-LocalMachineCertificate {
  param([string]$Thumbprint)
  $normalized = Get-NormalizedThumbprint $Thumbprint
  if (-not $normalized) { return $null }
  try {
    return Get-Item -Path "Cert:\\LocalMachine\\My\\$normalized" -ErrorAction Stop
  } catch {
    return $null
  }
}

function Get-SslBindingInfo {
  param([int]$Port)

  try {
    $output = & netsh http show sslcert 2>&1
  } catch {
    Write-DebugLog "Failed to query SSL bindings: $($_.Exception.Message)"
    return $null
  }

  if ($LASTEXITCODE -ne 0) {
    Write-DebugLog "netsh returned $LASTEXITCODE while listing SSL bindings."
    return $null
  }

  $current = $null
  $bindings = @()

  foreach ($line in $output) {
    if ($line -match '^\s*IP:port\s*:\s*(.+)$') {
      if ($current) { $bindings += [pscustomobject]$current }
      $current = @{ IpPort = $matches[1].Trim() }
    } elseif ($current -and $line -match '^\s*Certificate Hash\s*:\s*([0-9A-Fa-f]+)') {
      $current.Hash = $matches[1].Trim().ToUpperInvariant()
    } elseif ($current -and $line -match '^\s*Application ID\s*:\s*({[0-9A-Fa-f-]+})') {
      $current.AppId = $matches[1].Trim()
    } elseif ($current -and $line -match '^\s*Certificate Store Name\s*:\s*(\S+)') {
      $current.Store = $matches[1].Trim()
    }
  }

  if ($current) { $bindings += [pscustomobject]$current }

  foreach ($binding in $bindings) {
    if ($binding.IpPort -match ':(\d+)$') {
      $bindingPort = [int]$matches[1]
      if ($bindingPort -eq $Port) {
        return $binding
      }
    }
  }

  return $null
}

function Ensure-SslBinding {
  param(
    [string]$Scheme,
    [int]$Port,
    [string]$Thumbprint,
    [switch]$AutoConfigure,
    [string]$DnsName
  )

  if ($Scheme -ne 'https') {
    Write-DebugLog "Scheme is HTTP; skipping SSL binding check."
    return $true
  }

  Write-DebugLog "Ensuring SSL binding for port $Port."
  $existing = Get-SslBindingInfo -Port $Port
  if ($existing) {
    Write-DebugLog "Found existing SSL binding on $($existing.IpPort) with thumbprint $($existing.Hash)."
    if ($Thumbprint) {
      $desired = Get-NormalizedThumbprint $Thumbprint
      if ($existing.Hash -eq $desired) {
        Write-DebugLog "Existing binding matches requested certificate thumbprint.";
        return $true
      }
      Write-Error "SSL binding for port $Port already uses thumbprint $($existing.Hash); expected $desired. Remove or update the binding before starting the API."
      return $false
    }

    return $true
  }

  if (-not (Test-IsAdministrator)) {
    $instructions = @(
      "SSL binding for port $Port is missing and this session is not elevated.",
      "Have an administrator create the binding (run in elevated PowerShell):",
      "  netsh http add sslcert ipport=0.0.0.0:$Port certhash=<thumbprint> certstore=MY appid={<guid>}",
      "Ensure the certificate exists in Cert:\\LocalMachine\\My and either supply -CertificateThumbprint or rerun with -AutoConfigureHttps from an elevated shell."
    ) -join [Environment]::NewLine
    Write-Error $instructions
    return $false
  }

  $bindingThumbprint = $null
  $certificate = $null

  if ($Thumbprint) {
    $bindingThumbprint = Get-NormalizedThumbprint $Thumbprint
    $certificate = Get-LocalMachineCertificate $bindingThumbprint
    if (-not $certificate) {
      Write-Error "Certificate with thumbprint $bindingThumbprint was not found in Cert:\\LocalMachine\\My."
      return $false
    }
  } elseif ($AutoConfigure) {
    Write-DebugLog "Creating self-signed certificate for ${DnsName}."
    try {
      $certificate = New-SelfSignedCertificate -DnsName $DnsName -CertStoreLocation "Cert:\\LocalMachine\\My" -FriendlyName "Inventory API (${DnsName})"
    } catch {
      Write-Error "Failed to create self-signed certificate for ${DnsName}: $($_.Exception.Message)"
      return $false
    }

    $bindingThumbprint = Get-NormalizedThumbprint $certificate.Thumbprint
    Write-DebugLog "Created self-signed certificate with subject '$($certificate.Subject)' and thumbprint $bindingThumbprint."
  } else {
    $instructions = @(
      "No SSL binding found for port $Port.",
      "Either provide -CertificateThumbprint for a certificate in Cert:\\LocalMachine\\My or rerun the script in an elevated shell with -AutoConfigureHttps.",
      "An administrator can also configure it manually with:",
      "  netsh http add sslcert ipport=0.0.0.0:$Port certhash=<thumbprint> certstore=MY appid={<guid>}"
    ) -join [Environment]::NewLine
    Write-Error $instructions
    return $false
  }

  if (-not $bindingThumbprint) {
    Write-Error "Unable to determine certificate thumbprint for SSL binding."
    return $false
  }

  $appId = '{' + ([guid]::NewGuid().ToString()) + '}'
  Write-DebugLog "Binding certificate $bindingThumbprint to 0.0.0.0:${Port} with AppId $appId."

  try {
    $netshOutput = & netsh http add sslcert ipport=0.0.0.0:$Port certhash=$bindingThumbprint certstore=MY appid=$appId 2>&1
  } catch {
    Write-Error "Failed to add SSL binding for port ${Port}: $($_.Exception.Message)"
    return $false
  }

  foreach ($line in $netshOutput) { Write-DebugLog $line }

  if ($LASTEXITCODE -ne 0) {
    Write-Error "netsh failed to add SSL binding for port ${Port} (exit $LASTEXITCODE)."
    return $false
  }

  Write-DebugLog "SSL binding created for port $Port using thumbprint $bindingThumbprint."
  return $true
}


# --- Auth helpers: validate Basic creds against AD ---
function Test-AdCredential {
  param([string]$User,[string]$Pass)
  if (-not $User -or -not $Pass) { return $false }
  try {
    if ($User -match '@') {
      $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Domain')
      return $ctx.ValidateCredentials($User, $Pass)
    } elseif ($User -match '\\') {
      $domain,$sam = $User.Split('\',2)
      $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Domain',$domain)
      return $ctx.ValidateCredentials($sam, $Pass)
    } else {
      $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Machine',$env:COMPUTERNAME)
      return $ctx.ValidateCredentials($User, $Pass)
    }
  } catch { return $false }
}
function Get-BasicAuthPair {
  param($ctx)
  $hdr = $ctx.Request.Headers["Authorization"]
  if (-not $hdr -or -not $hdr.StartsWith("Basic ")) { return $null,$null }
  $raw = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($hdr.Substring(6)))
  return $raw.Split(":",2)
}

function Test-WmiAvailability {
  try {
    Write-DebugLog "Running WMI pre-check (Win32_OperatingSystem)."
    Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop | Out-Null
    Write-DebugLog "WMI pre-check succeeded."
    return $true
  } catch {
    Write-Error "WMI pre-check failed: $($_.Exception.Message)"
    return $false
  }
}

function Test-FirewallAccess {
  param([int]$Port)

  $firewallCmd = Get-Command -Name Get-NetFirewallRule -ErrorAction SilentlyContinue
  if (-not $firewallCmd) {
    Write-DebugLog "Get-NetFirewallRule not available; skipping firewall rule check."
    return $true
  }

  try {
    Write-DebugLog "Checking Windows Firewall inbound rules for TCP port $Port."
    $rules = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop

    foreach ($rule in $rules) {
      $portFilter = $rule | Get-NetFirewallPortFilter
      if (-not $portFilter -or $portFilter.Protocol -ne 'TCP') { continue }

      foreach ($localPort in @($portFilter.LocalPort)) {
        if (-not $localPort) { continue }

        $portText = [string]$localPort
        if ($portText -eq 'Any' -or $portText -eq '*') {
          Write-DebugLog "Firewall rule '$($rule.DisplayName)' allows all TCP ports."
          return $true
        }

        if ($portText -match '^(\d+)-(\d+)$') {
          $start = [int]$matches[1]
          $end = [int]$matches[2]
          if ($Port -ge $start -and $Port -le $end) {
            Write-DebugLog "Firewall rule '$($rule.DisplayName)' covers TCP port $Port via range $portText."
            return $true
          }
          continue
        }

        try {
          if ([int]$localPort -eq $Port) {
            Write-DebugLog "Firewall rule '$($rule.DisplayName)' explicitly allows TCP port $Port."
            return $true
          }
        } catch {
          continue
        }
      }
    }

    Write-Error "No enabled inbound firewall rule allows TCP port $Port. Add an allow rule or choose another port."
    return $false
  } catch {
    Write-Error "Firewall check failed: $($_.Exception.Message)"
    return $false
  }
}

function Convert-DmtfToIso8601 {
  param([string]$Dmtf)

  if ([string]::IsNullOrWhiteSpace($Dmtf)) {
    Write-DebugLog "OS install date not reported; leaving value empty."
    return $null
  }

  try {
    if ($Dmtf -match '^[0-9]{14}\.[0-9]{6}[+-][0-9]{3}$') {
      return ([Management.ManagementDateTimeConverter]::ToDateTime($Dmtf)).ToString("o")
    }

    $parsed = [datetime]::Parse($Dmtf)
    return $parsed.ToString("o")
  } catch {
    Write-DebugLog "Failed to convert DMTF date '$Dmtf': $($_.Exception.Message)"
    return $null
  }
}

function Get-SecureBootState {
  $cmd = Get-Command -Name Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
  if (-not $cmd) {
    Write-DebugLog "Confirm-SecureBootUEFI not available on this system."
    return $null
  }

  try {
    return (Confirm-SecureBootUEFI -ErrorAction Stop) -as [bool]
  } catch {
    Write-DebugLog "Secure Boot check failed: $($_.Exception.Message)"
    return $null
  }
}

function Get-BitLockerMountPoints {
  $cmd = Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue
  if (-not $cmd) {
    Write-DebugLog "Get-BitLockerVolume not available on this system."
    return @()
  }

  try {
    return (Get-BitLockerVolume -ErrorAction Stop | Where-Object { $_.VolumeStatus -eq 'FullyDecrypted' -or $_.VolumeStatus -eq 'FullyEncrypted' } | Select-Object -ExpandProperty MountPoint)
  } catch {
    Write-DebugLog "BitLocker query failed: $($_.Exception.Message)"
    return @()
  }
}

# --- Inventory collection producing the schema above ---
function Get-InventoryObject {
  $cs   = Get-CimInstance Win32_ComputerSystem
  $os   = Get-CimInstance Win32_OperatingSystem
  $bios = Get-CimInstance Win32_BIOS
  $procs = Get-CimInstance Win32_Processor
  $hotfixes = (Get-CimInstance Win32_QuickFixEngineering | Select-Object -ExpandProperty HotFixID) | Where-Object { $_ } | Sort-Object -Unique
  $nics = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE" | ForEach-Object {
    [pscustomobject]@{
      name            = $_.Description
      mac             = $_.MACAddress
      ipv4            = @($_.IPAddress | Where-Object { $_ -match '^\d+\.' })
      ipv6            = @($_.IPAddress | Where-Object { $_ -match ':' })
      defaultGateways = @($_.DefaultIPGateway)
    }
  }
  $disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 3" | ForEach-Object {
    [pscustomobject]@{
      deviceId   = $_.DeviceID
      filesystem = $_.FileSystem
      sizeGB     = [math]::Round(($_.Size/1GB),1)
      freeGB     = [math]::Round(($_.FreeSpace/1GB),1)
    }
  }

  # virtualization hints
  $virtVendor = (Get-CimInstance Win32_ComputerSystemProduct).Vendor
  $isVm = $virtVendor -and ($virtVendor -notmatch 'Microsoft Corporation' -or ($cs.Model -match 'Virtual'))
  $isHyperVHost = $false
  $hyperVCmd = Get-Command -Name Get-WindowsOptionalFeature -ErrorAction SilentlyContinue
  if ($hyperVCmd) {
    try {
      $isHyperVHost = (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -ErrorAction Stop | Select-Object -ExpandProperty State) -eq 'Enabled'
    } catch {
      Write-DebugLog "Hyper-V optional feature check failed: $($_.Exception.Message)"
      $isHyperVHost = $false
    }
  } else {
    Write-DebugLog "Get-WindowsOptionalFeature not available; skipping Hyper-V host detection."
  }

  [ordered]@{
    schemaVersion = "1.0"
    computer = @{
      hostname = $env:COMPUTERNAME
      domain   = $cs.Domain
      fqdn     = "$env:COMPUTERNAME.$($cs.Domain)".TrimEnd('.')
    }
    os = @{
      name        = $os.Caption
      version     = $os.Version
      build       = $os.BuildNumber
      installDate = Convert-DmtfToIso8601 $os.InstallDate
      hotfixes    = $hotfixes
    }
    hardware = @{
      manufacturer = $cs.Manufacturer
      model        = $cs.Model
      serialNumber = $bios.SerialNumber
      cpu          = @{
        name          = ($procs | Select-Object -First 1).Name
        logicalCores  = ($procs | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
        physicalCores = ($procs | Measure-Object -Property NumberOfCores -Sum).Sum
      }
      memoryGB = [math]::Round(($cs.TotalPhysicalMemory/1GB),2)
    }
    disks = $disks
    nics  = $nics
    virtualization = @{
      isHyperVHost = [bool]$isHyperVHost
      isVm         = [bool]$isVm
      vmVendor     = $virtVendor
    }
    security = @{
      joinType        = if ($cs.PartOfDomain) { 'Domain' } else { 'Workgroup' }
      secureBoot      = Get-SecureBootState
      bitlockerVolumes= Get-BitLockerMountPoints
    }
    timestamp = (Get-Date).ToString("o")
  }
}

# --- HTTP helpers ---
function Send-Json { param($ctx,[int]$code,$obj)
  $ctx.Response.StatusCode = $code
  $json = ($obj | ConvertTo-Json -Depth 8)
  $bytes = [Text.Encoding]::UTF8.GetBytes($json)
  $ctx.Response.ContentType = "application/json"
  $ctx.Response.ContentEncoding = [Text.Encoding]::UTF8
  $ctx.Response.ContentLength64 = $bytes.Length
  $ctx.Response.OutputStream.Write($bytes,0,$bytes.Length)
  $ctx.Response.OutputStream.Close()
}
function Send-Unauthorized { param($ctx)
  $ctx.Response.AddHeader("WWW-Authenticate","Basic realm=`"Inventory`"")
  $ctx.Response.StatusCode = 401
  $ctx.Response.OutputStream.Close()
}

# --- Listener ---
if (-not (Test-WmiAvailability)) {
  Write-Error "Inventory API cannot start without WMI access."
  exit 1
}

if (-not (Test-FirewallAccess -Port $Port)) {
  Write-Error "Inventory API cannot start without an inbound firewall rule for TCP port $Port."
  exit 1
}

if (-not (Ensure-UrlAcl -Prefix $Prefix)) {
  Write-Error "Inventory API cannot start without the required URL ACL reservation for $Prefix."
  exit 1
}

if (-not (Ensure-SslBinding -Scheme $Scheme -Port $Port -Thumbprint $CertificateThumbprint -AutoConfigure:$AutoConfigureHttps.IsPresent -DnsName $CertificateDnsName)) {
  Write-Error "Inventory API cannot start without an SSL certificate binding for port $Port."
  exit 1
}

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add($Prefix)   # e.g., https://+:8443/inventory/
$listener.Start()
Write-Host "Inventory API listening at $Prefix"
Write-DebugLog "Listening started."

try {
  while ($listener.IsListening) {
    $ctx = $listener.GetContext()

    Write-DebugLog "Received $($ctx.Request.HttpMethod) $($ctx.Request.Url.AbsolutePath)."

    $requestedPath = $ctx.Request.Url.AbsolutePath.TrimEnd('/')
    if (-not $requestedPath) { $requestedPath = '/' }

    if ($ctx.Request.HttpMethod -ne 'GET' -or $requestedPath -ne $script:ExpectedPath) {
      Send-Json $ctx 404 @{ error = "not found" }
      continue
    }

    $u,$p = Get-BasicAuthPair $ctx
    if (-not (Test-AdCredential -User $u -Pass $p)) {
      Write-DebugLog "Authentication failed for user '$u'."
      Send-Unauthorized $ctx
      continue
    }

    Write-DebugLog "Authentication succeeded for user '$u'."

    try {
      $obj = Get-InventoryObject
      Send-Json $ctx 200 $obj
    } catch {
      Write-DebugLog "Inventory collection failed: $($_.Exception.Message)"
      Send-Json $ctx 500 @{ error = $_.Exception.Message }
    }
  }
} finally {
  Write-DebugLog "Stopping listener."
  $listener.Stop()
}
