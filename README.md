# Inventory API

InventoryAPI.ps1 is a self-hosted HTTPS/HTTP listener that exposes a tiny JSON endpoint with Windows inventory data. It uses `HttpListener` so you can deploy the script on any Windows host with PowerShell 5.1 or later.

## Features
- Basic authentication against Active Directory or local machine accounts.
- Collects hardware, OS, security, and networking details via WMI/CIM.
- Optional debug logging streamed to the console.
- Pre-flight checks for WMI access, Windows Firewall rules, URL ACL reservations, and HTTPS bindings.
- Automatic URL ACL and HTTPS certificate binding when run with administrative rights.
- Parameters for port, endpoint path, scheme, and certificate control.
- Graceful handling when optional Windows features (BitLocker, Secure Boot, Hyper-V) are unavailable.

## Prerequisites
- Windows 10 or newer (Server 2016+ recommended).
- PowerShell 5.1 or PowerShell 7+.
- Account running the script must have permissions to query WMI (WinRM/COM) and, if Basic auth is used, must contact Active Directory.
- For HTTPS: a certificate installed in `Cert:\LocalMachine\My` and a matching HTTP.SYS SSL binding, or run the script elevated with `-AutoConfigureHttps` to create one automatically.

## Usage
```powershell
# Basic run (HTTP)
.\InventoryAPI.ps1 -Scheme http -Port 8080

# HTTPS with automatic certificate provisioning (requires elevation)
.\InventoryAPI.ps1 -Scheme https -Port 8443 -AutoConfigureHttps -EnableDebug

# HTTPS using an existing certificate
.\InventoryAPI.ps1 -Scheme https -Port 8443 -CertificateThumbprint '<thumbprint>'
```

### Parameters
| Name | Description |
| --- | --- |
| `-Scheme` | `http` or `https`. Defaults to `https`. |
| `-Port` | Listener port. Defaults to `8443`. |
| `-Endpoint` | Endpoint path (without slashes). Defaults to `inventory`. |
| `-EnableDebug` | Emit additional console logging. |
| `-AutoConfigureHttps` | When scheme is HTTPS, automatically create a self-signed cert and bind it (requires admin). |
| `-CertificateThumbprint` | Thumbprint of an existing cert in `Cert:\LocalMachine\My` to use for the HTTPS binding. |
| `-CertificateDnsName` | DNS name to embed in an auto-created cert; defaults to `HOSTNAME` or `HOSTNAME.domain`. |

## HTTPS Preparation (manual)
1. Install or create a certificate in `LocalMachine\My` and note the thumbprint.
2. Reserve the URL ACL for the service account:
   ```powershell
   netsh http add urlacl url=https://+:8443/inventory/ user=DOMAIN\svcInventory
   ```
3. Bind the certificate to the port:
   ```powershell
   netsh http add sslcert ipport=0.0.0.0:8443 certhash=<thumbprint> certstore=MY appid={<guid>}
   ```
4. Confirm an inbound firewall allow rule exists for the chosen TCP port.

If you run the script elevated with `-AutoConfigureHttps`, steps 2-3 are handled automatically (a new GUID is generated per run and the cert is created if missing).

## Running as a Windows Service (PowerShell 5.1)
1. Copy the script to a stable path, e.g. `C:\ProgramData\InventoryAPI\InventoryAPI.ps1`.
2. Create or choose a service account (domain or local) with:
   - Log on as a service right.
   - WMI access to the machine.
   - HTTP.SYS URL ACL and SSL binding ownership for the chosen prefix.
3. From an elevated PowerShell:
   ```powershell
   $cmd = 'powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass ' +
          '-File "C:\ProgramData\InventoryAPI\InventoryAPI.ps1" -Scheme https -Port 8443'
   New-Service -Name InventoryAPI -DisplayName 'Inventory API' -Description 'Hosts the Inventory API endpoint.' \
               -BinaryPathName $cmd -Credential "DOMAIN\svcInventory" -StartupType Automatic
   sc.exe failure InventoryAPI reset=0 actions=restart/60000
   Start-Service InventoryAPI
   ```
4. To update configuration, stop the service, edit the command line with `sc.exe config`, or replace the script and restart the service.

## Signing the Script
1. Obtain or create a code-signing certificate (for test environments: `New-SelfSignedCertificate -Subject "CN=InventoryAPI Signing" -Type CodeSigningCert`).
2. Sign the script:
   ```powershell
   $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object Subject -eq 'CN=InventoryAPI Signing' | Select-Object -First 1
   Set-AuthenticodeSignature -FilePath C:\ProgramData\InventoryAPI\InventoryAPI.ps1 -Certificate $cert
   ```
3. Verify with `Get-AuthenticodeSignature` and distribute the certificate to trusted stores as needed.

## Inventory Schema
The API responds with JSON similar to:
```json
{
  "schemaVersion": "1.0",
  "computer": { "hostname": "HOST", "domain": "contoso.local", "fqdn": "HOST.contoso.local" },
  "os": { "name": "Microsoft Windows 11", "version": "10.0.22631", "build": "22631", "installDate": "2025-02-10T20:49:23.0000000Z", "hotfixes": ["KB5030219"] },
  "hardware": { "manufacturer": "Dell Inc.", "model": "Precision 5570", ... },
  "disks": [ { "deviceId": "C:", "filesystem": "NTFS", ... } ],
  "nics": [ { "name": "Intel(R) Ethernet", "mac": "00-11-22-33-44-55" } ],
  "virtualization": { "isHyperVHost": false, "isVm": true, "vmVendor": "VMware, Inc." },
  "security": { "joinType": "Domain", "secureBoot": true, "bitlockerVolumes": ["C:"] },
  "timestamp": "2025-02-10T21:05:00.1234567Z"
}
```
Optional fields (`secureBoot`, `bitlockerVolumes`, etc.) may be `null` or empty when the underlying subsystem is unavailable on the host.

## Troubleshooting
- **401 Unauthorized:** verify credentials, AD reachability, and ensure the service account can validate Basic auth.
- **Listener fails to start:** the script emits explicit messages if WMI access, firewall rules, URL ACL, or SSL bindings are missing.
- **HTTPS handshake errors:** confirm clients trust the certificate or use `-AutoConfigureHttps` to generate a self-signed cert for testing; import the cert on the client if necessary.
- **Cmdlet not supported on this platform:** optional collectors (Secure Boot, BitLocker, Hyper-V) are skipped automatically, but check debug logs for context.

## License & Disclaimer
This project is licensed under the MIT License (see `LICENSE`). The software is provided "AS IS", without warranty of any kind—use at your own risk.
