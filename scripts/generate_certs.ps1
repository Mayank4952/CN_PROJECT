# PowerShell PKI Certificate Generator for Secure VPN - Group 15
param(
    [string]$OutDir = "certs",
    [string]$ServerSAN = "127.0.0.1,localhost",
    [int]$Days = 365
)

Write-Host "=== Generating Secure VPN Certificates (Group 15) ===" -ForegroundColor Cyan
python cert_gen.py --out-dir $OutDir --server-san $ServerSAN --days $Days

if ($LASTEXITCODE -eq 0) {
    Write-Host "Certificates generated successfully in $OutDir!" -ForegroundColor Green
} else {
    Write-Host "Failed to generate certificates. Check OpenSSL installation." -ForegroundColor Red
}
