# ==============================================================================
# install_cert_to_emulator.ps1
# Automates mitmproxy CA Certificate installation into Android System Store
# ==============================================================================

[CmdletBinding()]
param (
    [string]$AdbPath = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"
)

$ErrorActionPreference = "Stop"

function Write-Info($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Success($msg) { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err($msg) { Write-Host "[-] $msg" -ForegroundColor Red }

# 1. Check ADB
if (-not (Test-Path $AdbPath)) {
    if (Get-Command "adb" -ErrorAction SilentlyContinue) {
        $AdbPath = (Get-Command "adb").Source
    } else {
        Write-Err "adb.exe not found at $AdbPath. Please verify Android SDK installation."
        exit 1
    }
}
Write-Success "Found ADB: $AdbPath"

# 2. Check Device Connection
$devices = & $AdbPath devices | Select-String -Pattern "device$"
if (-not $devices) {
    Write-Warn "No running Android emulator detected. Make sure your emulator is running with '-writable-system'."
    Write-Info "Run: emulator -avd <Your_AVD_Name> -writable-system -no-snapshot"
    exit 1
}

# 3. Locate or Generate mitmproxy CA certificate
$certDir = "$env:USERPROFILE\.mitmproxy"
$pemPath = Join-Path $certDir "mitmproxy-ca-cert.pem"

if (-not (Test-Path $pemPath)) {
    Write-Info "mitmproxy CA cert not found. Launching mitmdump briefly to generate it..."
    if (Get-Command "mitmdump" -ErrorAction SilentlyContinue) {
        $p = Start-Process "mitmdump" -ArgumentList "-p 8080" -PassThru -NoNewWindow
        Start-Sleep -Seconds 3
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    } else {
        Write-Err "mitmdump not found. Run 'pip install mitmproxy' or generate cert first."
        exit 1
    }
}

if (-not (Test-Path $pemPath)) {
    Write-Err "Could not find $pemPath"
    exit 1
}

Write-Success "Located mitmproxy certificate: $pemPath"

# 4. Hash determination (Standard mitmproxy subject_hash_old is c8750f0d)
$hash = "c8750f0d"
if (Get-Command "openssl" -ErrorAction SilentlyContinue) {
    $computedHash = (openssl x509 -inform PEM -subject_hash_old -in $pemPath | Select-Object -First 1).Trim()
    if ($computedHash) { $hash = $computedHash }
}
$targetFileName = "$hash.0"
Write-Info "Target Android system cert name: $targetFileName"

# 5. Push to System Store
Write-Info "Requesting adb root..."
& $AdbPath root
Start-Sleep -Seconds 2

Write-Info "Remounting system partitions as writable..."
& $AdbPath remount

# Push to temporary directory first
Write-Info "Pushing certificate to device temp directory..."
& $AdbPath push $pemPath "/data/local/tmp/$targetFileName"

# Move to system certs and fix permissions
Write-Info "Installing certificate into /system/etc/security/cacerts/..."
& $AdbPath shell "mv /data/local/tmp/$targetFileName /system/etc/security/cacerts/$targetFileName"
& $AdbPath shell "chmod 644 /system/etc/security/cacerts/$targetFileName"
& $AdbPath shell "chown root:root /system/etc/security/cacerts/$targetFileName"

# For Android 14+ APEX mount overlay fallback (if applicable)
& $AdbPath shell "if [ -d /apex/com.android.conscrypt/cacerts ]; then mount -o bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts 2>/dev/null; fi"

Write-Success "Certificate installed successfully as /system/etc/security/cacerts/$targetFileName"
Write-Info "Rebooting emulator to apply changes..."
& $AdbPath reboot
Write-Success "Done! Sandbox is rebooting with trusted system CA."
