# ==============================================================================
# launch_headless_framework.ps1
# Native Windows PowerShell Master Orchestration Script for Local Telemetry Sandbox
# ==============================================================================

[CmdletBinding()]
param (
    [string]$AvdName = "",
    [int]$ProxyPort = 8080
)

$ErrorActionPreference = "Stop"
$WorkspaceDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$HostProxyAlias = "10.0.2.2"
$LogDir = Join-Path $WorkspaceDir "logs"
$TraceLogFile = Join-Path $LogDir "diagnostic_traces.log"
$TelemetryLogFile = Join-Path $WorkspaceDir "telemetry_audit.jsonl"
$AddonScript = Join-Path $WorkspaceDir "meta_dynamic_scanner.py"

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

function Write-Info($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Success($msg) { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err($msg) { Write-Host "[-] $msg" -ForegroundColor Red; exit 1 }

# Step 1: Validate Prerequisites
Write-Info "Step 1: Validating local software prerequisites..."

# Auto-detect Android SDK paths on Windows if not already in PATH
$sdkPlatformTools = "$env:LOCALAPPDATA\Android\Sdk\platform-tools"
$sdkEmulator = "$env:LOCALAPPDATA\Android\Sdk\emulator"
if (Test-Path $sdkPlatformTools) {
    if ($env:PATH -notlike "*$sdkPlatformTools*") {
        $env:PATH = "$sdkPlatformTools;$env:PATH"
    }
}
if (Test-Path $sdkEmulator) {
    if ($env:PATH -notlike "*$sdkEmulator*") {
        $env:PATH = "$sdkEmulator;$env:PATH"
    }
}

if (-not (Get-Command "python" -ErrorAction SilentlyContinue)) { Write-Err "Python not found in PATH." }
if (-not (Get-Command "mitmdump" -ErrorAction SilentlyContinue)) { Write-Err "mitmdump not found. Please run 'pip install mitmproxy'." }
if (-not (Get-Command "adb" -ErrorAction SilentlyContinue)) { Write-Err "adb not found in PATH." }
if (-not (Get-Command "emulator" -ErrorAction SilentlyContinue)) { Write-Err "Android emulator binary not found in PATH." }
if (-not (Test-Path $AddonScript)) { Write-Err "Addon script '$AddonScript' not found." }
Write-Success "Prerequisites validated."

# Step 2: Target AVD Selection
Write-Info "Step 2: Detecting target Android Virtual Device (AVD)..."
if ([string]::IsNullOrWhiteSpace($AvdName)) {
    $avds = emulator -list-avds
    if (-not $avds) {
        Write-Err "No AVD found. Create an AVD using Android Studio or avdmanager."
    }
    $AvdName = @($avds)[0].ToString().Trim()
    Write-Info "Auto-selected default AVD: '$AvdName'"
}

# Step 3: Launch Headless Sandbox
Write-Info "Step 3: Launching headless emulator: emulator -avd $AvdName -no-window -no-audio"
$emulatorProc = Start-Process -FilePath "emulator" -ArgumentList "-avd `"$AvdName`" -no-window -no-audio -no-boot-anim -gpu swiftshader_indirect" -PassThru -NoNewWindow

try {
    Write-Info "Awaiting ADB device authorization and connection..."
    adb wait-for-device

    Write-Info "Awaiting sys.boot_completed signal..."
    $bootCompleted = $false
    for ($i = 0; $i -lt 60; $i++) {
        $rawStatus = (adb shell getprop sys.boot_completed 2>$null)
        $status = if ($rawStatus) { @($rawStatus)[-1].ToString().Trim() } else { "" }
        if ($status -eq "1") {
            $bootCompleted = $true
            break
        }
        Start-Sleep -Seconds 2
    }

    if (-not $bootCompleted) {
        Write-Err "Timeout waiting for emulator boot."
    }
    Write-Success "Emulator sandbox is fully operational."

    # Step 4: Configure Proxy Routing
    Write-Info "Step 4: Updating device proxy routing to ${HostProxyAlias}:${ProxyPort}..."
    adb shell settings put global http_proxy "${HostProxyAlias}:${ProxyPort}"
    $rawProxy = (adb shell settings get global http_proxy 2>$null)
    $verifiedProxy = if ($rawProxy) { @($rawProxy)[-1].ToString().Trim() } else { "" }
    Write-Success "Device proxy verified: $verifiedProxy"

    # Step 5: Start Mitmdump Telemetry
    Write-Info "Step 5: Launching mitmdump telemetry monitor..."
    Write-Info "Trace logs destination: $TraceLogFile"
    Write-Info "Structured audit destination: $TelemetryLogFile"

    $env:TELEMETRY_LOG_FILE = $TelemetryLogFile
    mitmdump -s $AddonScript -p $ProxyPort --set block_global=false | Tee-Object -FilePath $TraceLogFile
}
finally {
    Write-Warn "Teardown triggered. Resetting proxy routing..."
    adb shell settings put global http_proxy :0
    if ($emulatorProc -and -not $emulatorProc.HasExited) {
        Write-Info "Stopping headless emulator..."
        Stop-Process -Id $emulatorProc.Id -Force -ErrorAction SilentlyContinue
    }
    Write-Success "Teardown complete."
}
