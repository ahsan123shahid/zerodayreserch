$ErrorActionPreference = "Stop"

# Auto-detect Android SDK paths
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

# 1. Download Frida server binary for x86_64
$fridaVer = (python -c "import frida; print(frida.__version__)").Trim()
Write-Host "[*] Frida version: $fridaVer"

$assetName = "frida-server-$fridaVer-android-x86_64.xz"
$targetBinary = "frida-server-$fridaVer-android-x86_64"
$url = "https://github.com/frida/frida/releases/download/$fridaVer/$assetName"

$xzPath = Join-Path $PSScriptRoot $assetName
$binPath = Join-Path $PSScriptRoot $targetBinary

if (-not (Test-Path $binPath)) {
    if (-not (Test-Path $xzPath)) {
        Write-Host "[*] Downloading Frida Server ($url)..."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $xzPath -UseBasicParsing
    }
    Write-Host "[*] Extracting $assetName..."
    $extractPy = Join-Path $PSScriptRoot "extract_xz.py"
    @"
import lzma, shutil, sys
with lzma.open(sys.argv[1], 'rb') as f_in, open(sys.argv[2], 'wb') as f_out:
    shutil.copyfileobj(f_in, f_out)
"@ | Set-Content -Path $extractPy -Encoding UTF8
    python $extractPy $xzPath $binPath
    Remove-Item $extractPy -Force
}
Write-Host "[+] Frida server binary ready at $binPath"

# 2. Check if emulator is running, start if needed
$deviceList = adb devices | Where-Object { $_ -match "\tdevice" }
if (-not $deviceList) {
    Write-Host "[*] No emulator currently running. Starting 'Medium_Phone' headless..."
    $emuProcess = Start-Process -FilePath "$sdkEmulator\emulator.exe" -ArgumentList "-avd", "Medium_Phone", "-no-window", "-no-audio", "-no-boot-anim", "-gpu", "swiftshader_indirect" -PassThru
    Write-Host "[*] Emulator process started (PID $($emuProcess.Id)). Waiting for boot to finish..."
    
    $booted = $false
    $timeout = 120
    $elapsed = 0
    while (-not $booted -and $elapsed -lt $timeout) {
        Start-Sleep -Seconds 3
        $elapsed += 3
        try {
            $status = (adb shell getprop sys.boot_completed 2>$null).Trim()
            if ($status -eq "1") {
                $booted = $true
            }
        } catch {}
        Write-Host "    Waiting for boot... ($elapsed s)"
    }
    if (-not $booted) {
        Write-Host "[-] Timeout waiting for emulator to boot." -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] Emulator successfully booted!" -ForegroundColor Green
}

# 3. Inject Frida Server
Write-Host "[*] Injecting Frida server into emulator..."
adb root
Start-Sleep -Seconds 1
adb push $binPath /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"

# 4. Start Frida Server
Write-Host "[*] Launching frida-server daemon..."
adb shell "pkill -9 frida-server" 2>$null
adb shell "/data/local/tmp/frida-server &"
Start-Sleep -Seconds 3

# 5. Verify Frida communication
Write-Host "[*] Verifying Frida connection via frida-ps -U..."
frida-ps -U
Write-Host "`n[+] Frida Server is running and successfully communicating with your host!" -ForegroundColor Green
