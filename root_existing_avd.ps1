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

Write-Host "[*] Checking ADB devices..."
$deviceList = adb devices | Where-Object { $_ -match "\tdevice" }
if (-not $deviceList) {
    Write-Host "[*] Starting 'Medium_Phone' emulator..."
    $emuProcess = Start-Process -FilePath "$sdkEmulator\emulator.exe" -ArgumentList "-avd", "Medium_Phone", "-no-window", "-no-audio", "-no-boot-anim", "-gpu", "swiftshader_indirect" -PassThru
    Write-Host "[*] Waiting for emulator to complete boot (PID $($emuProcess.Id))..."
    
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
        Write-Host "    Boot progress: $elapsed s..."
    }
    if (-not $booted) {
        Write-Host "[-] Timeout waiting for emulator boot." -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] Emulator booted successfully!" -ForegroundColor Green
}

# Run rootAVD against the Medium_Phone ramdisk
$rootAvdDir = "d:\zerodayreserch\rootAVD-master"
$ramdiskRel = "system-images\android-37.1\google_apis_playstore_ps16k\x86_64\ramdisk.img"

Write-Host "[*] Running rootAVD to patch ramdisk with Magisk..."
Push-Location $rootAvdDir
try {
    # Run rootAVD.bat
    cmd.exe /c "rootAVD.bat $ramdiskRel"
} finally {
    Pop-Location
}

Write-Host "[*] Rooting patch finished. Rebooting emulator to apply rooted ramdisk..."
adb reboot
Write-Host "[*] Waiting for reboot..."
Start-Sleep -Seconds 15
adb wait-for-device

$rebooted = $false
$elapsed = 0
while (-not $rebooted -and $elapsed -lt 90) {
    Start-Sleep -Seconds 3
    $elapsed += 3
    try {
        $status = (adb shell getprop sys.boot_completed 2>$null).Trim()
        if ($status -eq "1") {
            $rebooted = $true
        }
    } catch {}
}

Write-Host "[*] Checking root access..."
$rootId = adb shell "su -c id" 2>$null
Write-Host "su check output: $rootId"

if ($rootId -match "uid=0\(root\)") {
    Write-Host "[+] SUCCESS: Emulator is now fully ROOTED (uid=0) via Magisk!" -ForegroundColor Green
} else {
    Write-Host "[!] Root check completed. Status: $rootId"
}
