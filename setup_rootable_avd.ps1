$ErrorActionPreference = "Stop"

$sdkPath = "$env:LOCALAPPDATA\Android\Sdk"
$toolsDir = Join-Path $sdkPath "cmdline-tools"
$latestDir = Join-Path $toolsDir "latest"
$zipPath = Join-Path $sdkPath "commandlinetools-win.zip"

if (-not (Test-Path "$latestDir\bin\sdkmanager.bat")) {
    Write-Host "[*] Downloading Android SDK Command-line Tools..."
    New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null
    
    $url = "https://dl.google.com/android/repository/commandlinetools-win-11076708_latest.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
    
    Write-Host "[*] Extracting command-line tools..."
    $tempExtract = Join-Path $toolsDir "temp"
    Expand-Archive -Path $zipPath -DestinationPath $tempExtract -Force
    
    if (Test-Path $latestDir) { Remove-Item $latestDir -Recurse -Force }
    Move-Item -Path "$tempExtract\cmdline-tools" -Destination $latestDir -Force
    Remove-Item $tempExtract -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Command-line tools ready at $latestDir"
} else {
    Write-Host "[+] Command-line tools already installed."
}

# Setup Java and Android environment variables
$jbrPath = "C:\Program Files\Android\Android Studio\jbr"
$env:JAVA_HOME = $jbrPath
$env:PATH = "$jbrPath\bin;$latestDir\bin;$sdkPath\platform-tools;$sdkPath\emulator;$env:PATH"
$env:ANDROID_HOME = $sdkPath

$sdkManager = "$latestDir\bin\sdkmanager.bat"
$avdManager = "$latestDir\bin\avdmanager.bat"

# Accept licenses
Write-Host "[*] Accepting SDK licenses..."
cmd.exe /c "echo y | `"$sdkManager`" --licenses" 2>$null | Out-Null

# Download Google APIs system image (API 34, x86_64 - userdebug)
$imagePackage = "system-images;android-34;google_apis;x86_64"
Write-Host "[*] Downloading Google APIs System Image ($imagePackage)... This will take a few minutes."
cmd.exe /c "echo y | `"$sdkManager`" `"$imagePackage`""

# Create new AVD with the downloaded image
$avdName = "Rooted_Google_APIs_34"
Write-Host "[*] Creating AVD '$avdName'..."
cmd.exe /c "echo no | `"$avdManager`" create avd -n `"$avdName`" -k `"$imagePackage`" -d pixel_6 --force"

Write-Host "[+] AVD '$avdName' successfully created and ready for root!" -ForegroundColor Green
