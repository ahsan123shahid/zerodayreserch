# ADB & Frida Troubleshooting and Setup Guide

## 1. ADB Not Recognized Fix

### Root Cause
Android SDK's `platform-tools` directory was not present in the system environment `Path` variable.

### Solution Applied
Added `C:\Users\ahsan\AppData\Local\Android\Sdk\platform-tools` to the Windows User `Path`.

To verify in PowerShell:
```powershell
adb devices
```

---

## 2. Frida "need Gadget to attach on jailed Android" Fix

### Root Cause
When running `run_injector.py`, Frida reported:
```text
[-] Critical Instrumentation Failure: need Gadget to attach on jailed Android; its default location is: C:\Users\ahsan\AppData\Local\Microsoft\Windows\INetCache\frida\gadget-android-arm64.so
```
1. The emulator was launched using a **Google Play** production system image (`ro.debuggable=0`). Production builds do not permit running `adbd` as root (`adb root` outputs `adbd cannot run as root in production builds`).
2. Without root privileges, `frida-server` cannot run on the device, causing Frida to treat the environment as "jailed" (non-rooted) and look for `frida-gadget`.

---

### Solution 1: Use a Rootable Emulator (Google APIs Image) — Recommended

1. Open **Android Studio** -> **Virtual Device Manager**.
2. Click **Create Device**.
3. Under System Image, choose an image with **Google APIs** (without the Play Store icon).
4. Start the emulator and run:
   ```powershell
   adb root
   ```
5. Push the matching `frida-server` (version `17.22.2` for `x86_64`) to the device:
   ```powershell
   adb push frida-server-17.22.2-android-x86_64 /data/local/tmp/frida-server
   adb shell "chmod 755 /data/local/tmp/frida-server"
   adb shell "/data/local/tmp/frida-server &"
   ```
6. Run the script:
   ```powershell
   python .\run_injector.py
   ```

---

### Solution 2: Patch Target APK with Frida Gadget (For Non-Rooted / Production AVDs)

For unrooted environments, embed `frida-gadget` directly into the APK:
1. Download `frida-gadget-17.22.2-android-x86_64.so.xz` or `arm64` matching your architecture from the [Frida Releases page](https://github.com/frida/frida/releases/tag/17.22.2).
2. Decompress and copy the gadget library into Frida's cache directory:
   ```text
   C:\Users\ahsan\AppData\Local\Microsoft\Windows\INetCache\frida\gadget-android-arm64.so
   ```
3. Use `objection patchapk --source app.apk` to inject the gadget library into the target application before installing it.
