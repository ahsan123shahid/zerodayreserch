#!/usr/bin/env bash
# ==============================================================================
# launch_headless_framework.sh
# Production-ready Master Orchestration Script for Local Telemetry & Compliance Sandbox
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Configuration & Paths
# ------------------------------------------------------------------------------
WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_PORT=8080
HOST_PROXY_ALIAS="10.0.2.2"  # Android Emulator's default routing alias to Host loopback
LOG_DIR="${WORKSPACE_DIR}/logs"
TRACE_LOG_FILE="${LOG_DIR}/diagnostic_traces.log"
TELEMETRY_LOG_FILE="${WORKSPACE_DIR}/telemetry_audit.jsonl"
ADDON_SCRIPT="${WORKSPACE_DIR}/meta_dynamic_scanner.py"

mkdir -p "${LOG_DIR}"

# ------------------------------------------------------------------------------
# Formatting Helpers
# ------------------------------------------------------------------------------
info()  { echo -e "\033[1;34m[*] $1\033[0m"; }
succ()  { echo -e "\033[1;32m[+] $1\033[0m"; }
warn()  { echo -e "\033[1;33m[!] $1\033[0m"; }
err()   { echo -e "\033[1;31m[-] $1\033[0m"; exit 1; }

# ------------------------------------------------------------------------------
# Cleanup Routine (Restores Device State on Interrupt/Exit)
# ------------------------------------------------------------------------------
cleanup() {
    warn "Received shutdown signal. Teardown underway..."
    
    info "Resetting Android device proxy settings..."
    adb shell settings put global http_proxy :0 2>/dev/null || true
    
    if [[ -n "${EMULATOR_PID:-}" ]] && kill -0 "${EMULATOR_PID}" 2>/dev/null; then
        info "Terminating background headless emulator (PID: ${EMULATOR_PID})..."
        kill "${EMULATOR_PID}" 2>/dev/null || true
    fi

    if [[ -n "${MITM_PID:-}" ]] && kill -0 "${MITM_PID}" 2>/dev/null; then
        info "Stopping mitmdump background process (PID: ${MITM_PID})..."
        kill "${MITM_PID}" 2>/dev/null || true
    fi

    succ "Environment cleaned. Diagnostics stored in ${TRACE_LOG_FILE}."
}
trap cleanup EXIT SIGINT SIGTERM

# ------------------------------------------------------------------------------
# Step 1: Validate Local Software Prerequisites
# ------------------------------------------------------------------------------
info "Step 1: Validating local software prerequisites..."

# Auto-detect Android SDK if running in Windows bash/WSL
if [[ -n "${LOCALAPPDATA:-}" ]]; then
    ANDROID_SDK_WIN="$(cygpath -u "$LOCALAPPDATA" 2>/dev/null || echo "$LOCALAPPDATA")/Android/Sdk"
    [[ -d "${ANDROID_SDK_WIN}/platform-tools" ]] && export PATH="${ANDROID_SDK_WIN}/platform-tools:$PATH"
    [[ -d "${ANDROID_SDK_WIN}/emulator" ]] && export PATH="${ANDROID_SDK_WIN}/emulator:$PATH"
fi

command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1 || err "Python is required but not installed."
command -v mitmdump >/dev/null 2>&1 || err "mitmdump is not found. Please install mitmproxy ('pip install mitmproxy')."
command -v adb >/dev/null 2>&1 || err "adb (Android Debug Bridge) is required in PATH."
command -v emulator >/dev/null 2>&1 || err "Android 'emulator' binary is required in PATH."

if [[ ! -f "${ADDON_SCRIPT}" ]]; then
    err "Required addon script '${ADDON_SCRIPT}' not found!"
fi

succ "All prerequisites confirmed (Python, mitmdump, adb, emulator)."

# ------------------------------------------------------------------------------
# Step 2: Select / Determine Android Virtual Device (AVD)
# ------------------------------------------------------------------------------
info "Step 2: Detecting target Android Virtual Device (AVD)..."

AVD_TARGET="${1:-${AVD_NAME:-}}"

if [[ -z "${AVD_TARGET}" ]]; then
    AVAILABLE_AVDS=($(emulator -list-avds))
    if [[ ${#AVAILABLE_AVDS[@]} -eq 0 ]]; then
        err "No Android Virtual Devices (AVDs) found. Create one using 'avdmanager create avd'."
    fi
    AVD_TARGET="${AVAILABLE_AVDS[0]}"
    info "No AVD explicitly specified; auto-selected default: '${AVD_TARGET}'"
fi

# ------------------------------------------------------------------------------
# Step 3: Spin Up Headless Testing Sandbox
# ------------------------------------------------------------------------------
info "Step 3: Launching headless testing sandbox: emulator -avd ${AVD_TARGET} -no-window -no-audio"

emulator -avd "${AVD_TARGET}" \
    -no-window \
    -no-audio \
    -no-boot-anim \
    -gpu swiftshader_indirect \
    > "${LOG_DIR}/emulator_stdout.log" 2>&1 &
EMULATOR_PID=$!

info "Sandbox launched (PID: ${EMULATOR_PID}). Awaiting device readiness..."
adb wait-for-device

info "Awaiting system boot completion..."
BOOT_COMPLETE=0
RETRIES=0
MAX_RETRIES=60

while [[ ${BOOT_COMPLETE} -ne 1 && ${RETRIES} -lt ${MAX_RETRIES} ]]; do
    BOOT_STATUS=$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
    if [[ "${BOOT_STATUS}" == "1" ]]; then
        BOOT_COMPLETE=1
        break
    fi
    sleep 2
    RETRIES=$((RETRIES + 1))
done

if [[ ${BOOT_COMPLETE} -ne 1 ]]; then
    err "Sandbox emulator timed out awaiting sys.boot_completed."
fi

succ "Headless sandbox is fully initialized and operational."

# ------------------------------------------------------------------------------
# Step 4: Update Local Device Proxy Routing Rules
# ------------------------------------------------------------------------------
info "Step 4: Configuring device proxy routing to ${HOST_PROXY_ALIAS}:${PROXY_PORT}..."

adb shell settings put global http_proxy "${HOST_PROXY_ALIAS}:${PROXY_PORT}"
VERIFIED_PROXY=$(adb shell settings get global http_proxy | tr -d '\r')

if [[ "${VERIFIED_PROXY}" == "${HOST_PROXY_ALIAS}:${PROXY_PORT}" ]]; then
    succ "Device proxy verified: ${VERIFIED_PROXY}"
else
    warn "Proxy setting returned unexpected value: '${VERIFIED_PROXY}'. Continuing..."
fi

# ------------------------------------------------------------------------------
# Step 5: Start Telemetry Engine & Pipe Diagnostic Trace Logs
# ------------------------------------------------------------------------------
info "Step 5: Launching mitmdump telemetry monitor on port ${PROXY_PORT}..."
info "Diagnostic traces piping into: ${TRACE_LOG_FILE}"
info "Structured compliance findings piping into: ${TELEMETRY_LOG_FILE}"

export TELEMETRY_LOG_FILE="${TELEMETRY_LOG_FILE}"

mitmdump \
    -s "${ADDON_SCRIPT}" \
    -p "${PROXY_PORT}" \
    --set block_global=false \
    2>&1 | tee -a "${TRACE_LOG_FILE}" &
MITM_PID=$!

succ "Telemetry framework active. Press Ctrl+C to initiate graceful teardown."

# Keep process alive until signaled
wait "${MITM_PID}"
