# Production Telemetry & Compliance Auditing Workspace

This repository provides an automated local debugging and telemetry verification environment built to validate system state compliance, detect unmasked private identifiers, and audit multi-platform microservice interactions.

---

## 1. Architectural Overview

```
                      +---------------------------------------+
                      |       Headless Android Sandbox        |
                      |  (emulator -no-window -no-audio)      |
                      +-------------------+-------------------+
                                          |
                        HTTP/HTTPS Proxy (10.0.2.2:8080)
                                          v
                      +---------------------------------------+
                      |               mitmproxy               |
                      |         (mitmdump + TLS Engine)       |
                      +-------------------+-------------------+
                                          |
                            Addon Pipeline Hooks
                                          v
                    +-------------------------------------------+
                    |         meta_dynamic_scanner.py           |
                    |  * Data Masking & GraphQL Schema Auditor  |
                    |  * Distributed State Sync Latency Auditor |
                    |  * Conversational Context Boundary Check  |
                    |  * Federated Identity Interoperability    |
                    |  * Session & Anti-Forgery CSRF Tracker    |
                    +---------------------+---------------------+
                                          |
                +-------------------------+-------------------------+
                v                                                   v
    [ logs/diagnostic_traces.log ]                        [ telemetry_audit.jsonl ]
```

---

## 2. Component Inspection & Boundary Audit Layers

The telemetry engine (`meta_dynamic_scanner.py`) asynchronously parses real-time HTTP/HTTPS and GraphQL request/response bodies across four key defensive auditing domains:

### A. Dynamic Data-Masking & PII Verification
- **Recursive Schema Traversal:** Traverses deeply nested JSON, serialized JSON-strings within objects, and GraphQL multi-level responses (`data` / `errors`).
- **Explicit Identifier Auditing:** Evaluates traffic for explicit target identifier strings (e.g., `malik_iqra04`) and sensitive keys (`session_state`, `destination_addr`, `auth_token`, `user_id`, `email`, `ssn`).
- **Obfuscation Compliance:** Checks whether values contain valid character masking markers (e.g., `***`, `[MASKED]`, `[REDACTED]`). Any cleartext exposure of sensitive values triggers a `CRITICAL` or `HIGH` compliance alert.

### B. Distributed State Synchronization Latency
- **Boundary Objective:** Detects desynchronization gaps between separate database nodes handling user access control properties.
- **Markers Evaluated:**
  - `X-Replication-Lag-Ms`: Flags nodes exceeding safe replication thresholds (>1500ms).
  - `X-Node-ID` / `X-Cluster-Node` / `X-DB-Replica`: Maps response node identity.
  - `X-State-Version` / `ETag`: Flags state-modifying requests on access control endpoints that lack deterministic versioning or etags.

### C. Conversational Assistant Context Boundaries
- **Boundary Objective:** Monitors automated query assistants and LLM agents to ensure responses do not leak underlying configuration structures or metadata when handling non-standard contextual patterns.
- **Audit Rules:**
  - **System Prompt Disclosure:** Flags leakage of internal system instructions (e.g., `system_prompt`, `core_directive`).
  - **Internal Schema Disclosure:** Detects exposure of backend vector collection IDs, embedding dimensions, or database schemas.
  - **Backend Stack Trace Exposure:** Alerts on runtime tracebacks, exception dumps, or internal gateway configurations.

### D. Federated Identity Interoperability Paths
- **Boundary Objective:** Validates data schema integrity and checks parameter reflection during multi-platform callback transactions.
- **Audit Rules:**
  - **Parameter Reflection:** Checks if critical identity parameters (`redirect_uri`, `state`, `client_id`, `nonce`) are reflected unencoded in callback bodies.
  - **State Validation:** Flags OAuth2/OIDC callback transactions that omit the anti-forgery `state` parameter.

### E. Session Validation & Cross-Site Mitigation Tracking
- **Anti-Forgery CSRF Tokens:** Verifies state-changing HTTP operations (`POST`, `PUT`, `PATCH`, `DELETE`) with authenticated sessions carry defensive headers (`X-CSRF-Token`, `X-XSRF-Token`).
- **Defensive Cookie Flags:** Validates that session cookies enforce `SameSite`, `HttpOnly`, and `Secure` attributes.

### F. Pre-Authentication Information Disclosure Auditing
- **Boundary Objective:** Verifies whether the backend server leaks raw user identifiers (`user_id`, `uid`, `account_id`, `pk`) or profile creation timestamps (`created_at`, `creation_timestamp`, `registered_on`) in clear text inside JSON response blocks before any authentication layer is established.
- **Audit Rules:**
  - Evaluates HTTP flows lacking `Authorization` headers and authenticated session cookies (`sessionid`, `jwt`, `token`, etc.).
  - Recursively flags clear-text occurrences of internal account identifiers or profile creation timestamps in public endpoints (e.g., username checks, lookup APIs, pre-registration validators).
  - Emits `Pre_Auth_Raw_Identifier_Leak` (`HIGH`) and `Pre_Auth_Creation_Timestamp_Leak` (`MEDIUM`) to CLI and structured audit logs.

---

## 3. Workspace Setup & Prerequisites

### Prerequisites
1. **Python 3.9+**
2. **mitmproxy** (`mitmdump` must be in system `PATH`)
3. **Android SDK Command-Line Tools** (`adb` and `emulator` must be in system `PATH`)

### Quick Install
Install python dependencies:
```bash
pip install -r requirements.txt
```

---

## 4. TLS Decryption Certificate Setup & Interception Verification

To inspect HTTPS and GraphQL payloads securely from the Android sandbox, the local mitmproxy Root CA certificate must be trusted by the testing environment.

### Step 1: Locate or Generate the Root CA
Run `mitmdump` once to automatically initialize certificates in `~/.mitmproxy/` (or `%USERPROFILE%\.mitmproxy` on Windows):
- `mitmproxy-ca-cert.pem` (PEM format)
- `mitmproxy-ca-cert.cer` (DER format)

### Step 2: Install Certificate into Android Sandbox

#### Method A: Development Build with Network Security Config (Recommended for Apps)
In your application under test, add a `res/xml/network_security_config.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
```
Reference it in `AndroidManifest.xml` under `<application android:networkSecurityConfig="@xml/network_security_config">`.
Then install the certificate on the device:
```bash
adb push ~/.mitmproxy/mitmproxy-ca-cert.cer /sdcard/
adb shell am start -a "android.credentials.INSTALL" -d "file:///sdcard/mitmproxy-ca-cert.cer"
```

#### Method B: Rooted / Writable Emulator (System Store)
Calculate certificate hash:
```bash
HASH=$(openssl x509 -inform PEM -subject_hash_old -in ~/.mitmproxy/mitmproxy-ca-cert.pem | head -1)
cp ~/.mitmproxy/mitmproxy-ca-cert.pem "${HASH}.0"

# Remount emulator as writable
adb root
adb remount
adb push "${HASH}.0" /system/etc/security/cacerts/
adb shell chmod 644 "/system/etc/security/cacerts/${HASH}.0"
adb reboot
```

### Step 3: Verification Matrix
Verify that TLS interception is operational:
1. Open the sandbox browser or issue a test request:
   ```bash
   adb shell curl -k -x 10.0.2.2:8080 http://mitm.it
   ```
2. Navigate to `http://mitm.it` within the device to view the mitmproxy certificate status page.
3. Check `logs/diagnostic_traces.log` to confirm that HTTP/HTTPS flows are being processed and decrypted.

---

## 5. Execution Guide

### Automated Execution (Linux / WSL / Git Bash)
Run the master orchestration script:
```bash
chmod +x launch_headless_framework.sh
./launch_headless_framework.sh [optional_avd_name]
```

### Automated Execution (Native Windows PowerShell)
Run the PowerShell orchestration script:
```powershell
.\launch_headless_framework.ps1 -AvdName "Pixel_API_34" -ProxyPort 8080
```

### Manual Execution (Without Sandbox Container)
You can run the telemetry addon standalone for proxying any local service or browser:
```bash
mitmdump -s meta_dynamic_scanner.py -p 8080 --set block_global=false
```

---

## 6. Telemetry Log Output Structure

Findings are logged in real-time to `telemetry_audit.jsonl` using JSON Lines:

```json
{
  "timestamp": "2026-10-05T07:15:20.124501Z",
  "boundary_layer": "Data Masking Compliance",
  "severity": "CRITICAL",
  "flow_id": "8f8b042b-58f2-4e4b-9721-a5d2eb6a58bc",
  "method": "GET",
  "url": "https://api.internal.service/v1/user/account",
  "finding_type": "Target_Identifier_Unmasked",
  "description": "Field 'username' at path '$.data.account.username' violates data obfuscation policy.",
  "matched_key": "username",
  "sample_evidence": "Explicit identifier 'malik_iqra04' detected without masking: 'malik_iqra0...'",
  "metadata": {
    "path": "$.data.account.username"
  }
}
```
