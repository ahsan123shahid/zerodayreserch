"""
meta_dynamic_scanner.py
=======================
Automated Network Telemetry & Data Masking Compliance Monitor for mitmproxy.

Audits real-time network traffic across microservice boundary layers:
1. Distributed State Synchronization Latency (replication lag & node divergence)
2. Conversational Assistant Context Boundaries (prompt/schema leakage & stack disclosure)
3. Federated Identity Interoperability Paths (schema integrity & parameter reflection)
4. Dynamic Response Data Masking (unmasked PII & raw user identifier auditing)
"""

import asyncio
import json
import logging
import os
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

try:
    from mitmproxy import ctx, http
except ImportError:
    # Graceful fallback for unit testing and CI without mitmproxy binary
    class _MockLog:
        @staticmethod
        def info(msg: str) -> None: print(f"[MITM-INFO] {msg}")
        @staticmethod
        def warn(msg: str) -> None: print(f"[MITM-WARN] {msg}")
        @staticmethod
        def error(msg: str) -> None: print(f"[MITM-ERROR] {msg}")

    class _MockCtx:
        log = _MockLog()

    ctx = _MockCtx()
    class _MockHttp:
        class HTTPFlow:
            pass
    http = _MockHttp()



# ==============================================================================
# AUDIT TELEMETRY MODELS & CONFIGURATION
# ==============================================================================

@dataclass
class ComplianceFinding:
    timestamp: str
    boundary_layer: str
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    flow_id: str
    method: str
    url: str
    finding_type: str
    description: str
    matched_key: Optional[str] = None
    sample_evidence: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class TelemetryConfig:
    # Explicit target private identifiers to audit for unmasked exposure
    EXPLICIT_USER_IDENTIFIERS: Set[str] = {
        "malik_iqra04",
    }

    # Sensitive key patterns in nested JSON / GraphQL schemas
    SENSITIVE_KEY_PATTERNS: List[re.Pattern] = [
        re.compile(r"(?i)(user[_-]?id|username|user_identifier)"),
        re.compile(r"(?i)(email|e[_-]?mail)"),
        re.compile(r"(?i)(phone|mobile|cell[_-]?phone)"),
        re.compile(r"(?i)(ssn|social[_-]?security|tax[_-]?id)"),
        re.compile(r"(?i)(card[_-]?number|pan|credit[_-]?card|cvv)"),
        re.compile(r"(?i)(password|passcode|secret|api[_-]?key|auth[_-]?token|bearer)"),
        re.compile(r"(?i)(session[_-]?state|access[_-]?state|perm_bits)"),
        re.compile(r"(?i)(destination[_-]?addr|raw[_-]?dest|internal[_-]?ip)"),
    ]

    # Masking heuristic: Must contain asterisks or standard masking characters
    MASKING_REGEX: re.Pattern = re.compile(r"(\*{3,}|[xX]{3,}|•{3,}|\[REDACTED\]|\[MASKED\])")

    # Conversational assistant leakage patterns
    ASSISTANT_LEAK_PATTERNS: List[Tuple[str, re.Pattern]] = [
        ("System Prompt Disclosure", re.compile(r"(?i)(you are a helpful ai|system[_-]?prompt|model_instructions|core_directive)")),
        ("Internal Schema Disclosure", re.compile(r"(?i)(database_schema|vector_store_id|embedding_dim|faiss_index|pinecone_idx)")),
        ("Backend Traceback/Config", re.compile(r"(?i)(traceback \(most recent call last\)|exception in internal agent|llm_gateway_config)")),
    ]

    # Pre-Authentication sensitive inspection patterns
    PRE_AUTH_ID_PATTERNS: List[re.Pattern] = [
        re.compile(r"(?i)^(user[_-]?id|uid|account[_-]?id|internal[_-]?id|pk|fbid|owner[_-]?id|profile[_-]?id)$"),
    ]
    PRE_AUTH_TIMESTAMP_PATTERNS: List[re.Pattern] = [
        re.compile(r"(?i)^(created[_-]?at|creation[_-]?timestamp|registered[_-]?(on|at)|profile[_-]?created|signup[_-]?(time|timestamp|date)|joined[_-]?date)$"),
    ]
    AUTH_HEADER_NAMES: Set[str] = {
        "authorization", "proxy-authorization", "x-auth-token", "x-access-token", "x-session-token", "x-api-key"
    }

    # Endpoints associated with conversational agents
    ASSISTANT_ENDPOINTS: List[re.Pattern] = [
        re.compile(r"(?i)/(api/)?v\d+/(chat|completions|agent|assistant|conversation|dialogue)"),
        re.compile(r"(?i)/graphql.*(prompt|assistant|botQuery)"),
    ]

    # Federated Identity endpoints
    FEDERATED_ENDPOINTS: List[re.Pattern] = [
        re.compile(r"(?i)/(oauth|oidc|saml|sso|federation|idp)/"),
        re.compile(r"(?i)/(auth/callback|oauth2/token|userinfo|authorize)"),
    ]

    # CSRF & Session verification headers
    CSRF_HEADERS: List[str] = [
        "x-csrf-token",
        "x-xsrf-token",
        "csrf-token",
        "anti-forgery-token",
    ]

    SESSION_COOKIES: List[str] = [
        "sessionid",
        "session_token",
        "jsessionid",
        "phpsessid",
        "auth_token",
    ]

    LOG_FILE_PATH: str = os.getenv("TELEMETRY_LOG_FILE", "telemetry_audit.jsonl")


# ==============================================================================
# AUDITING ENGINES
# ==============================================================================

class DataMaskingAuditor:
    """
    Recursively inspects complex nested JSON and multi-layered GraphQL schemas
    to detect cleartext identifiers and unmasked private keys.
    """

    @staticmethod
    def is_properly_masked(value: str) -> bool:
        if not isinstance(value, str):
            return True
        # If masked string matches standard replacement patterns
        return bool(TelemetryConfig.MASKING_REGEX.search(value))

    def inspect_value(self, path: str, key: str, value: Any, findings: List[Dict[str, Any]]) -> None:
        if value is None:
            return

        str_val = str(value).strip()

        # 1. Direct Target Identifier Match (e.g., malik_iqra04)
        for target_id in TelemetryConfig.EXPLICIT_USER_IDENTIFIERS:
            if target_id.lower() in str_val.lower():
                # Check if it was masked
                if not self.is_properly_masked(str_val):
                    findings.append({
                        "type": "Target_Identifier_Unmasked",
                        "severity": "CRITICAL",
                        "path": path,
                        "key": key,
                        "evidence": f"Explicit identifier '{target_id}' detected without masking: '{str_val[:12]}...'",
                    })

        # 2. Sensitive Key Inspection without obfuscation
        for pattern in TelemetryConfig.SENSITIVE_KEY_PATTERNS:
            if pattern.search(key):
                if len(str_val) > 3 and not self.is_properly_masked(str_val):
                    findings.append({
                        "type": "Sensitive_Field_Cleartext",
                        "severity": "HIGH",
                        "path": path,
                        "key": key,
                        "evidence": f"Sensitive key '{key}' contains unmasked value: length {len(str_val)} chars.",
                    })
                break

    def traverse(self, data: Any, current_path: str = "$", findings: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        if findings is None:
            findings = []

        if isinstance(data, dict):
            for k, v in data.items():
                child_path = f"{current_path}.{k}"
                self.inspect_value(child_path, str(k), v, findings)
                self.traverse(v, child_path, findings)
        elif isinstance(data, list):
            for idx, item in enumerate(data):
                child_path = f"{current_path}[{idx}]"
                self.traverse(item, child_path, findings)
        elif isinstance(data, str):
            # Probe if string is a nested serialized JSON
            if (data.startswith("{") and data.endswith("}")) or (data.startswith("[") and data.endswith("]")):
                try:
                    nested_obj = json.loads(data)
                    self.traverse(nested_obj, f"{current_path}<json>", findings)
                except Exception:
                    pass

        return findings


class ArchitecturalBoundaryAuditor:
    """
    Inspects boundary transactions across:
    - Distributed State Synchronization Latency
    - Conversational Assistant Context Boundaries
    - Federated Identity Interoperability Paths
    """

    def audit_distributed_state_latency(self, flow: http.HTTPFlow) -> List[ComplianceFinding]:
        """Layer 1: Distributed State Synchronization Latency"""
        findings: List[ComplianceFinding] = []
        headers = flow.response.headers

        # Trace node identifiers & synchronization sequence markers
        node_id = headers.get("x-node-id") or headers.get("x-cluster-node") or headers.get("x-db-replica")
        state_version = headers.get("x-state-version") or headers.get("x-entity-version")
        sync_timestamp = headers.get("x-sync-timestamp") or headers.get("last-modified")
        replication_lag_ms = headers.get("x-replication-lag-ms")

        # Check for state synchronization latency markers
        if replication_lag_ms:
            try:
                lag = float(replication_lag_ms)
                if lag > 1500.0:
                    findings.append(ComplianceFinding(
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        boundary_layer="Distributed State Synchronization Latency",
                        severity="MEDIUM",
                        flow_id=flow.id,
                        method=flow.request.method,
                        url=flow.request.pretty_url,
                        finding_type="High_Replication_Lag",
                        description=f"Node '{node_id or 'unknown'}' reports replication lag of {lag}ms across distributed state boundary.",
                        metadata={"node_id": node_id, "replication_lag_ms": lag, "state_version": state_version}
                    ))
            except ValueError:
                pass

        # Check for potential cache/node desynchronization gaps on state mutative endpoints
        if flow.request.method in ("PUT", "POST", "PATCH", "DELETE") and "access-control" in flow.request.path.lower():
            if not state_version and not headers.get("etag"):
                findings.append(ComplianceFinding(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    boundary_layer="Distributed State Synchronization Latency",
                    severity="LOW",
                    flow_id=flow.id,
                    method=flow.request.method,
                    url=flow.request.pretty_url,
                    finding_type="Missing_State_Versioning_Header",
                    description="Access control state modification lacks deterministic versioning header (x-state-version or ETag).",
                    metadata={"node_id": node_id}
                ))

        return findings

    def audit_assistant_context_boundary(self, flow: http.HTTPFlow, response_text: str) -> List[ComplianceFinding]:
        """Layer 2: Conversational Assistant Context Boundaries"""
        findings: List[ComplianceFinding] = []
        url = flow.request.pretty_url

        is_assistant_endpoint = any(pat.search(url) for pat in TelemetryConfig.ASSISTANT_ENDPOINTS)
        if not is_assistant_endpoint:
            return findings

        # Check for leakage of system prompts, internal metadata, or stack traces
        for label, pattern in TelemetryConfig.ASSISTANT_LEAK_PATTERNS:
            match = pattern.search(response_text)
            if match:
                snippet = response_text[max(0, match.start() - 20): min(len(response_text), match.end() + 40)]
                findings.append(ComplianceFinding(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    boundary_layer="Conversational Assistant Context Boundaries",
                    severity="HIGH",
                    flow_id=flow.id,
                    method=flow.request.method,
                    url=url,
                    finding_type="Context_Boundary_Breach",
                    description=f"Assistant response reflects internal structural metadata: {label}.",
                    sample_evidence=snippet.strip(),
                    metadata={"pattern": label}
                ))

        return findings

    def audit_federated_identity_paths(self, flow: http.HTTPFlow, response_text: str) -> List[ComplianceFinding]:
        """Layer 3: Federated Identity Interoperability Paths"""
        findings: List[ComplianceFinding] = []
        url = flow.request.pretty_url

        is_federated = any(pat.search(url) for pat in TelemetryConfig.FEDERATED_ENDPOINTS)
        if not is_federated:
            return findings

        # Parse request query params to check for parameter reflection
        parsed_req = urlparse(flow.request.url)
        query_params = parse_qs(parsed_req.query)

        # Audit schema integrity and check for raw parameter reflection (e.g. unencoded redirect_uri/state reflection)
        for param_key, param_values in query_params.items():
            if param_key.lower() in ("state", "redirect_uri", "nonce", "client_id"):
                for val in param_values:
                    if len(val) > 4 and val in response_text:
                        # Inspect context of reflection: is it in an unencoded HTML or JSON error block?
                        if f'"{val}"' not in response_text and f"'{val}'" not in response_text:
                            findings.append(ComplianceFinding(
                                timestamp=datetime.now(timezone.utc).isoformat(),
                                boundary_layer="Federated Identity Interoperability Paths",
                                severity="MEDIUM",
                                flow_id=flow.id,
                                method=flow.request.method,
                                url=url,
                                finding_type="Raw_Parameter_Reflection",
                                description=f"Federated parameter '{param_key}' is reflected raw in callback transaction body.",
                                sample_evidence=val[:24],
                                metadata={"param": param_key}
                            ))

        # Check for state parameter validation on callback
        if "callback" in url.lower() and "code=" in url.lower() and "state=" not in url.lower():
            findings.append(ComplianceFinding(
                timestamp=datetime.now(timezone.utc).isoformat(),
                boundary_layer="Federated Identity Interoperability Paths",
                severity="HIGH",
                flow_id=flow.id,
                method=flow.request.method,
                url=url,
                finding_type="Missing_OAuth_State_Validation",
                description="Federated identity callback omits cross-site state parameter validation.",
                metadata={}
            ))

        return findings


class SessionValidationTracker:
    """
    Monitors session lifecycle transitions, anti-forgery CSRF tokens, and security flags.
    """

    def inspect_session_state(self, flow: http.HTTPFlow) -> List[ComplianceFinding]:
        findings: List[ComplianceFinding] = []
        method = flow.request.method.upper()

        # Check state-changing requests for CSRF anti-forgery headers
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            has_csrf_header = any(h in flow.request.headers for h in TelemetryConfig.CSRF_HEADERS)
            has_session_cookie = any(c in flow.request.cookies for c in TelemetryConfig.SESSION_COOKIES)

            # If authenticated session present without CSRF protection header
            if has_session_cookie and not has_csrf_header:
                findings.append(ComplianceFinding(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    boundary_layer="Session Validation & Anti-Forgery",
                    severity="LOW",
                    flow_id=flow.id,
                    method=method,
                    url=flow.request.pretty_url,
                    finding_type="Missing_Anti_Forgery_Header",
                    description=f"State-modifying {method} request with active session cookies lacks standard anti-forgery CSRF headers.",
                    metadata={"cookies_present": list(flow.request.cookies.keys())}
                ))

        # Check response Set-Cookie attributes for defensive flags
        for cookie_name, cookie_val in flow.response.cookies.items():
            cookie_text = str(flow.response.headers.get_all("set-cookie"))
            if cookie_name.lower() in TelemetryConfig.SESSION_COOKIES:
                flags_missing = []
                if "samesite" not in cookie_text.lower():
                    flags_missing.append("SameSite")
                if "httponly" not in cookie_text.lower():
                    flags_missing.append("HttpOnly")
                if "secure" not in cookie_text.lower() and flow.request.scheme == "https":
                    flags_missing.append("Secure")

                if flags_missing:
                    findings.append(ComplianceFinding(
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        boundary_layer="Session Validation & Anti-Forgery",
                        severity="MEDIUM",
                        flow_id=flow.id,
                        method=method,
                        url=flow.request.pretty_url,
                        finding_type="Insecure_Cookie_Attributes",
                        description=f"Session cookie '{cookie_name}' is set without defensive security attributes: {', '.join(flags_missing)}.",
                        metadata={"missing_flags": flags_missing}
                    ))

        return findings


class PreAuthExposureAuditor:
    """
    Audits responses from unauthenticated endpoints to verify whether the backend
    leaks raw user_id, account identifiers, or profile creation timestamps in clear text
    inside JSON response blocks before any authentication layer is reached.
    """

    @staticmethod
    def is_unauthenticated_request(flow: http.HTTPFlow) -> bool:
        if not hasattr(flow, "request") or not flow.request:
            return False

        # 1. Check for standard authentication headers
        req_headers = {k.lower(): v for k, v in flow.request.headers.items()}
        for auth_h in TelemetryConfig.AUTH_HEADER_NAMES:
            if auth_h in req_headers:
                return False

        # 2. Check for active session cookies
        req_cookies = {k.lower() for k in flow.request.cookies.keys()}
        for session_c in TelemetryConfig.SESSION_COOKIES:
            if session_c in req_cookies:
                return False

        return True

    def audit(self, flow: http.HTTPFlow, parsed_json: Any) -> List[ComplianceFinding]:
        findings: List[ComplianceFinding] = []

        if not self.is_unauthenticated_request(flow):
            return findings

        def _traverse_pre_auth(data: Any, current_path: str = "$") -> None:
            if isinstance(data, dict):
                for k, v in data.items():
                    child_path = f"{current_path}.{k}"
                    if v is not None:
                        val_str = str(v).strip()
                        # Check for raw user_id / account_id exposure
                        for pat in TelemetryConfig.PRE_AUTH_ID_PATTERNS:
                            if pat.search(str(k)):
                                if len(val_str) > 0 and not TelemetryConfig.MASKING_REGEX.search(val_str):
                                    findings.append(ComplianceFinding(
                                        timestamp=datetime.now(timezone.utc).isoformat(),
                                        boundary_layer="Pre-Authentication Information Disclosure",
                                        severity="HIGH",
                                        flow_id=getattr(flow, "id", "flow_id"),
                                        method=flow.request.method,
                                        url=flow.request.pretty_url,
                                        finding_type="Pre_Auth_Raw_Identifier_Leak",
                                        description=f"Pre-authentication endpoint leaks raw user identifier key '{k}' without masking in JSON block.",
                                        matched_key=str(k),
                                        sample_evidence=f"{k}: '{val_str[:24]}'",
                                        metadata={"path": child_path, "pre_auth": True}
                                    ))
                                break

                        # Check for profile creation timestamp exposure
                        for pat in TelemetryConfig.PRE_AUTH_TIMESTAMP_PATTERNS:
                            if pat.search(str(k)):
                                if len(val_str) > 0 and not TelemetryConfig.MASKING_REGEX.search(val_str):
                                    findings.append(ComplianceFinding(
                                        timestamp=datetime.now(timezone.utc).isoformat(),
                                        boundary_layer="Pre-Authentication Information Disclosure",
                                        severity="MEDIUM",
                                        flow_id=getattr(flow, "id", "flow_id"),
                                        method=flow.request.method,
                                        url=flow.request.pretty_url,
                                        finding_type="Pre_Auth_Creation_Timestamp_Leak",
                                        description=f"Pre-authentication endpoint leaks profile creation timestamp key '{k}' in clear text.",
                                        matched_key=str(k),
                                        sample_evidence=f"{k}: '{val_str[:32]}'",
                                        metadata={"path": child_path, "pre_auth": True}
                                    ))
                                break

                    _traverse_pre_auth(v, child_path)
            elif isinstance(data, list):
                for idx, item in enumerate(data):
                    _traverse_pre_auth(item, f"{current_path}[{idx}]")

        _traverse_pre_auth(parsed_json)
        return findings


# ==============================================================================
# MASTER MITMPROXY TELEMETRY ADDON
# ==============================================================================

class TelemetryComplianceScanner:
    """
    Master Mitmproxy Addon executing real-time data compliance validation
    and architectural boundary inspection.
    """

    def __init__(self):
        self.masking_auditor = DataMaskingAuditor()
        self.boundary_auditor = ArchitecturalBoundaryAuditor()
        self.session_tracker = SessionValidationTracker()
        self.pre_auth_auditor = PreAuthExposureAuditor()
        self.log_file = TelemetryConfig.LOG_FILE_PATH
        self.total_flows_scanned = 0
        self.total_findings = 0
        self._ensure_log_initialized()

    def _ensure_log_initialized(self) -> None:
        if not os.path.exists(self.log_file):
            with open(self.log_file, "w", encoding="utf-8") as f:
                f.write(f"# Telemetry Compliance Monitor Audit Log Initialized: {datetime.now(timezone.utc).isoformat()}\n")

    def _write_finding(self, finding: ComplianceFinding) -> None:
        self.total_findings += 1
        finding_dict = asdict(finding)
        
        # Color-coded console logging via ctx.log
        color_map = {
            "CRITICAL": "[red][CRITICAL][/red]",
            "HIGH": "[light_red][HIGH][/light_red]",
            "MEDIUM": "[yellow][MEDIUM][/yellow]",
            "LOW": "[blue][LOW][/blue]",
            "INFO": "[green][INFO][/green]"
        }
        tag = color_map.get(finding.severity, f"[{finding.severity}]")
        ctx.log.warn(f"[{finding.boundary_layer}] {tag} {finding.finding_type}: {finding.description} (URL: {finding.url})")

        # Append structured JSONL entry
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(finding_dict) + "\n")
        except Exception as e:
            ctx.log.error(f"Failed to record telemetry finding: {e}")

    def load(self, loader):
        ctx.log.info("=" * 68)
        ctx.log.info("  META DYNAMIC SCANNER: Telemetry Compliance Engine Online")
        ctx.log.info(f"  Target Identifiers Tracked: {list(TelemetryConfig.EXPLICIT_USER_IDENTIFIERS)}")
        ctx.log.info(f"  Structured Log Target: {self.log_file}")
        ctx.log.info("=" * 68)

    async def response(self, flow: http.HTTPFlow) -> None:
        """
        Asynchronously inspects the completed HTTP response flow.
        """
        self.total_flows_scanned += 1
        findings: List[ComplianceFinding] = []

        # 1. Inspect Session & CSRF State Transitions
        findings.extend(self.session_tracker.inspect_session_state(flow))

        # 2. Inspect Distributed State Synchronization Latency
        findings.extend(self.boundary_auditor.audit_distributed_state_latency(flow))

        # Extract response text content safely
        content_type = flow.response.headers.get("content-type", "").lower()
        response_text = ""
        if flow.response.content:
            try:
                response_text = flow.response.get_text()
            except Exception:
                pass

        if response_text:
            # 3. Conversational Assistant Context Boundaries
            findings.extend(self.boundary_auditor.audit_assistant_context_boundary(flow, response_text))

            # 4. Federated Identity Interoperability Paths
            findings.extend(self.boundary_auditor.audit_federated_identity_paths(flow, response_text))

            # 5. Dynamic Data Masking & GraphQL/JSON Schema Inspection
            if "application/json" in content_type or "graphql" in content_type or response_text.startswith(("{", "[")):
                try:
                    parsed_json = json.loads(response_text)
                    masking_issues = self.masking_auditor.traverse(parsed_json)
                    for issue in masking_issues:
                        findings.append(ComplianceFinding(
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            boundary_layer="Data Masking Compliance",
                            severity=issue["severity"],
                            flow_id=flow.id,
                            method=flow.request.method,
                            url=flow.request.pretty_url,
                            finding_type=issue["type"],
                            description=f"Field '{issue['key']}' at path '{issue['path']}' violates data obfuscation policy.",
                            matched_key=issue["key"],
                            sample_evidence=issue.get("evidence"),
                            metadata={"path": issue["path"]}
                        ))

                    # 6. Pre-Authentication Information Disclosure Check
                    pre_auth_issues = self.pre_auth_auditor.audit(flow, parsed_json)
                    findings.extend(pre_auth_issues)
                except Exception:
                    pass

        # Flush findings to stream
        for finding in findings:
            self._write_finding(finding)


addons = [
    TelemetryComplianceScanner()
]
