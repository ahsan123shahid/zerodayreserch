"""
Unit verification script for meta_dynamic_scanner.py logic components.
"""
import json
from meta_dynamic_scanner import DataMaskingAuditor, TelemetryConfig

def test_masking_auditor():
    auditor = DataMaskingAuditor()

    # 1. Test unmasked target identifier
    unmasked_payload = {
        "status": "success",
        "data": {
            "account": {
                "profile": {
                    "username": "malik_iqra04",
                    "destination_addr": "192.168.1.104",
                    "session_state": "ACTIVE_AUTHENTICATED_FLAG"
                }
            }
        }
    }
    findings = auditor.traverse(unmasked_payload)
    print(f"Total findings for unmasked payload: {len(findings)}")
    assert any("malik_iqra04" in f.get("evidence", "") for f in findings), "Expected target identifier violation"
    assert any(f.get("key") == "session_state" for f in findings), "Expected session_state violation"
    assert any(f.get("key") == "destination_addr" for f in findings), "Expected destination_addr violation"

    # 2. Test properly masked payload
    masked_payload = {
        "status": "success",
        "data": {
            "account": {
                "profile": {
                    "username": "malik_***04",
                    "destination_addr": "***REDACTED***",
                    "session_state": "[MASKED]"
                }
            }
        }
    }
    findings_masked = auditor.traverse(masked_payload)
    # The explicit identifier "malik_iqra04" is not in "malik_***04", and values have mask symbols
    critical_or_high = [f for f in findings_masked if f.get("severity") in ("CRITICAL", "HIGH")]
    print(f"Findings for properly masked payload: {len(critical_or_high)}")
    assert len(critical_or_high) == 0, f"Masked payload should have 0 critical/high findings, got {critical_or_high}"

    print("[+] DataMaskingAuditor unit test PASSED!")

def test_pre_auth_exposure_auditor():
    from meta_dynamic_scanner import PreAuthExposureAuditor

    auditor = PreAuthExposureAuditor()

    class MockRequest:
        def __init__(self, headers=None, cookies=None, method="GET", url="https://api.internal/v1/user/lookup"):
            self.headers = headers or {}
            self.cookies = cookies or {}
            self.method = method
            self.pretty_url = url

    class MockFlow:
        def __init__(self, req):
            self.request = req
            self.id = "mock_flow_123"

    # Test Case 1: Pre-auth request returning cleartext user_id and creation timestamp
    pre_auth_flow = MockFlow(MockRequest(headers={}, cookies={}))
    payload_leaking = {
        "status": "ok",
        "data": {
            "account": {
                "user_id": 9841203,
                "created_at": "2021-04-12T10:14:00Z"
            }
        }
    }
    findings = auditor.audit(pre_auth_flow, payload_leaking)
    print(f"Pre-auth findings count: {len(findings)}")
    assert len(findings) == 2, f"Expected 2 findings, got {len(findings)}"
    types = [f.finding_type for f in findings]
    assert "Pre_Auth_Raw_Identifier_Leak" in types, "Missing Pre_Auth_Raw_Identifier_Leak finding"
    assert "Pre_Auth_Creation_Timestamp_Leak" in types, "Missing Pre_Auth_Creation_Timestamp_Leak finding"

    # Test Case 2: Authenticated request with Bearer token (should NOT trigger pre-auth leak findings)
    authed_flow = MockFlow(MockRequest(headers={"authorization": "Bearer token123"}))
    findings_authed = auditor.audit(authed_flow, payload_leaking)
    assert len(findings_authed) == 0, "Authenticated flow should not trigger Pre-Auth audit"

    # Test Case 3: Pre-auth request with properly masked values
    payload_masked = {
        "status": "ok",
        "data": {
            "account": {
                "user_id": "9841***",
                "created_at": "[MASKED]"
            }
        }
    }
    findings_masked = auditor.audit(pre_auth_flow, payload_masked)
    assert len(findings_masked) == 0, "Masked values should not trigger Pre-Auth audit"

    print("[+] PreAuthExposureAuditor unit test PASSED!")

if __name__ == "__main__":
    test_masking_auditor()
    test_pre_auth_exposure_auditor()

