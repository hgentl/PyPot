from honeypot.logger import is_suspicious


def test_detects_suspicous_path():
    reasons = is_suspicious("1.2.3.4", "/admin", "Mozilla")
    assert "Sensitive endpoint probing" in reasons

def test_detecs_suspicious_user_agent():
    reasons = is_suspicious("1.2.3.4", "/home", "curl/7.0")
    assert "Suspicious user agent" in reasons

def test_detects_multiple_issues():
    reasons = is_suspicious("1.2.3.4", "/admin", "curl/7.0")
    assert len(reasons) == 2

def test_normal_request_not_flagged():
    reasons = is_suspicious("1.2.3.4", "/home", "Mozilla/5.0")
    assert reasons == []