import re

# These are intentionally generic/demo-oriented signatures.
# They identify likely secrets; they do not prove that a value is valid.
PATTERNS = [
    {
        "name": "AWS Access Key",
        "pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "risk": "High",
    },
    {
        "name": "GitHub Token",
        "pattern": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
        "risk": "High",
    },
    {
        "name": "JWT Token",
        "pattern": re.compile(
            r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"
        ),
        "risk": "High",
    },
    {
        "name": "Private Key",
        "pattern": re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
        ),
        "risk": "Critical",
    },
    {
        "name": "Generic API Key",
        "pattern": re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{12,})"
        ),
        "risk": "High",
    },
    {
        "name": "Password Assignment",
        "pattern": re.compile(
            r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{6,})['\"]"
        ),
        "risk": "High",
    },
    {
        "name": "Secret/Token Assignment",
        "pattern": re.compile(
            r"(?i)\b(?:secret|token|auth[_-]?token)\s*[:=]\s*['\"]([^'\"]{10,})['\"]"
        ),
        "risk": "High",
    },
]
