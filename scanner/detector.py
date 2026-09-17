import re
from .entropy import shannon_entropy
from .patterns import PATTERNS


def mask_secret(value: str) -> str:
    """Show only a small prefix/suffix so the detected secret is not exposed."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * max(4, len(value) - 8)}{value[-4:]}"


def _candidate_from_match(match: re.Match) -> str:
    """Use a capture group when the pattern has one, otherwise the whole match."""
    if match.lastindex:
        return match.group(1)
    return match.group(0)


def scan_text(text: str, filename: str = "input.txt") -> list[dict]:
    """Scan text and return structured findings."""
    findings = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        for item in PATTERNS:
            for match in item["pattern"].finditer(line):
                candidate = _candidate_from_match(match)
                findings.append({
                    "file": filename,
                    "line": line_number,
                    "type": item["name"],
                    "risk": item["risk"],
                    "value": mask_secret(candidate),
                    "entropy": round(shannon_entropy(candidate), 2),
                })

        # Heuristic: long mixed strings can be suspicious even without a known prefix.
        for candidate_match in re.finditer(
            r"\b[A-Za-z0-9_\-+/=]{20,}\b", line
        ):
            candidate = candidate_match.group(0)
            entropy = shannon_entropy(candidate)
            if entropy >= 4.0:
                findings.append({
                    "file": filename,
                    "line": line_number,
                    "type": "High-Entropy String",
                    "risk": "Medium",
                    "value": mask_secret(candidate),
                    "entropy": round(entropy, 2),
                })

    return _deduplicate(findings)


def _deduplicate(findings: list[dict]) -> list[dict]:
    seen = set()
    result = []

    for finding in findings:
        key = (
            finding["file"],
            finding["line"],
            finding["type"],
            finding["value"],
        )
        if key not in seen:
            seen.add(key)
            result.append(finding)

    return result
