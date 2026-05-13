"""Content scanner for detecting security risks."""


from .patterns import get_patterns
from .scorer import Score
from .types import RiskLevel, ScanIssue, ScanResult


def scan(
    content: str,
    *,
    fail_on: str = "high",
    enable_supply_chain: bool = True,
    max_score: int = 100,
) -> ScanResult:
    """Scan content for injection and supply-chain risks.

    Args:
        content: Text to scan for security issues.
        fail_on: Minimum risk level that triggers failure.
        enable_supply_chain: Whether to check supply-chain patterns.
        max_score: Maximum possible risk score.

    Returns:
        ScanResult with issues and risk assessment.
    """
    issues: list[ScanIssue] = []
    patterns = get_patterns(enable_supply_chain=enable_supply_chain)

    lines = content.split("\n")
    for line_num, line in enumerate(lines, 1):
        for pattern in patterns:
            for match in pattern.pattern.finditer(line):
                issue = ScanIssue(
                    line=line_num,
                    column=match.start() + 1,
                    message=f"{pattern.description}: '{match.group()}'",
                    risk_level=RiskLevel(pattern.risk_level),
                    pattern_name=pattern.name,
                    suggestion=_get_suggestion(pattern.name),
                )
                issues.append(issue)

    score = Score.calculate(issues, max_score=max_score)
    risk_level = _determine_risk_level(score)
    threshold = Score.threshold_for(fail_on)
    is_safe = score < threshold

    return ScanResult(
        content=content,
        issues=issues,
        score=score,
        risk_level=risk_level,
        is_safe=is_safe,
    )


def scan_file(
    path: str,
    *,
    fail_on: str = "high",
    encoding: str = "utf-8",
) -> ScanResult:
    """Scan a file for security risks.

    Args:
        path: Path to file to scan.
        fail_on: Minimum risk level that triggers failure.
        encoding: File encoding.

    Returns:
        ScanResult with issues and risk assessment.
    """
    with open(path, encoding=encoding) as f:
        content = f.read()
    return scan(content, fail_on=fail_on)


def _get_suggestion(pattern_name: str) -> str | None:
    """Get remediation suggestion for a pattern."""
    suggestions = {
        "ignore_previous": "Remove instruction override attempts",
        "system_override": "Avoid system instruction manipulation",
        "jailbreak": "Block jailbreak patterns entirely",
        "role_injection": "Sanitize role-playing attempts",
    }
    return suggestions.get(pattern_name)


def _determine_risk_level(score: int) -> RiskLevel:
    """Determine risk level from score."""
    if score >= 90:
        return RiskLevel.CRITICAL
    elif score >= 70:
        return RiskLevel.HIGH
    elif score >= 40:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW
