"""Risk scoring engine for safeworkflow."""

from .types import RiskLevel, ScanIssue


class Score:
    """Risk scoring utilities."""

    WEIGHTS = {
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 3,
        RiskLevel.HIGH: 7,
        RiskLevel.CRITICAL: 15,
    }

    @staticmethod
    def calculate(issues: list[ScanIssue], max_score: int = 100) -> int:
        """Calculate risk score from issues.

        Args:
            issues: List of detected security issues.
            max_score: Maximum possible score.

        Returns:
            Risk score 0-100.
        """
        if not issues:
            return 0

        # Higher weighting for critical issues
        weights = {
            RiskLevel.CRITICAL: 40,
            RiskLevel.HIGH: 25,
            RiskLevel.MEDIUM: 10,
            RiskLevel.LOW: 5,
        }
        total = sum(weights.get(issue.risk_level, 5) for issue in issues)
        # Cap at max_score
        return min(total, max_score)

    @staticmethod
    def threshold_for(level: str) -> int:
        """Get score threshold for a risk level.

        Args:
            level: Risk level string (low/medium/high/critical).

        Returns:
            Score threshold.
        """
        thresholds = {
            "low": 25,
            "medium": 50,
            "high": 75,
            "critical": 90,
        }
        return thresholds.get(level.lower(), 75)
