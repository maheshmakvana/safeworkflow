"""Core types for safeworkflow."""

from dataclasses import dataclass
from enum import Enum


class RiskLevel(str, Enum):
    """Risk severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ScanIssue:
    """Represents a detected security issue."""
    line: int
    column: int
    message: str
    risk_level: RiskLevel
    pattern_name: str
    suggestion: str | None = None


@dataclass
class ScanResult:
    """Result of scanning content for security issues."""
    content: str
    issues: list[ScanIssue]
    score: int
    risk_level: RiskLevel
    is_safe: bool

    def __bool__(self) -> bool:
        """Return True if content is safe."""
        return self.is_safe
