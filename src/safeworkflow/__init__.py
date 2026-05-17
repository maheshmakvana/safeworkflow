"""safeworkflow - Prompt injection and supply-chain risk protection."""

from .config import Settings
from .sanitizer import sanitize
from .scanner import scan
from .scorer import RiskLevel, Score
from .types import ScanIssue, ScanResult

__version__ = "1.0.7"
__all__ = [
    "scan",
    "Score",
    "RiskLevel",
    "sanitize",
    "Settings",
    "ScanResult",
    "ScanIssue",
]
