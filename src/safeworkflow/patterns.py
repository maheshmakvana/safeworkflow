"""Pattern database for detecting injection and supply-chain risks."""

import re
from typing import NamedTuple


class Pattern(NamedTuple):
    """A detection pattern."""
    name: str
    pattern: re.Pattern
    risk_level: str
    description: str


# Base injection patterns
INJECTION_PATTERNS = [
    Pattern(
        name="ignore_previous",
        pattern=re.compile(
            r"ignore\s+(all\s+)?(previous|above|prior|earlier)",
            re.IGNORECASE
        ),
        risk_level="critical",
        description="Attempts to ignore previous instructions",
    ),
    Pattern(
        name="system_override",
        pattern=re.compile(
            r"(you are now|new instructions|override|disregard).*system",
            re.IGNORECASE
        ),
        risk_level="critical",
        description="System instruction override attempt",
    ),
    Pattern(
        name="jailbreak",
        pattern=re.compile(
            r"(jailbreak|dan\s*mode|developer\s*mode|unfiltered)",
            re.IGNORECASE
        ),
        risk_level="critical",
        description="Jailbreak or DAN mode attempt",
    ),
    Pattern(
        name="role_injection",
        pattern=re.compile(
            r"(you are|act as|pretend to be|roleplay).*?(assistant|admin|root)",
            re.IGNORECASE
        ),
        risk_level="high",
        description="Role injection attempt",
    ),
    Pattern(
        name="command_injection",
        pattern=re.compile(
            r"(rm\s+-rf|sudo|chmod|curl\s+\||\|\s*bash|\$\(.*\)|`.*?`)",
            re.IGNORECASE
        ),
        risk_level="high",
        description="Shell command injection attempt",
    ),
    Pattern(
        name="javascript_protocol",
        pattern=re.compile(
            r"javascript:|data:text/html",
            re.IGNORECASE
        ),
        risk_level="medium",
        description="JavaScript protocol in URL",
    ),
    Pattern(
        name="supply_chain_pkg",
        pattern=re.compile(
            r"(pip\s+install|npm\s+install|go\s+get).*-[a-z0-9]{8,12}",
            re.IGNORECASE
        ),
        risk_level="high",
        description="Suspicious package name with random suffix",
    ),
    Pattern(
        name="typosquatting",
        pattern=re.compile(
            r"(requessts|requsts|resquests|numpyy|pandas1)",
            re.IGNORECASE
        ),
        risk_level="high",
        description="Typosquatting attempt",
    ),
    Pattern(
        name="env_leak",
        pattern=re.compile(
            r"(OPENAI_API_KEY|ANTHROPIC_API|SECRET|TOKEN).{0,20}(['\"]?\w{20,})",
            re.IGNORECASE
        ),
        risk_level="medium",
        description="Potential credential leak",
    ),
]


def get_patterns(enable_supply_chain: bool = True) -> list[Pattern]:
    """Get all detection patterns based on configuration."""
    patterns = list(INJECTION_PATTERNS)
    if not enable_supply_chain:
        patterns = [
            p
            for p in patterns
            if "supply" not in p.name.lower() and "typo" not in p.name.lower()
        ]
    return patterns
