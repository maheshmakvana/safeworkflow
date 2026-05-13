"""Configuration for safeworkflow."""


from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Configuration settings for safeworkflow."""

    fail_on: str = Field(default="high", description="Minimum risk level to fail")
    max_risk_score: int = Field(default=70, description="Maximum acceptable risk score")
    enable_ai_patterns: bool = Field(
        default=True, description="Enable AI-specific patterns"
    )
    enable_supply_chain: bool = Field(
        default=True, description="Enable supply-chain detection"
    )
    custom_patterns: list[str] = Field(
        default_factory=list, description="Custom regex patterns"
    )

    model_config = {"env_prefix": "SAFEWORKFLOW_", "env_file": ".env"}

    @property
    def should_fail_on(self) -> dict[str, int]:
        """Map risk level to minimum score for fail."""
        return {
            "low": 25,
            "medium": 50,
            "high": 75,
            "critical": 90,
        }
