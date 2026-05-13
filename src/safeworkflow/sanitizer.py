"""Content sanitizer for removing sensitive/injection patterns."""


from .patterns import get_patterns


def sanitize(
    content: str,
    *,
    replacement: str = "[REDACTED]",
    enable_supply_chain: bool = True,
) -> str:
    """Sanitize content by removing/redacting security risks.

    Args:
        content: Text to sanitize.
        replacement: Text to replace detected patterns with.
        enable_supply_chain: Whether to check supply-chain patterns.

    Returns:
        Sanitized content.
    """
    patterns = get_patterns(enable_supply_chain=enable_supply_chain)
    result = content

    for pattern in patterns:
        result = pattern.pattern.sub(replacement, result)

    return result


def sanitize_file(
    input_path: str,
    output_path: str | None = None,
    *,
    replacement: str = "[REDACTED]",
) -> str:
    """Sanitize a file and optionally write to output.

    Args:
        input_path: Path to input file.
        output_path: Optional path for sanitized output.
        replacement: Text to replace detected patterns with.

    Returns:
        Sanitized content.
    """
    with open(input_path, encoding="utf-8") as f:
        content = f.read()

    result = sanitize(content, replacement=replacement)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(result)

    return result
