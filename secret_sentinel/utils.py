"""Utility functions for Secret Sentinel."""

import math


def shannon_entropy(value: str) -> float:
    """Calculate the Shannon entropy of a given string.

    Args:
        value: Input string to evaluate.

    Returns:
        Shannon entropy as a float value.
    """
    if not value:
        return 0.0
    frequency = {}
    for ch in value:
        frequency[ch] = frequency.get(ch, 0) + 1
    entropy = 0.0
    length = len(value)
    for count in frequency.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_text_bytes(data: bytes) -> bool:
    """Determine whether binary data appears to be plain text.

    Args:
        data: Byte sequence to check.

    Returns:
        True if the data looks like plain text, False otherwise.
    """
    if not data:
        return True
    if b"\0" in data:
        return False
    # Bytes >= 0x80 are allowed so UTF-8 and Latin-1 text are not mistaken for binary.
    sample = data[:4096]
    control_bytes = sum(
        1 for byte in sample if byte < 32 and byte not in b"\n\r\t\b\f\v\x1b"
    )
    return control_bytes / len(sample) < 0.05


def mask_secret(value: str) -> str:
    """Redact a secret value completely to prevent credential exposure.

    Args:
        value: Sensitive string to mask.

    Returns:
        Redacted placeholder string.
    """
    return "[REDACTED]"


def sanitize_snippet(snippet: str, secret: str) -> str:
    """Replace sensitive secret occurrences within a code snippet.

    Args:
        snippet: The source code line or snippet.
        secret: The secret value detected within the snippet.

    Returns:
        The snippet with the secret replaced by a redacted placeholder.
    """
    if not snippet or not secret:
        return snippet
    return snippet.replace(secret, "[REDACTED]")
