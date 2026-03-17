"""Block cipher modes of operation."""

from .ecb import ECBMode

__all__ = [
    "ECBMode",
    "ModeError",
]


class ModeError(ValueError):
    """Mode-specific error (e.g., IV reuse, invalid parameters)."""
    pass
