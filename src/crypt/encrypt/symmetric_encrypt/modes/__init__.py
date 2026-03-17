"""Block cipher modes of operation."""

from .cbc import CBCMode
from .ecb import ECBMode

__all__ = [
    "ECBMode",
    "CBCMode",
    "ModeError",
]


class ModeError(ValueError):
    """Mode-specific error (e.g., IV reuse, invalid parameters)."""
    pass
