"""Storage layer — persistence for scans, findings, and annotations.

Manages database operations and annotation tracking for security findings.
"""

from .database import SentinelDatabase
from .annotations import AnnotationManager

__all__ = [
    "SentinelDatabase",
    "AnnotationManager",
]
