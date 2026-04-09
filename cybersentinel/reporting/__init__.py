"""Reporting layer — generates reports in various formats.

Provides multiple report generation formats including interactive HTML dashboards,
PDF reports, Markdown output, and compliance framework mapping (NIST, CIS, etc.).
"""

from .html_dashboard import HTMLDashboardGenerator
from .markdown_report import MarkdownReportGenerator
from .compliance import ComplianceMapper
from .delta import DeltaReporter, DeltaReport

# PDF reporter is optional due to reportlab dependency
try:
    from .pdf_report import PDFReportGenerator
except ImportError:
    PDFReportGenerator = None

__all__ = [
    "HTMLDashboardGenerator",
    "PDFReportGenerator",
    "MarkdownReportGenerator",
    "ComplianceMapper",
    "DeltaReporter",
    "DeltaReport",
]
