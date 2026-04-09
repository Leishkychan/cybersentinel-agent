"""PDF Report Generator — generates professional PDF reports using reportlab."""

import io
from datetime import datetime
from typing import Optional, Any
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, black, white
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle,
    Image, KeepTogether, PageTemplate, Frame, PageDrawing
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfgen import canvas


class PDFReportGenerator:
    """Generates professional PDF security reports using reportlab."""

    def __init__(self, filename: str = "security_report.pdf"):
        """Initialize PDF generator.

        Args:
            filename: Output PDF filename
        """
        self.filename = filename
        self.severity_colors = {
            "critical": HexColor("#ff3333"),
            "high": HexColor("#ff9933"),
            "medium": HexColor("#ffcc33"),
            "low": HexColor("#33cc33"),
            "informational": HexColor("#3366ff")
        }
        self.dark_bg = HexColor("#0a0e27")
        self.card_bg = HexColor("#1a1f3a")
        self.text_color = HexColor("#e0e6ed")
        self.secondary_text = HexColor("#9ca3af")

    def generate(
        self,
        findings: list,
        scan_metadata: dict,
        chains: Optional[list] = None,
        compliance_map: Optional[dict] = None
    ) -> bytes:
        """Generate complete PDF report.

        Args:
            findings: List of Finding objects or dicts
            scan_metadata: Dict with scan info
            chains: List of attack chains
            compliance_map: Compliance framework mapping

        Returns:
            PDF as bytes
        """
        # Convert findings to dicts
        findings_data = [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings]

        # Create PDF in memory
        pdf_buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            pdf_buffer,
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=1*inch,
            bottomMargin=0.75*inch,
            title="CyberSentinel Security Report"
        )

        # Define styles
        styles = self._create_styles()

        # Build story (content)
        story = []

        # Cover page
        story.extend(self._build_cover_page(scan_metadata, styles))
        story.append(PageBreak())

        # Executive summary
        story.extend(self._build_executive_summary(findings_data, scan_metadata, styles))
        story.append(PageBreak())

        # Methodology
        story.extend(self._build_methodology(styles))
        story.append(PageBreak())

        # Detailed findings
        story.extend(self._build_findings_section(findings_data, styles))

        # Attack chains if provided
        if chains:
            story.append(PageBreak())
            story.extend(self._build_chains_section(chains, styles))

        # Compliance mapping if provided
        if compliance_map:
            story.append(PageBreak())
            story.extend(self._build_compliance_section(compliance_map, findings_data, styles))

        # Appendix
        story.append(PageBreak())
        story.extend(self._build_appendix(scan_metadata, styles))

        # Build PDF
        doc.build(story, onFirstPage=self._add_page_header, onLaterPages=self._add_page_header)

        pdf_buffer.seek(0)
        return pdf_buffer.read()

    def _create_styles(self) -> dict:
        """Create custom styles for the report."""
        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=28,
            textColor=HexColor("#ff3333"),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )

        heading1 = ParagraphStyle(
            'CustomHeading1',
            parent=styles['Heading1'],
            fontSize=16,
            textColor=HexColor("#ff3333"),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        )

        heading2 = ParagraphStyle(
            'CustomHeading2',
            parent=styles['Heading2'],
            fontSize=12,
            textColor=HexColor("#e0e6ed"),
            spaceAfter=10,
            spaceBefore=10,
            fontName='Helvetica-Bold'
        )

        body_style = ParagraphStyle(
            'CustomBody',
            parent=styles['BodyText'],
            fontSize=10,
            textColor=HexColor("#c4cfe0"),
            spaceAfter=12,
            alignment=TA_JUSTIFY
        )

        return {
            'title': title_style,
            'heading1': heading1,
            'heading2': heading2,
            'body': body_style,
            'normal': styles['Normal']
        }

    def _add_page_header(self, canvas_obj: Any, doc: Any):
        """Add header and footer to each page."""
        canvas_obj.saveState()
        canvas_obj.setFont("Helvetica-Bold", 10)
        canvas_obj.setFillColor(HexColor("#9ca3af"))

        # Footer
        footer_text = f"CyberSentinel Security Report | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Page {doc.page}"
        canvas_obj.drawString(0.75*inch, 0.5*inch, footer_text)

        canvas_obj.restoreState()

    def _build_cover_page(self, metadata: dict, styles: dict) -> list:
        """Build cover page."""
        story = []

        # Title
        story.append(Spacer(1, 1.5*inch))
        story.append(Paragraph("CYBERSENTINEL", styles['title']))
        story.append(Paragraph("Security Assessment Report", styles['heading2']))
        story.append(Spacer(1, 0.5*inch))

        # Report info table
        info_data = [
            ["Target:", metadata.get('target', 'Unknown')],
            ["Date:", metadata.get('timestamp', datetime.now().isoformat())],
            ["Assessment Mode:", metadata.get('mode', 'Unknown')],
            ["Total Findings:", str(sum(1 for f in []))],
        ]

        info_table = Table(info_data, colWidths=[1.5*inch, 3*inch])
        info_table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica', 10),
            ('TEXTCOLOR', (0, 0), (0, -1), HexColor("#ff3333")),
            ('TEXTCOLOR', (1, 0), (1, -1), HexColor("#c4cfe0")),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ]))
        story.append(info_table)

        story.append(Spacer(1, 1*inch))
        story.append(Paragraph(
            "This report contains sensitive security information and should be handled with appropriate confidentiality controls.",
            styles['body']
        ))

        return story

    def _build_executive_summary(self, findings: list, metadata: dict, styles: dict) -> list:
        """Build executive summary section."""
        story = []
        story.append(Paragraph("Executive Summary", styles['heading1']))

        # Severity counts
        severity_counts = {
            "critical": len([f for f in findings if f.get('severity') == 'critical']),
            "high": len([f for f in findings if f.get('severity') == 'high']),
            "medium": len([f for f in findings if f.get('severity') == 'medium']),
            "low": len([f for f in findings if f.get('severity') == 'low']),
            "informational": len([f for f in findings if f.get('severity') == 'informational']),
        }

        # Summary cards
        summary_data = [
            ["Severity", "Count"],
            ["CRITICAL", str(severity_counts['critical'])],
            ["HIGH", str(severity_counts['high'])],
            ["MEDIUM", str(severity_counts['medium'])],
            ["LOW", str(severity_counts['low'])],
            ["INFORMATIONAL", str(severity_counts['informational'])],
            ["TOTAL", str(len(findings))],
        ]

        summary_table = Table(summary_data, colWidths=[3*inch, 1.5*inch])
        summary_table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 11),
            ('BACKGROUND', (0, 0), (-1, 0), HexColor("#1a1f3a")),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor("#ff3333")),
            ('FONT', (0, 1), (-1, -1), 'Helvetica', 10),
            ('TEXTCOLOR', (0, 1), (-1, -1), HexColor("#c4cfe0")),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor("#0f1329")),
            ('GRID', (0, 0), (-1, -1), 1, HexColor("#2d3748")),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ]))
        story.append(summary_table)

        story.append(Spacer(1, 0.3*inch))
        risk_score = self._calculate_risk_score(severity_counts)
        story.append(Paragraph(
            f"<b>Risk Score:</b> {risk_score}/100",
            styles['heading2']
        ))

        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph(
            "A comprehensive security assessment of the target environment identified multiple security findings "
            "across critical infrastructure components. Immediate action is recommended for all critical and high-severity findings.",
            styles['body']
        ))

        return story

    def _build_methodology(self, styles: dict) -> list:
        """Build methodology section."""
        story = []
        story.append(Paragraph("Assessment Methodology", styles['heading1']))

        methodology_text = """
        <b>Scope:</b> This assessment evaluated the target environment for security vulnerabilities,
        misconfigurations, and compliance gaps using automated scanning and manual analysis.<br/><br/>

        <b>Tools & Techniques:</b> CyberSentinel employs multiple specialized agents to perform
        comprehensive security analysis including: vulnerability scanning, configuration review,
        dependency analysis, secret detection, and compliance mapping.<br/><br/>

        <b>Framework References:</b> Findings are mapped to industry-standard frameworks including
        NIST 800-53, CWE/CVSS, MITRE ATT&CK, and PCI-DSS to facilitate remediation planning
        and compliance reporting.<br/><br/>

        <b>Risk Rating:</b> Findings are rated using CVSS v3.1 scores and EPSS probability estimates
        to help prioritize remediation efforts.
        """

        story.append(Paragraph(methodology_text, styles['body']))
        return story

    def _build_findings_section(self, findings: list, styles: dict) -> list:
        """Build detailed findings section."""
        story = []
        story.append(Paragraph("Detailed Findings", styles['heading1']))

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get('severity', 'info'), 5))

        for i, finding in enumerate(sorted_findings, 1):
            story.append(Paragraph(f"Finding {i}: {finding.get('title', 'Unknown')}", styles['heading2']))

            # Finding details table
            severity = finding.get('severity', 'info').upper()
            cves = ", ".join(finding.get('cve_ids', [])) or "N/A"
            cvss = finding.get('cvss_score', 'N/A')
            component = finding.get('affected_component', 'N/A')

            details_data = [
                ["Severity:", severity],
                ["Component:", component],
                ["CVE(s):", cves],
                ["CVSS Score:", str(cvss)],
                ["EPSS Score:", str(finding.get('epss_score', 'N/A'))],
                ["Confidence:", finding.get('confidence', 'N/A').upper()],
                ["Status:", finding.get('status', 'N/A').upper()],
            ]

            details_table = Table(details_data, colWidths=[1.5*inch, 3.5*inch])
            details_table.setStyle(TableStyle([
                ('FONT', (0, 0), (0, -1), 'Helvetica-Bold', 9),
                ('TEXTCOLOR', (0, 0), (0, -1), HexColor("#ff3333")),
                ('TEXTCOLOR', (1, 0), (1, -1), HexColor("#c4cfe0")),
                ('FONT', (1, 0), (1, -1), 'Helvetica', 9),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(details_table)

            story.append(Spacer(1, 0.15*inch))

            # Description
            if finding.get('description'):
                story.append(Paragraph("<b>Description:</b>", styles['heading2']))
                story.append(Paragraph(finding.get('description', ''), styles['body']))

            # Evidence
            if finding.get('evidence'):
                story.append(Paragraph("<b>Evidence:</b>", styles['heading2']))
                story.append(Paragraph(finding.get('evidence', ''), styles['body']))

            # Remediation
            if finding.get('remediation'):
                story.append(Paragraph("<b>Remediation:</b>", styles['heading2']))
                story.append(Paragraph(finding.get('remediation', ''), styles['body']))

            # Detection guidance
            if finding.get('detection_guidance'):
                story.append(Paragraph("<b>Detection Guidance:</b>", styles['heading2']))
                story.append(Paragraph(finding.get('detection_guidance', ''), styles['body']))

            # ATT&CK mapping
            techniques = finding.get('mitre_techniques', [])
            if techniques:
                story.append(Paragraph("<b>MITRE ATT&CK Mapping:</b>", styles['heading2']))
                tech_text = ", ".join(techniques)
                story.append(Paragraph(tech_text, styles['body']))

            story.append(Spacer(1, 0.25*inch))

        return story

    def _build_chains_section(self, chains: list, styles: dict) -> list:
        """Build attack chains section."""
        story = []
        story.append(Paragraph("Attack Chains", styles['heading1']))

        for i, chain in enumerate(chains, 1):
            story.append(Paragraph(f"Chain {i}", styles['heading2']))
            chain_text = " → ".join(chain)
            story.append(Paragraph(chain_text, styles['body']))
            story.append(Spacer(1, 0.2*inch))

        return story

    def _build_compliance_section(self, compliance_map: dict, findings: list, styles: dict) -> list:
        """Build compliance mapping section."""
        story = []
        story.append(Paragraph("Compliance Mapping", styles['heading1']))

        # Build compliance table
        from collections import defaultdict
        framework_controls = defaultdict(set)

        for finding in findings:
            title = finding.get('title', '')
            if title in compliance_map:
                for framework, controls in compliance_map[title].items():
                    framework_controls[framework].update(controls)

        for framework in sorted(framework_controls.keys()):
            story.append(Paragraph(f"{framework}", styles['heading2']))

            controls = sorted(framework_controls[framework])
            table_data = [["Control"]]
            table_data.extend([[c] for c in controls])

            table = Table(table_data, colWidths=[4*inch])
            table.setStyle(TableStyle([
                ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 10),
                ('BACKGROUND', (0, 0), (-1, 0), HexColor("#1a1f3a")),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor("#ff3333")),
                ('FONT', (0, 1), (-1, -1), 'Helvetica', 9),
                ('TEXTCOLOR', (0, 1), (-1, -1), HexColor("#c4cfe0")),
                ('GRID', (0, 0), (-1, -1), 1, HexColor("#2d3748")),
            ]))
            story.append(table)
            story.append(Spacer(1, 0.2*inch))

        return story

    def _build_appendix(self, metadata: dict, styles: dict) -> list:
        """Build appendix section."""
        story = []
        story.append(Paragraph("Appendix", styles['heading1']))

        story.append(Paragraph("Scan Details", styles['heading2']))

        appendix_data = [
            ["Target", metadata.get('target', 'Unknown')],
            ["Scan Date", metadata.get('timestamp', 'Unknown')],
            ["Assessment Mode", metadata.get('mode', 'Unknown')],
            ["Report Generated", datetime.now().isoformat()],
        ]

        appendix_table = Table(appendix_data, colWidths=[2*inch, 3*inch])
        appendix_table.setStyle(TableStyle([
            ('FONT', (0, 0), (0, -1), 'Helvetica-Bold', 10),
            ('TEXTCOLOR', (0, 0), (0, -1), HexColor("#ff3333")),
            ('TEXTCOLOR', (1, 0), (1, -1), HexColor("#c4cfe0")),
            ('FONT', (1, 0), (1, -1), 'Helvetica', 10),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ]))
        story.append(appendix_table)

        story.append(Spacer(1, 0.3*inch))
        story.append(Paragraph(
            "This report and all findings contained herein are confidential and proprietary. "
            "Unauthorized access, use, or distribution is prohibited.",
            styles['body']
        ))

        return story

    def _calculate_risk_score(self, severity_counts: dict) -> int:
        """Calculate overall risk score."""
        critical = severity_counts.get('critical', 0) * 25
        high = severity_counts.get('high', 0) * 10
        medium = severity_counts.get('medium', 0) * 3
        score = min(100, critical + high + medium)
        return score
