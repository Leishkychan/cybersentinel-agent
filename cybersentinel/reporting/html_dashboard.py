"""HTML Dashboard Generator — generates interactive, visual single-file HTML dashboard."""

import json
from datetime import datetime
from typing import Any, Optional
from collections import defaultdict, Counter


class HTMLDashboardGenerator:
    """Generates a professional, interactive HTML dashboard from findings and metadata.

    The dashboard is a completely self-contained HTML file with embedded CSS and JavaScript,
    using Chart.js from CDN for charts. It includes dark theme styling optimized for
    cybersecurity reporting.
    """

    def __init__(self):
        """Initialize the dashboard generator."""
        self.severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
        self.severity_colors = {
            "critical": "#ff3333",
            "high": "#ff9933",
            "medium": "#ffcc33",
            "low": "#33cc33",
            "informational": "#3366ff"
        }

    def generate(
        self,
        findings: list,
        scan_metadata: dict,
        chains: Optional[list] = None,
        compliance_map: Optional[dict] = None,
        delta_report: Optional[dict] = None
    ) -> str:
        """Generate complete HTML dashboard.

        Args:
            findings: List of Finding objects or dicts
            scan_metadata: Dict with scan info (target, timestamp, mode, etc)
            chains: List of attack chains (each chain is a list of steps)
            compliance_map: Dict mapping findings to compliance controls
            delta_report: Delta comparison data (new, resolved, persisting, etc)

        Returns:
            Complete HTML string ready to save as .html file
        """
        # Convert findings to dicts if necessary
        findings_data = [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings]

        # Prepare data for charts and tables
        severity_counts = self._count_by_severity(findings_data)
        agent_counts = self._count_by_agent(findings_data)
        status_counts = self._count_by_status(findings_data)
        timeline_data = self._build_timeline(findings_data, scan_metadata)

        # Generate sections
        html_parts = [
            self._html_head(),
            self._html_body_open(),
            self._navigation(),
            self._executive_summary(severity_counts, status_counts, scan_metadata),
            self._severity_donut_chart(severity_counts),
            self._agent_distribution_chart(agent_counts),
            self._filters_section(),
            self._findings_table(findings_data),
            self._finding_details_section(findings_data),
        ]

        # Add optional sections
        if chains:
            html_parts.append(self._attack_chains_section(chains))

        if delta_report:
            html_parts.append(self._delta_section(delta_report))

        if compliance_map:
            html_parts.append(self._compliance_section(compliance_map, findings_data))

        html_parts.append(self._timeline_section(timeline_data))
        html_parts.append(self._footer())
        html_parts.append("</body></html>")

        return "".join(html_parts)

    def _html_head(self) -> str:
        """Generate HTML head section with styling."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberSentinel Security Report Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
            color: #e0e6ed;
            line-height: 1.6;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            background: linear-gradient(135deg, #1a1f3a 0%, #0f1329 100%);
            border-bottom: 3px solid #ff3333;
            padding: 40px 0;
            margin-bottom: 40px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
        }

        .header-content {
            max-width: 1400px;
            margin: 0 auto;
            padding: 0 20px;
        }

        h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            background: linear-gradient(135deg, #ff3333, #ff9933);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .header-meta {
            font-size: 0.9em;
            color: #9ca3af;
        }

        .nav-tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 30px;
            border-bottom: 2px solid #2d3748;
            flex-wrap: wrap;
        }

        .tab-button {
            padding: 12px 24px;
            background: transparent;
            border: none;
            border-bottom: 3px solid transparent;
            color: #9ca3af;
            cursor: pointer;
            font-size: 1em;
            font-weight: 500;
            transition: all 0.3s ease;
        }

        .tab-button:hover {
            color: #e0e6ed;
        }

        .tab-button.active {
            color: #ff3333;
            border-bottom-color: #ff3333;
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .executive-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }

        .summary-card {
            background: linear-gradient(135deg, #1a1f3a 0%, #141829 100%);
            border: 1px solid #2d3748;
            border-radius: 8px;
            padding: 24px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
        }

        .summary-card h3 {
            font-size: 0.85em;
            color: #9ca3af;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            margin-bottom: 12px;
        }

        .summary-card .value {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 8px;
        }

        .summary-card.critical .value {
            color: #ff3333;
        }

        .summary-card.high .value {
            color: #ff9933;
        }

        .summary-card.medium .value {
            color: #ffcc33;
        }

        .summary-card.low .value {
            color: #33cc33;
        }

        .summary-card.info .value {
            color: #3366ff;
        }

        .chart-container {
            background: linear-gradient(135deg, #1a1f3a 0%, #141829 100%);
            border: 1px solid #2d3748;
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 30px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
        }

        .chart-container h3 {
            margin-bottom: 20px;
            font-size: 1.3em;
            color: #e0e6ed;
        }

        .chart-wrapper {
            position: relative;
            height: 300px;
        }

        .filter-section {
            background: linear-gradient(135deg, #1a1f3a 0%, #141829 100%);
            border: 1px solid #2d3748;
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 30px;
        }

        .filter-controls {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }

        .filter-group {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .filter-group label {
            font-size: 0.85em;
            color: #9ca3af;
            font-weight: 500;
        }

        .filter-group select,
        .filter-group input {
            padding: 8px 12px;
            background: #0f1329;
            border: 1px solid #2d3748;
            border-radius: 4px;
            color: #e0e6ed;
            font-size: 0.95em;
        }

        .filter-group select:focus,
        .filter-group input:focus {
            outline: none;
            border-color: #ff3333;
            box-shadow: 0 0 10px rgba(255, 51, 51, 0.3);
        }

        .table-container {
            background: linear-gradient(135deg, #1a1f3a 0%, #141829 100%);
            border: 1px solid #2d3748;
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 30px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        thead {
            background: #0f1329;
            border-bottom: 2px solid #2d3748;
        }

        th {
            padding: 16px;
            text-align: left;
            font-weight: 600;
            color: #9ca3af;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            cursor: pointer;
            user-select: none;
        }

        th:hover {
            background: #1a1f3a;
        }

        td {
            padding: 16px;
            border-bottom: 1px solid #2d3748;
        }

        tbody tr {
            transition: background-color 0.2s ease;
            cursor: pointer;
        }

        tbody tr:hover {
            background: rgba(255, 51, 51, 0.05);
        }

        .severity-badge {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 4px;
            font-weight: 600;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .severity-critical {
            background: rgba(255, 51, 51, 0.2);
            color: #ff3333;
            border: 1px solid #ff3333;
        }

        .severity-high {
            background: rgba(255, 153, 51, 0.2);
            color: #ff9933;
            border: 1px solid #ff9933;
        }

        .severity-medium {
            background: rgba(255, 204, 51, 0.2);
            color: #ffcc33;
            border: 1px solid #ffcc33;
        }

        .severity-low {
            background: rgba(51, 204, 51, 0.2);
            color: #33cc33;
            border: 1px solid #33cc33;
        }

        .severity-informational {
            background: rgba(51, 102, 255, 0.2);
            color: #3366ff;
            border: 1px solid #3366ff;
        }

        .status-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 3px;
            font-size: 0.8em;
            text-transform: uppercase;
        }

        .status-open {
            background: rgba(255, 51, 51, 0.15);
            color: #ff3333;
        }

        .status-confirmed {
            background: rgba(255, 153, 51, 0.15);
            color: #ff9933;
        }

        .status-resolved {
            background: rgba(51, 204, 51, 0.15);
            color: #33cc33;
        }

        .status-false_positive {
            background: rgba(51, 102, 255, 0.15);
            color: #3366ff;
        }

        .detail-modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.7);
            z-index: 1000;
            overflow-y: auto;
        }

        .detail-modal.active {
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .detail-content {
            background: #0f1329;
            border: 2px solid #2d3748;
            border-radius: 8px;
            padding: 40px;
            max-width: 800px;
            max-height: 90vh;
            overflow-y: auto;
            width: 90%;
        }

        .detail-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid #2d3748;
        }

        .detail-title {
            font-size: 1.5em;
            color: #e0e6ed;
            flex: 1;
        }

        .close-btn {
            background: none;
            border: none;
            color: #9ca3af;
            cursor: pointer;
            font-size: 1.5em;
            padding: 0;
        }

        .close-btn:hover {
            color: #ff3333;
        }

        .detail-section {
            margin-bottom: 20px;
        }

        .detail-section h4 {
            color: #ff3333;
            margin-bottom: 10px;
            font-size: 0.95em;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .detail-section p {
            color: #c4cfe0;
            line-height: 1.8;
        }

        .cve-list, .technique-list {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 8px;
        }

        .cve-tag, .technique-tag {
            background: #1a1f3a;
            border: 1px solid #2d3748;
            padding: 6px 12px;
            border-radius: 4px;
            font-size: 0.85em;
            color: #c4cfe0;
        }

        .cve-tag {
            border-left: 3px solid #ff9933;
        }

        .technique-tag {
            border-left: 3px solid #3366ff;
        }

        .attack-chain {
            background: linear-gradient(135deg, #1a1f3a 0%, #141829 100%);
            border: 1px solid #2d3748;
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 30px;
        }

        .chain-steps {
            display: flex;
            align-items: center;
            gap: 15px;
            flex-wrap: wrap;
            margin-top: 16px;
        }

        .chain-step {
            background: #0f1329;
            border: 2px solid #2d3748;
            padding: 12px 16px;
            border-radius: 4px;
            font-weight: 500;
            color: #e0e6ed;
            font-size: 0.9em;
        }

        .chain-arrow {
            color: #ff3333;
            font-weight: bold;
            font-size: 1.2em;
        }

        .delta-changes {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .delta-card {
            background: #1a1f3a;
            border: 1px solid #2d3748;
            border-radius: 8px;
            padding: 16px;
        }

        .delta-card.new {
            border-left: 4px solid #ff3333;
        }

        .delta-card.resolved {
            border-left: 4px solid #33cc33;
        }

        .delta-card.persisting {
            border-left: 4px solid #ffcc33;
        }

        .delta-card h4 {
            margin-bottom: 12px;
            color: #e0e6ed;
        }

        .delta-card .count {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 8px;
        }

        .delta-card.new .count {
            color: #ff3333;
        }

        .delta-card.resolved .count {
            color: #33cc33;
        }

        .delta-card.persisting .count {
            color: #ffcc33;
        }

        .compliance-table {
            margin-top: 20px;
        }

        .compliance-table tr:nth-child(odd) {
            background: rgba(255, 51, 51, 0.02);
        }

        .timeline-item {
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
            padding-bottom: 20px;
            border-bottom: 1px solid #2d3748;
        }

        .timeline-item:last-child {
            border-bottom: none;
        }

        .timeline-marker {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            margin-top: 2px;
            flex-shrink: 0;
        }

        .timeline-marker.critical {
            background: #ff3333;
            box-shadow: 0 0 15px rgba(255, 51, 51, 0.5);
        }

        .timeline-marker.high {
            background: #ff9933;
        }

        .timeline-marker.medium {
            background: #ffcc33;
        }

        .timeline-marker.low {
            background: #33cc33;
        }

        .timeline-marker.informational {
            background: #3366ff;
        }

        .timeline-content {
            flex: 1;
        }

        .timeline-title {
            color: #e0e6ed;
            font-weight: 600;
            margin-bottom: 4px;
        }

        .timeline-meta {
            color: #9ca3af;
            font-size: 0.9em;
        }

        footer {
            border-top: 1px solid #2d3748;
            padding: 20px;
            text-align: center;
            color: #9ca3af;
            margin-top: 40px;
        }

        .hidden {
            display: none !important;
        }

        @media (max-width: 768px) {
            h1 {
                font-size: 1.8em;
            }

            .chart-wrapper {
                height: 250px;
            }

            .filter-controls {
                flex-direction: column;
                align-items: stretch;
            }

            .detail-content {
                padding: 24px;
            }
        }
    </style>
</head>
"""

    def _html_body_open(self) -> str:
        """Generate opening body tag and header."""
        return '<body>'

    def _navigation(self) -> str:
        """Generate header and navigation."""
        return """
<header>
    <div class="header-content">
        <h1>CyberSentinel Security Report</h1>
        <div class="header-meta" id="headerMeta">Generated on <span id="generatedTime"></span></div>
    </div>
</header>

<div class="container">
    <div class="nav-tabs">
        <button class="tab-button active" onclick="switchTab('summary')">Executive Summary</button>
        <button class="tab-button" onclick="switchTab('findings')">Findings</button>
        <button class="tab-button" onclick="switchTab('chains')" id="chainsTab">Attack Chains</button>
        <button class="tab-button" onclick="switchTab('delta')" id="deltaTab">Delta Report</button>
        <button class="tab-button" onclick="switchTab('compliance')" id="complianceTab">Compliance</button>
        <button class="tab-button" onclick="switchTab('timeline')">Timeline</button>
    </div>
"""

    def _executive_summary(self, severity_counts: dict, status_counts: dict, metadata: dict) -> str:
        """Generate executive summary section."""
        total = sum(severity_counts.values())
        target = metadata.get('target', 'Unknown')
        timestamp = metadata.get('timestamp', datetime.now().isoformat())
        mode = metadata.get('mode', 'Unknown')

        return f"""
    <div id="summary" class="tab-content active">
        <div class="executive-summary">
            <div class="summary-card critical">
                <h3>Critical</h3>
                <div class="value">{severity_counts.get('critical', 0)}</div>
            </div>
            <div class="summary-card high">
                <h3>High</h3>
                <div class="value">{severity_counts.get('high', 0)}</div>
            </div>
            <div class="summary-card medium">
                <h3>Medium</h3>
                <div class="value">{severity_counts.get('medium', 0)}</div>
            </div>
            <div class="summary-card low">
                <h3>Low</h3>
                <div class="value">{severity_counts.get('low', 0)}</div>
            </div>
            <div class="summary-card info">
                <h3>Informational</h3>
                <div class="value">{severity_counts.get('informational', 0)}</div>
            </div>
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="value">{total}</div>
            </div>
        </div>

        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 30px;">
            <div class="chart-container">
                <h3>Severity Distribution</h3>
                <div class="chart-wrapper">
                    <canvas id="severityChart"></canvas>
                </div>
            </div>
            <div class="chart-container">
                <h3>Status Breakdown</h3>
                <div class="chart-wrapper">
                    <canvas id="statusChart"></canvas>
                </div>
            </div>
        </div>

        <div class="summary-card">
            <h3>Scan Information</h3>
            <div style="margin-top: 16px;">
                <p><strong>Target:</strong> {target}</p>
                <p><strong>Timestamp:</strong> {timestamp}</p>
                <p><strong>Mode:</strong> {mode}</p>
                <p><strong>Total Findings:</strong> {total}</p>
                <p><strong>Critical Findings:</strong> {severity_counts.get('critical', 0)}</p>
                <p style="margin-top: 12px; color: #9ca3af; font-size: 0.9em;">Risk Score: <strong style="color: #ff3333;">{self._calculate_risk_score(severity_counts)}/100</strong></p>
            </div>
        </div>
    </div>
"""

    def _severity_donut_chart(self, severity_counts: dict) -> str:
        """Generate JavaScript for severity donut chart."""
        total = sum(severity_counts.values())
        if total == 0:
            return ""

        return f"""
<script>
    document.addEventListener('DOMContentLoaded', function() {{
        const severityCtx = document.getElementById('severityChart');
        if (severityCtx) {{
            new Chart(severityCtx, {{
                type: 'doughnut',
                data: {{
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Informational'],
                    datasets: [{{
                        data: [
                            {severity_counts.get('critical', 0)},
                            {severity_counts.get('high', 0)},
                            {severity_counts.get('medium', 0)},
                            {severity_counts.get('low', 0)},
                            {severity_counts.get('informational', 0)}
                        ],
                        backgroundColor: ['#ff3333', '#ff9933', '#ffcc33', '#33cc33', '#3366ff'],
                        borderColor: '#0f1329',
                        borderWidth: 2
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            position: 'bottom',
                            labels: {{
                                color: '#c4cfe0',
                                font: {{size: 12}},
                                padding: 15
                            }}
                        }}
                    }}
                }}
            }});
        }}
    }});
</script>
"""

    def _agent_distribution_chart(self, agent_counts: dict) -> str:
        """Generate JavaScript for agent distribution chart."""
        if not agent_counts:
            return ""

        labels = list(agent_counts.keys())
        data = list(agent_counts.values())

        return f"""
<script>
    document.addEventListener('DOMContentLoaded', function() {{
        const statusCtx = document.getElementById('statusChart');
        if (statusCtx) {{
            new Chart(statusCtx, {{
                type: 'bar',
                data: {{
                    labels: {json.dumps(labels)},
                    datasets: [{{
                        label: 'Findings by Agent',
                        data: {data},
                        backgroundColor: '#ff3333',
                        borderColor: '#ff6666',
                        borderWidth: 1
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y',
                    plugins: {{
                        legend: {{
                            labels: {{
                                color: '#c4cfe0'
                            }}
                        }}
                    }},
                    scales: {{
                        x: {{
                            ticks: {{
                                color: '#9ca3af'
                            }},
                            grid: {{
                                color: 'rgba(255, 51, 51, 0.1)'
                            }}
                        }},
                        y: {{
                            ticks: {{
                                color: '#9ca3af'
                            }},
                            grid: {{
                                display: false
                            }}
                        }}
                    }}
                }}
            }});
        }}
    }});
</script>
"""

    def _filters_section(self) -> str:
        """Generate filters section."""
        return """
    <div id="findings" class="tab-content">
        <div class="filter-section">
            <div class="filter-controls">
                <div class="filter-group">
                    <label for="severityFilter">Severity</label>
                    <select id="severityFilter" onchange="applyFilters()">
                        <option value="">All</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                        <option value="informational">Informational</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label for="statusFilter">Status</label>
                    <select id="statusFilter" onchange="applyFilters()">
                        <option value="">All</option>
                        <option value="open">Open</option>
                        <option value="confirmed">Confirmed</option>
                        <option value="resolved">Resolved</option>
                        <option value="false_positive">False Positive</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label for="agentFilter">Agent</label>
                    <select id="agentFilter" onchange="applyFilters()">
                        <option value="">All</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label for="searchBox">Search</label>
                    <input type="text" id="searchBox" placeholder="Title or component..." onkeyup="applyFilters()">
                </div>
            </div>
        </div>
"""

    def _findings_table(self, findings: list) -> str:
        """Generate findings table."""
        rows = []
        for i, finding in enumerate(findings):
            cves = ", ".join(finding.get('cve_ids', []))
            title = finding.get('title', 'Unknown')
            severity = finding.get('severity', 'info')
            component = finding.get('affected_component', '')
            agent = finding.get('agent_source', '')
            status = finding.get('status', 'open')

            rows.append(f"""
            <tr onclick="showDetail({i})" data-severity="{severity}" data-status="{status}" data-agent="{agent}" data-searchable="{title.lower()} {component.lower()}">
                <td><span class="severity-badge severity-{severity}">{severity.upper()}</span></td>
                <td>{title}</td>
                <td>{component}</td>
                <td>{cves or 'N/A'}</td>
                <td><span class="status-badge status-{status}">{status}</span></td>
                <td>{agent}</td>
            </tr>
            """)

        return f"""
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th onclick="sortTable(0)">Severity ▼</th>
                        <th onclick="sortTable(1)">Title</th>
                        <th onclick="sortTable(2)">Component</th>
                        <th>CVE(s)</th>
                        <th onclick="sortTable(4)">Status</th>
                        <th onclick="sortTable(5)">Agent</th>
                    </tr>
                </thead>
                <tbody id="findingsBody">
                    {''.join(rows)}
                </tbody>
            </table>
        </div>
"""

    def _finding_details_section(self, findings: list) -> str:
        """Generate hidden detail modals for each finding."""
        modals = []
        for i, finding in enumerate(findings):
            cves = finding.get('cve_ids', [])
            techniques = finding.get('mitre_techniques', [])

            cve_html = ''.join([f'<span class="cve-tag">{cve}</span>' for cve in cves])
            tech_html = ''.join([f'<span class="technique-tag">{t}</span>' for t in techniques])

            detail = f"""
            <div id="detail-{i}" class="detail-modal">
                <div class="detail-content">
                    <div class="detail-header">
                        <h2 class="detail-title">{finding.get('title', 'Unknown')}</h2>
                        <button class="close-btn" onclick="closeDetail({i})">✕</button>
                    </div>

                    <div class="detail-section">
                        <span class="severity-badge severity-{finding.get('severity', 'info')}">{finding.get('severity', 'info').upper()}</span>
                    </div>

                    <div class="detail-section">
                        <h4>Description</h4>
                        <p>{finding.get('description', 'N/A')}</p>
                    </div>

                    <div class="detail-section">
                        <h4>Affected Component</h4>
                        <p>{finding.get('affected_component', 'N/A')}</p>
                    </div>

                    <div class="detail-section">
                        <h4>CVE References</h4>
                        <div class="cve-list">{cve_html or '<span class="cve-tag">No CVEs</span>'}</div>
                    </div>

                    <div class="detail-section">
                        <h4>CVSS Score</h4>
                        <p>{finding.get('cvss_score', 'N/A')} {('(Vector: ' + finding.get('cvss_vector', '') + ')') if finding.get('cvss_vector') else ''}</p>
                    </div>

                    <div class="detail-section">
                        <h4>EPSS Score</h4>
                        <p>{finding.get('epss_score', 'N/A')}</p>
                    </div>

                    <div class="detail-section">
                        <h4>ATT&CK Mapping</h4>
                        <div class="technique-list">{tech_html or '<span class="technique-tag">No mappings</span>'}</div>
                    </div>

                    <div class="detail-section">
                        <h4>Evidence</h4>
                        <p>{finding.get('evidence', 'No evidence provided')}</p>
                    </div>

                    <div class="detail-section">
                        <h4>Remediation</h4>
                        <p>{finding.get('remediation', 'No remediation guidance available')}</p>
                    </div>

                    <div class="detail-section">
                        <h4>Detection Guidance</h4>
                        <p>{finding.get('detection_guidance', 'No detection guidance available')}</p>
                    </div>

                    <div class="detail-section">
                        <h4>Confidence Level</h4>
                        <p>{finding.get('confidence', 'N/A').upper()}</p>
                    </div>

                    <div class="detail-section">
                        <h4>Source Agent</h4>
                        <p>{finding.get('agent_source', 'N/A')}</p>
                    </div>
                </div>
            </div>
            """
            modals.append(detail)

        return f"""
        </div>
        {''.join(modals)}
"""

    def _attack_chains_section(self, chains: list) -> str:
        """Generate attack chains visualization section."""
        chain_html = []
        for i, chain in enumerate(chains):
            steps_html = []
            for step in chain:
                steps_html.append(f'<div class="chain-step">{step}</div>')
                if step != chain[-1]:
                    steps_html.append('<div class="chain-arrow">→</div>')

            chain_html.append(f"""
            <div class="attack-chain">
                <h3>Attack Chain {i+1}</h3>
                <div class="chain-steps">
                    {''.join(steps_html)}
                </div>
            </div>
            """)

        return f"""
    <div id="chains" class="tab-content">
        {''.join(chain_html)}
    </div>
"""

    def _delta_section(self, delta: dict) -> str:
        """Generate delta report section."""
        new_count = len(delta.get('new_findings', []))
        resolved_count = len(delta.get('resolved_findings', []))
        persisting_count = len(delta.get('persisting_findings', []))
        escalated_count = len(delta.get('escalated_findings', []))

        return f"""
    <div id="delta" class="tab-content">
        <div class="delta-changes">
            <div class="delta-card new">
                <h4>New Findings</h4>
                <div class="count">{new_count}</div>
                <p>Findings discovered in this scan</p>
            </div>
            <div class="delta-card resolved">
                <h4>Resolved</h4>
                <div class="count">{resolved_count}</div>
                <p>Previously open findings now fixed</p>
            </div>
            <div class="delta-card persisting">
                <h4>Persisting</h4>
                <div class="count">{persisting_count}</div>
                <p>Still present from previous scan</p>
            </div>
            <div class="delta-card new">
                <h4>Escalated</h4>
                <div class="count">{escalated_count}</div>
                <p>Severity increased since last scan</p>
            </div>
        </div>
    </div>
"""

    def _compliance_section(self, compliance_map: dict, findings: list) -> str:
        """Generate compliance mapping section."""
        frameworks = defaultdict(list)
        for finding in findings:
            finding_id = finding.get('title', '')
            if finding_id in compliance_map:
                for framework, controls in compliance_map[finding_id].items():
                    frameworks[framework].extend(controls)

        framework_html = []
        for framework, controls in sorted(frameworks.items()):
            unique_controls = sorted(set(controls))
            control_html = ''.join([f'<tr><td>{control}</td></tr>' for control in unique_controls])

            framework_html.append(f"""
            <div class="chart-container">
                <h3>{framework} Mapping</h3>
                <table class="compliance-table">
                    <thead>
                        <tr><th>Control</th></tr>
                    </thead>
                    <tbody>
                        {control_html}
                    </tbody>
                </table>
            </div>
            """)

        return f"""
    <div id="compliance" class="tab-content">
        {''.join(framework_html)}
    </div>
"""

    def _timeline_section(self, timeline_data: list) -> str:
        """Generate timeline visualization."""
        timeline_html = []
        for item in timeline_data:
            severity = item.get('severity', 'info')
            timeline_html.append(f"""
            <div class="timeline-item">
                <div class="timeline-marker {severity}"></div>
                <div class="timeline-content">
                    <div class="timeline-title">{item.get('title', 'Unknown')}</div>
                    <div class="timeline-meta">{item.get('component', 'N/A')} • {item.get('time', 'N/A')}</div>
                </div>
            </div>
            """)

        return f"""
    <div id="timeline" class="tab-content">
        <div class="chart-container">
            <h3>Discovery Timeline</h3>
            {''.join(timeline_html)}
        </div>
    </div>
"""

    def _footer(self) -> str:
        """Generate footer."""
        return """
</div>

<footer>
    <p>CyberSentinel Security Report — <span id="footerTime"></span></p>
    <p style="font-size: 0.9em; margin-top: 10px;">This report contains sensitive security information. Handle with appropriate confidentiality controls.</p>
</footer>

<script>
    // Set timestamps
    document.getElementById('generatedTime').textContent = new Date().toLocaleString();
    document.getElementById('footerTime').textContent = new Date().toLocaleString();

    // Tab switching
    function switchTab(tabName) {
        const contents = document.querySelectorAll('.tab-content');
        contents.forEach(c => c.classList.remove('active'));
        document.getElementById(tabName).classList.add('active');

        const buttons = document.querySelectorAll('.tab-button');
        buttons.forEach(b => b.classList.remove('active'));
        event.target.classList.add('active');
    }

    // Hide tabs if no data
    function updateTabVisibility() {
        const chainsTab = document.getElementById('chainsTab');
        const chainsContent = document.getElementById('chains');
        if (chainsContent && chainsContent.textContent.trim().length < 20) {
            chainsTab.classList.add('hidden');
        }

        const deltaTab = document.getElementById('deltaTab');
        const deltaContent = document.getElementById('delta');
        if (deltaContent && deltaContent.textContent.trim().length < 20) {
            deltaTab.classList.add('hidden');
        }

        const complianceTab = document.getElementById('complianceTab');
        const complianceContent = document.getElementById('compliance');
        if (complianceContent && complianceContent.textContent.trim().length < 20) {
            complianceTab.classList.add('hidden');
        }
    }

    // Detail modal
    function showDetail(index) {
        document.getElementById(`detail-${index}`).classList.add('active');
    }

    function closeDetail(index) {
        document.getElementById(`detail-${index}`).classList.remove('active');
    }

    // Filter and search
    function applyFilters() {
        const severity = document.getElementById('severityFilter').value.toLowerCase();
        const status = document.getElementById('statusFilter').value.toLowerCase();
        const agent = document.getElementById('agentFilter').value.toLowerCase();
        const search = document.getElementById('searchBox').value.toLowerCase();

        const rows = document.querySelectorAll('#findingsBody tr');
        rows.forEach(row => {
            const rowSeverity = row.getAttribute('data-severity');
            const rowStatus = row.getAttribute('data-status');
            const rowAgent = row.getAttribute('data-agent').toLowerCase();
            const searchable = row.getAttribute('data-searchable');

            let match = true;
            if (severity && rowSeverity !== severity) match = false;
            if (status && rowStatus !== status) match = false;
            if (agent && !rowAgent.includes(agent)) match = false;
            if (search && !searchable.includes(search)) match = false;

            row.style.display = match ? '' : 'none';
        });
    }

    // Populate agent filter
    document.addEventListener('DOMContentLoaded', function() {
        const agents = new Set();
        document.querySelectorAll('#findingsBody tr').forEach(row => {
            agents.add(row.getAttribute('data-agent'));
        });

        const agentSelect = document.getElementById('agentFilter');
        agents.forEach(agent => {
            const option = document.createElement('option');
            option.value = agent;
            option.textContent = agent;
            agentSelect.appendChild(option);
        });

        updateTabVisibility();
    });

    // Sort table
    function sortTable(col) {
        const tbody = document.getElementById('findingsBody');
        const rows = Array.from(tbody.querySelectorAll('tr'));

        rows.sort((a, b) => {
            const aText = a.cells[col].textContent;
            const bText = b.cells[col].textContent;
            return aText.localeCompare(bText);
        });

        rows.forEach(row => tbody.appendChild(row));
    }

    // Close modal on outside click
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('detail-modal')) {
            e.target.classList.remove('active');
        }
    });
</script>
</body>
</html>
"""

    def _count_by_severity(self, findings: list) -> dict:
        """Count findings by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for finding in findings:
            severity = finding.get('severity', 'informational')
            if severity in counts:
                counts[severity] += 1
        return counts

    def _count_by_agent(self, findings: list) -> dict:
        """Count findings by agent source."""
        counts = defaultdict(int)
        for finding in findings:
            agent = finding.get('agent_source', 'Unknown')
            counts[agent] += 1
        return dict(counts)

    def _count_by_status(self, findings: list) -> dict:
        """Count findings by status."""
        counts = defaultdict(int)
        for finding in findings:
            status = finding.get('status', 'open')
            counts[status] += 1
        return dict(counts)

    def _build_timeline(self, findings: list, metadata: dict) -> list:
        """Build timeline data for visualization."""
        timeline = []
        for finding in sorted(findings, key=lambda f: f.get('severity', 'informational')):
            timeline.append({
                'title': finding.get('title', 'Unknown'),
                'component': finding.get('affected_component', 'Unknown'),
                'severity': finding.get('severity', 'info'),
                'time': metadata.get('timestamp', 'Unknown')
            })
        return timeline

    def _calculate_risk_score(self, severity_counts: dict) -> int:
        """Calculate overall risk score (0-100)."""
        critical = severity_counts.get('critical', 0) * 25
        high = severity_counts.get('high', 0) * 10
        medium = severity_counts.get('medium', 0) * 3

        score = min(100, critical + high + medium)
        return score
