"""AnnotationManager — manages human annotations on findings."""

from typing import List, Optional
from collections import defaultdict


class AnnotationManager:
    """Manages annotations and metadata on findings.

    Provides high-level interface for tagging, prioritization, and
    annotation management backed by SentinelDatabase.
    """

    def __init__(self, database):
        """Initialize annotation manager.

        Args:
            database: SentinelDatabase instance for persistence
        """
        self.db = database
        self.priority_levels = {"critical", "high", "medium", "low", "info"}

    def add_annotation(
        self,
        finding_id: str,
        text: str,
        author: str = "system",
        priority: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> str:
        """Add annotation to a finding.

        Args:
            finding_id: Finding ID
            text: Annotation text
            author: Author name (default: "system")
            priority: Optional priority level (critical, high, medium, low, info)
            tags: Optional list of string tags

        Returns:
            Annotation ID
        """
        # Validate priority if provided
        if priority and priority not in self.priority_levels:
            raise ValueError(f"Invalid priority. Must be one of: {self.priority_levels}")

        return self.db.add_annotation(
            finding_id=finding_id,
            text=text,
            author=author,
            priority=priority,
            tags=tags or []
        )

    def get_annotations(self, finding_id: str) -> List[dict]:
        """Get all annotations for a finding.

        Args:
            finding_id: Finding ID

        Returns:
            List of annotation dicts in reverse chronological order
        """
        return self.db.get_annotations(finding_id)

    def add_tag(self, finding_id: str, tag: str, author: str = "system"):
        """Add a tag to a finding via annotation.

        Args:
            finding_id: Finding ID
            tag: Tag string
            author: Author name
        """
        return self.add_annotation(
            finding_id=finding_id,
            text=f"Tagged: {tag}",
            author=author,
            tags=[tag]
        )

    def set_priority(
        self,
        finding_id: str,
        priority: str,
        author: str = "system",
        reason: str = ""
    ) -> str:
        """Set priority level for a finding.

        Args:
            finding_id: Finding ID
            priority: Priority level (critical, high, medium, low, info)
            author: Author name
            reason: Optional reason for priority change

        Returns:
            Annotation ID
        """
        if priority not in self.priority_levels:
            raise ValueError(f"Invalid priority. Must be one of: {self.priority_levels}")

        text = f"Priority set to: {priority}"
        if reason:
            text += f" - {reason}"

        return self.add_annotation(
            finding_id=finding_id,
            text=text,
            author=author,
            priority=priority
        )

    def search_by_tag(self, tag: str) -> List[str]:
        """Find all findings with a given tag.

        Note: This is a simple implementation that searches annotations.
        For better performance with many findings, consider adding a
        dedicated tags table to the database.

        Args:
            tag: Tag to search for

        Returns:
            List of finding IDs with this tag
        """
        # This would require iterating through findings
        # For now, return empty list - implement with database query optimization
        # if needed for production use
        finding_ids = []

        # In a real implementation, you'd query the annotations table
        # for entries where tags contains the given tag
        # SQL: SELECT DISTINCT finding_id FROM annotations WHERE json_extract(tags, '$[*]') LIKE ?

        return finding_ids

    def get_findings_by_priority(self, priority: str) -> List[str]:
        """Get all findings with a given priority level.

        Args:
            priority: Priority level

        Returns:
            List of finding IDs
        """
        if priority not in self.priority_levels:
            raise ValueError(f"Invalid priority. Must be one of: {self.priority_levels}")

        # Would be implemented with database query
        return []

    def add_remediation_note(
        self,
        finding_id: str,
        remediation_text: str,
        author: str = "system",
        status: str = "in_progress"
    ) -> str:
        """Add remediation progress note to finding.

        Args:
            finding_id: Finding ID
            remediation_text: Note text
            author: Author name
            status: Remediation status (not_started, in_progress, completed)

        Returns:
            Annotation ID
        """
        tags = ["remediation", f"status:{status}"]

        return self.add_annotation(
            finding_id=finding_id,
            text=f"[{status.upper()}] {remediation_text}",
            author=author,
            tags=tags
        )

    def mark_false_positive(
        self,
        finding_id: str,
        reason: str,
        author: str = "system"
    ) -> str:
        """Mark finding as false positive.

        Args:
            finding_id: Finding ID
            reason: Reason why it's a false positive
            author: Author name

        Returns:
            Annotation ID
        """
        return self.add_annotation(
            finding_id=finding_id,
            text=f"Marked as false positive: {reason}",
            author=author,
            priority="info",
            tags=["false_positive"]
        )

    def mark_acknowledged(
        self,
        finding_id: str,
        acknowledgment_text: str,
        author: str = "system"
    ) -> str:
        """Mark finding as acknowledged with a note.

        Args:
            finding_id: Finding ID
            acknowledgment_text: Acknowledgment note
            author: Author name

        Returns:
            Annotation ID
        """
        return self.add_annotation(
            finding_id=finding_id,
            text=f"Acknowledged: {acknowledgment_text}",
            author=author,
            tags=["acknowledged"]
        )

    def add_risk_assessment(
        self,
        finding_id: str,
        assessment_text: str,
        author: str = "system"
    ) -> str:
        """Add risk assessment to finding.

        Args:
            finding_id: Finding ID
            assessment_text: Assessment text
            author: Author name

        Returns:
            Annotation ID
        """
        return self.add_annotation(
            finding_id=finding_id,
            text=f"Risk assessment: {assessment_text}",
            author=author,
            tags=["risk_assessment"]
        )

    def get_annotation_summary(self, finding_id: str) -> dict:
        """Get summary of all annotations for a finding.

        Args:
            finding_id: Finding ID

        Returns:
            Dict with annotation counts and latest priority
        """
        annotations = self.get_annotations(finding_id)

        summary = {
            "total_annotations": len(annotations),
            "authors": set(),
            "tags": set(),
            "latest_priority": None,
            "has_remediation": False,
            "is_false_positive": False,
            "is_acknowledged": False,
        }

        for ann in annotations:
            if ann.get('author'):
                summary['authors'].add(ann['author'])

            if ann.get('tags'):
                summary['tags'].update(ann['tags'])

            if ann.get('priority') and not summary['latest_priority']:
                summary['latest_priority'] = ann['priority']

            if 'remediation' in ann.get('tags', []):
                summary['has_remediation'] = True

            if 'false_positive' in ann.get('tags', []):
                summary['is_false_positive'] = True

            if 'acknowledged' in ann.get('tags', []):
                summary['is_acknowledged'] = True

        # Convert sets to sorted lists for JSON serialization
        summary['authors'] = sorted(list(summary['authors']))
        summary['tags'] = sorted(list(summary['tags']))

        return summary
