"""Evidence-gated reports built from stored scans, findings and campaign evidence."""

from .campaign_report import ReportError, build_campaign_report

__all__ = ["ReportError", "build_campaign_report"]
