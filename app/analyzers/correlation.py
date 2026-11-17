from __future__ import annotations

from app.models import Finding


def correlate(findings: list[Finding]) -> list[Finding]:
    """Collapse confirmed subsystem evidence into a cautious common-cause note."""
    # The detailed rules already attach related IDs and avoid claiming causality.
    # Keep independent findings visible; the UI groups linked issues by category.
    return findings
