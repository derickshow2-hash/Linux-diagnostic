from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Finding:
    title: str
    severity: str
    status: str
    evidence: list[str] = field(default_factory=list)
    explanation: str = ""
    confidence: float = 0.5
    recommendations: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    category: str = "Общее"
    related: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DiagnosticReport:
    created_at: str
    host: dict[str, Any]
    data: dict[str, Any]
    findings: list[Finding]
    duration_seconds: float = 0.0

    @classmethod
    def create(cls, host: dict[str, Any], data: dict[str, Any], findings: list[Finding], duration: float) -> "DiagnosticReport":
        return cls(datetime.now(timezone.utc).isoformat(), host, data, findings, round(duration, 2))

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "created_at": self.created_at, "host": self.host,
                "duration_seconds": self.duration_seconds, "data": self.data,
                "findings": [f.to_dict() for f in self.findings]}
