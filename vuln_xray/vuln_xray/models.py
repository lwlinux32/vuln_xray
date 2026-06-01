"""Core data models for vulnerability scanning."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class VulnerabilityType(Enum):
    """Types of vulnerabilities detectable by VulnX-Ray."""
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting"
    RCE = "Remote Code Execution"
    FILE_UPLOAD = "File Upload"
    SSRF = "Server-Side Request Forgery"
    LOGIC_FLAWS = "Logic Flaws"
    PATH_TRAVERSAL = "Path Traversal"
    AUTH_BYPASS = "Authentication Bypass"
    DESERIALIZATION = "Deserialization"
    COMMAND_INJECTION = "Command Injection"


class Severity(Enum):
    """Severity levels for vulnerabilities."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Payload:
    """Represents a test payload for fuzzing."""
    name: str
    value: str
    category: str
    encoding: str = "urlencoded"
    boolean: bool = False  # Boolean-based blind SQLi payloads


@dataclass
class Vulnerability:
    """Represents a detected vulnerability."""
    type: VulnerabilityType
    target: str
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    parameter: Optional[str] = None
    payload: Optional[str] = None
    response: Optional[Dict[str, Any]] = None
    confidence: float = 0.0
    severity: Severity = Severity.MEDIUM
    description: str = ""
    proof_of_concept: Optional[str] = None
    mitigation: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """A finding represents a specific instance of a vulnerability with evidence."""
    vulnerability: Vulnerability
    evidence: Dict[str, Any] = field(default_factory=dict)
    fingerprint: Optional[str] = None
    tools_suggested: List[str] = field(default_factory=list)
    poc_snippet: Optional[str] = None
    complexity_score: float = 0.0
    additional_notes: str = ""


class ScanResult:
    """Container for complete scan results."""
    def __init__(self, target: str, start_time: datetime = None):
        self.target = target
        self.start_time = start_time or datetime.now()
        self.end_time: Optional[datetime] = None
        self.findings: List[Finding] = []
        self.fingerprints: Dict[str, str] = {}  # Technology -> version
        self.request_stats: Dict[str, int] = {}  # Method -> count
        self.errors: List[str] = []

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_fingerprint(self, technology: str, version: str) -> None:
        self.fingerprints[technology] = version

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "target_url": self.target,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": (self.end_time - self.start_time).total_seconds() if self.end_time else None,
            "findings": [f.to_dict() for f in self.findings],
            "fingerprints": self.fingerprints,
            "statistics": {
                "total_findings": len(self.findings),
                "by_severity": {
                    "critical": len([f for f in self.findings if f.vulnerability.severity == Severity.CRITICAL]),
                    "high": len([f for f in self.findings if f.vulnerability.severity == Severity.HIGH]),
                    "medium": len([f for f in self.findings if f.vulnerability.severity == Severity.MEDIUM]),
                    "low": len([f for f in self.findings if f.vulnerability.severity == Severity.LOW]),
                }
            }
        }

    def add_error(self, error: str) -> None:
        self.errors.append(error)


class Finding:
    """Represents a specific vulnerability finding with detailed evidence."""

    def __init__(
        self,
        vulnerability: Vulnerability,
        evidence: Dict[str, Any] = None,
        fingerprint: str = None,
        tools_suggested: List[str] = None,
        poc_snippet: str = None,
        complexity_score: float = 0.0,
        additional_notes: str = ""
    ):
        self.vulnerability = vulnerability
        self.evidence = evidence or {}
        self.fingerprint = fingerprint
        self.tools_suggested = tools_suggested or []
        self.poc_snippet = poc_snippet
        self.complexity_score = complexity_score
        self.additional_notes = additional_notes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.vulnerability.id,
            "vulnerability": {
                "type": self.vulnerability.type.value,
                "target": self.vulnerability.target,
                "parameter": self.vulnerability.parameter,
                "confidence": self.vulnerability.confidence,
                "severity": self.vulnerability.severity.value,
                "description": self.vulnerability.description,
            },
            "evidence": self.evidence,
            "fingerprint": self.fingerprint,
            "tools_suggested": self.tools_suggested,
            "poc_snippet": self.poc_snippet,
            "complexity_score": self.complexity_score,
            "additional_notes": self.additional_notes,
        }
