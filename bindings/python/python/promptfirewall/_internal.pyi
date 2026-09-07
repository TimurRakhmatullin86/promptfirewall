from typing import Optional

class PiiFinding:
    entity_type: str
    start: int
    end: int
    text: str
    confidence: float

    def __repr__(self) -> str: ...
    def to_dict(self) -> dict[str, object]: ...

class ScanResult:
    is_safe: bool
    pii_findings: list[PiiFinding]
    injection_score: float
    injection_labels: list[str]
    redacted_text: Optional[str]
    latency_us: int

    def __repr__(self) -> str: ...
    def to_dict(self) -> dict[str, object]: ...

def scan(
    text: str,
    *,
    detect_pii: bool = True,
    detect_injection: bool = True,
    pii_types: Optional[list[str]] = None,
    injection_threshold: float = 0.7,
    redact: bool = False,
    redact_with: str = "mask",
) -> ScanResult: ...

def is_safe(text: str) -> bool: ...

def redact(
    text: str,
    *,
    redact_with: str = "mask",
    pii_types: Optional[list[str]] = None,
) -> str: ...

def detect_injection(
    text: str,
    *,
    threshold: float = 0.7,
) -> ScanResult: ...

def detect_pii(
    text: str,
    *,
    pii_types: Optional[list[str]] = None,
) -> ScanResult: ...
