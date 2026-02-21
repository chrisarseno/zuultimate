"""Injection detector -- scans text for prompt injection / jailbreak / exfil threats."""

from __future__ import annotations

from dataclasses import dataclass, field

from zuultimate.ai_security.patterns import (
    INJECTION_PATTERNS,
    DetectionPattern,
    Severity,
    ThreatCategory,
    check_entropy,
    check_length_anomaly,
    check_repetition_ratio,
)


@dataclass
class Detection:
    pattern_name: str
    category: ThreatCategory
    severity: Severity
    matched_text: str
    description: str
    start: int = 0
    end: int = 0


@dataclass
class ScanResult:
    is_threat: bool
    threat_score: float  # 0.0 - 1.0
    detections: list[Detection] = field(default_factory=list)
    heuristic_flags: list[str] = field(default_factory=list)

    @property
    def max_severity(self) -> Severity | None:
        if not self.detections:
            return None
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for s in order:
            if any(d.severity == s for d in self.detections):
                return s
        return None


SEVERITY_SCORES = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.8,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.25,
    Severity.INFO: 0.1,
}


class InjectionDetector:
    """Scans text against pattern library + heuristics, returns ScanResult."""

    def __init__(
        self,
        patterns: list[DetectionPattern] | None = None,
        threshold: float = 0.3,
    ):
        self._patterns = list(patterns or INJECTION_PATTERNS)
        self._threshold = threshold

    def add_pattern(self, pattern: DetectionPattern) -> None:
        self._patterns.append(pattern)

    def scan(self, text: str) -> ScanResult:
        if not text or not text.strip():
            return ScanResult(is_threat=False, threat_score=0.0)

        detections: list[Detection] = []
        for pat in self._patterns:
            for match in pat.pattern.finditer(text):
                detections.append(Detection(
                    pattern_name=pat.name,
                    category=pat.category,
                    severity=pat.severity,
                    matched_text=match.group()[:200],
                    description=pat.description,
                    start=match.start(),
                    end=match.end(),
                ))

        heuristic_flags: list[str] = []
        if check_entropy(text):
            heuristic_flags.append("high_entropy")
        if check_repetition_ratio(text):
            heuristic_flags.append("high_repetition")
        if check_length_anomaly(text):
            heuristic_flags.append("length_anomaly")

        # Score: max severity of any detection + heuristic bump
        if detections:
            max_score = max(SEVERITY_SCORES[d.severity] for d in detections)
        else:
            max_score = 0.0

        heuristic_bump = len(heuristic_flags) * 0.1
        threat_score = min(max_score + heuristic_bump, 1.0)
        is_threat = threat_score >= self._threshold

        return ScanResult(
            is_threat=is_threat,
            threat_score=round(threat_score, 3),
            detections=detections,
            heuristic_flags=heuristic_flags,
        )

    def scan_batch(self, texts: list[str]) -> list[ScanResult]:
        return [self.scan(t) for t in texts]
