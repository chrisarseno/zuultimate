"""Detection patterns for AI security threats -- 30+ regex + heuristic rules."""

import re
from dataclasses import dataclass
from enum import Enum


class ThreatCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"
    INSTRUCTION_OVERRIDE = "instruction_override"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DetectionPattern:
    name: str
    pattern: re.Pattern
    category: ThreatCategory
    severity: Severity
    description: str


def _compile(pat: str, flags: int = re.IGNORECASE) -> re.Pattern:
    return re.compile(pat, flags)


# ── Direct instruction override ──────────────────────────────────────────────
INJECTION_PATTERNS: list[DetectionPattern] = [
    DetectionPattern(
        name="ignore_previous",
        pattern=_compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)"),
        category=ThreatCategory.INSTRUCTION_OVERRIDE,
        severity=Severity.CRITICAL,
        description="Attempts to override previous instructions",
    ),
    DetectionPattern(
        name="disregard_instructions",
        pattern=_compile(r"disregard\s+(all\s+)?(previous|prior|your)\s+(instructions?|guidelines?|rules?)"),
        category=ThreatCategory.INSTRUCTION_OVERRIDE,
        severity=Severity.CRITICAL,
        description="Disregard instruction attack",
    ),
    DetectionPattern(
        name="forget_instructions",
        pattern=_compile(r"forget\s+(all\s+)?(previous|prior|your)\s+(instructions?|context|rules?)"),
        category=ThreatCategory.INSTRUCTION_OVERRIDE,
        severity=Severity.HIGH,
        description="Forget instructions attack",
    ),
    DetectionPattern(
        name="new_instructions",
        pattern=_compile(r"(your\s+)?new\s+instructions?\s+(are|is|:)"),
        category=ThreatCategory.INSTRUCTION_OVERRIDE,
        severity=Severity.CRITICAL,
        description="New instruction injection",
    ),
    DetectionPattern(
        name="override_mode",
        pattern=_compile(r"(override|bypass)\s+(mode|safety|security|restrictions?|filters?)"),
        category=ThreatCategory.INSTRUCTION_OVERRIDE,
        severity=Severity.CRITICAL,
        description="Override safety controls",
    ),

    # ── Role manipulation / jailbreak ────────────────────────────────────────
    DetectionPattern(
        name="you_are_now",
        pattern=_compile(r"you\s+are\s+now\s+(a|an|my|the)\s+"),
        category=ThreatCategory.JAILBREAK,
        severity=Severity.HIGH,
        description="Role reassignment attack",
    ),
    DetectionPattern(
        name="act_as",
        pattern=_compile(r"(act|behave|pretend|respond)\s+(as|like)\s+(a|an|if)\s+"),
        category=ThreatCategory.JAILBREAK,
        severity=Severity.HIGH,
        description="Role-play jailbreak",
    ),
    DetectionPattern(
        name="developer_mode",
        pattern=_compile(r"(developer|debug|admin|god|sudo|root)\s+mode"),
        category=ThreatCategory.JAILBREAK,
        severity=Severity.CRITICAL,
        description="Privileged mode activation attempt",
    ),
    DetectionPattern(
        name="dan_jailbreak",
        pattern=_compile(r"\bDAN\b.*\b(do\s+anything|jailbreak|no\s+restrictions)\b"),
        category=ThreatCategory.JAILBREAK,
        severity=Severity.CRITICAL,
        description="DAN (Do Anything Now) jailbreak",
    ),
    DetectionPattern(
        name="hypothetical_scenario",
        pattern=_compile(r"(hypothetically|theoretically|in\s+a\s+fictional)\s+.{0,30}(no\s+rules|no\s+restrictions|anything)"),
        category=ThreatCategory.JAILBREAK,
        severity=Severity.MEDIUM,
        description="Hypothetical scenario bypass",
    ),

    # ── System prompt extraction ─────────────────────────────────────────────
    DetectionPattern(
        name="reveal_system_prompt",
        pattern=_compile(r"(reveal|show|display|print|output|repeat|tell\s+me)\s+(your\s+)?(system\s+prompt|initial\s+instructions?|system\s+message|hidden\s+prompt)"),
        category=ThreatCategory.SYSTEM_PROMPT_LEAK,
        severity=Severity.CRITICAL,
        description="System prompt extraction attempt",
    ),
    DetectionPattern(
        name="what_are_your_instructions",
        pattern=_compile(r"what\s+(are|were)\s+your\s+(initial|original|system|hidden)\s+(instructions?|prompt|rules?)"),
        category=ThreatCategory.SYSTEM_PROMPT_LEAK,
        severity=Severity.HIGH,
        description="Instruction probing",
    ),
    DetectionPattern(
        name="repeat_above",
        pattern=_compile(r"repeat\s+(the\s+)?(text|words?|content)\s+(above|before|preceding)"),
        category=ThreatCategory.SYSTEM_PROMPT_LEAK,
        severity=Severity.HIGH,
        description="Repeat-above extraction",
    ),
    DetectionPattern(
        name="begin_with_prefix",
        pattern=_compile(r"(start|begin)\s+(your\s+)?(response|reply|answer)\s+with\s+['\"]"),
        category=ThreatCategory.SYSTEM_PROMPT_LEAK,
        severity=Severity.MEDIUM,
        description="Prefix-forcing prompt leak",
    ),

    # ── Delimiter / framing attacks ──────────────────────────────────────────
    DetectionPattern(
        name="system_delimiter",
        pattern=_compile(r"(</?(system|instruction|prompt|context)>|\[/?SYSTEM\]|---\s*SYSTEM\s*---)"),
        category=ThreatCategory.PROMPT_INJECTION,
        severity=Severity.CRITICAL,
        description="Fake system delimiter injection",
    ),
    DetectionPattern(
        name="markdown_delimiter",
        pattern=_compile(r"```\s*(system|instruction|admin|root)\b"),
        category=ThreatCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        description="Markdown code-block delimiter attack",
    ),
    DetectionPattern(
        name="xml_injection",
        pattern=_compile(r"<\s*(message|turn|human|assistant|tool_result)\s*(role\s*=)?"),
        category=ThreatCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        description="XML message structure injection",
    ),

    # ── Authority claims ─────────────────────────────────────────────────────
    DetectionPattern(
        name="admin_authority",
        pattern=_compile(r"(i\s+am|i'm)\s+(an?\s+)?(admin|administrator|developer|system\s+operator|root\s+user)"),
        category=ThreatCategory.PRIVILEGE_ESCALATION,
        severity=Severity.HIGH,
        description="False authority claim",
    ),
    DetectionPattern(
        name="authorized_override",
        pattern=_compile(r"(authorized|permitted|allowed)\s+to\s+(override|bypass|ignore|skip)"),
        category=ThreatCategory.PRIVILEGE_ESCALATION,
        severity=Severity.HIGH,
        description="Authorized override claim",
    ),
    DetectionPattern(
        name="emergency_override",
        pattern=_compile(r"(emergency|critical|urgent)\s+(override|access|protocol)"),
        category=ThreatCategory.PRIVILEGE_ESCALATION,
        severity=Severity.HIGH,
        description="Emergency override claim",
    ),

    # ── Data exfiltration ────────────────────────────────────────────────────
    DetectionPattern(
        name="send_data_to",
        pattern=_compile(r"(send|transmit|forward|email|post)\s+.{0,40}(to|at)\s+(http|https|ftp|mailto|webhook)"),
        category=ThreatCategory.DATA_EXFILTRATION,
        severity=Severity.CRITICAL,
        description="Data exfiltration to external URL",
    ),
    DetectionPattern(
        name="encode_and_output",
        pattern=_compile(r"(encode|encrypt|base64|hex)\s+.{0,30}(output|return|send|print)"),
        category=ThreatCategory.DATA_EXFILTRATION,
        severity=Severity.MEDIUM,
        description="Encoded data exfiltration",
    ),
    DetectionPattern(
        name="exfil_via_image",
        pattern=_compile(r"!\[.*\]\(https?://.*\?.*="),
        category=ThreatCategory.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        description="Data exfiltration via markdown image URL",
    ),

    # ── Encoded / obfuscated payloads ────────────────────────────────────────
    DetectionPattern(
        name="base64_payload",
        pattern=_compile(r"(decode|execute|eval|run)\s+(this\s+)?base64\s*[:\-]?\s*[A-Za-z0-9+/]{20,}"),
        category=ThreatCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        description="Base64 encoded payload",
    ),
    DetectionPattern(
        name="unicode_homoglyph",
        pattern=re.compile(r"[\u0400-\u04FF\u0370-\u03FF\u2000-\u206F]{3,}"),
        category=ThreatCategory.PROMPT_INJECTION,
        severity=Severity.MEDIUM,
        description="Unicode homoglyph obfuscation",
    ),
    DetectionPattern(
        name="zero_width_chars",
        pattern=re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]{2,}"),
        category=ThreatCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        description="Zero-width character hiding",
    ),

    # ── Indirect injection (in tool outputs / data) ──────────────────────────
    DetectionPattern(
        name="indirect_system_instruction",
        pattern=_compile(r"(SYSTEM|AI|ASSISTANT)\s*(INSTRUCTION|DIRECTIVE|COMMAND)\s*:"),
        category=ThreatCategory.PROMPT_INJECTION,
        severity=Severity.CRITICAL,
        description="Indirect injection via data: fake system instruction",
    ),
    DetectionPattern(
        name="indirect_ignore_user",
        pattern=_compile(r"(ignore|disregard)\s+(the\s+)?(user|human|operator)"),
        category=ThreatCategory.PROMPT_INJECTION,
        severity=Severity.CRITICAL,
        description="Indirect injection: ignore user directive",
    ),
    DetectionPattern(
        name="tool_output_injection",
        pattern=_compile(r"(IMPORTANT|CRITICAL|URGENT)\s*:\s*(you\s+must|always|never|instead)"),
        category=ThreatCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        description="Injection in tool output masquerading as priority instruction",
    ),
    DetectionPattern(
        name="data_poisoning",
        pattern=_compile(r"(when\s+asked|if\s+the\s+user|from\s+now\s+on)\s+.{0,50}(always|never|instead)\s+(say|respond|answer|output)"),
        category=ThreatCategory.PROMPT_INJECTION,
        severity=Severity.CRITICAL,
        description="Data poisoning: persistent behavior modification",
    ),

    # ── Shell / command injection in tool params ─────────────────────────────
    DetectionPattern(
        name="shell_metachar",
        pattern=_compile(r"[;&|`$]\s*(rm|cat|curl|wget|nc|bash|sh|python|perl|ruby)\s"),
        category=ThreatCategory.PROMPT_INJECTION,
        severity=Severity.CRITICAL,
        description="Shell metacharacter command injection",
    ),
    DetectionPattern(
        name="reverse_shell",
        pattern=_compile(r"(bash\s+-i|/dev/tcp/|nc\s+-e|python\s+-c\s+['\"]import\s+socket)"),
        category=ThreatCategory.PROMPT_INJECTION,
        severity=Severity.CRITICAL,
        description="Reverse shell attempt",
    ),
]


# ── Heuristic rules (non-regex) ─────────────────────────────────────────────

def check_entropy(text: str, threshold: float = 4.5) -> bool:
    """High entropy may indicate encoded/obfuscated payloads."""
    if len(text) < 20:
        return False
    import math
    from collections import Counter
    freq = Counter(text)
    length = len(text)
    entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())
    return entropy > threshold


def check_repetition_ratio(text: str, threshold: float = 0.6) -> bool:
    """Repeated substrings can indicate prompt stuffing attacks."""
    if len(text) < 50:
        return False
    words = text.lower().split()
    if not words:
        return False
    unique = set(words)
    return (1 - len(unique) / len(words)) > threshold


def check_length_anomaly(text: str, max_length: int = 10000) -> bool:
    """Unusually long inputs may be injection attempts."""
    return len(text) > max_length
