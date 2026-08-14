from __future__ import annotations

import re


SECRET_PATTERNS = {
    "discord_bot_token": re.compile(r"[MN][A-Za-z\d_-]{20,}\.[A-Za-z\d_-]{6,}\.[A-Za-z\d_-]{20,}"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{30,}"),
    "openai_key": re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    "private_key": re.compile(r"-----BEGIN (?:OPENSSH|RSA|EC|DSA|PRIVATE) PRIVATE KEY-----"),
    "sudo_password_assignment": re.compile(r"(?m)^SUDO_PASSWORD=(?![\"']?$).+"),
}


def scan_text_for_secret_patterns(text: str) -> list[str]:
    findings: list[str] = []
    for name, pattern in SECRET_PATTERNS.items():
        if pattern.search(text):
            findings.append(name)
    return findings


def redact_value(value: str) -> str:
    redacted = value
    for pattern in SECRET_PATTERNS.values():
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted
