"""
Structured and sanitized logging configuration for CloudGuard.
Ensures sensitive tokens, passwords, and private parameters are redacted.
"""
import logging
import re
import sys

# Patterns to redact
REDACTION_PATTERNS = [
    (re.compile(r'(authorization:\s*(?:bearer|basic)\s+)[^\s,]+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(token[=:\s"]+)[^"&\s]+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(password[=:\s"]+)[^"&\s]+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(api[-_]?key[=:\s"]+)[^"&\s]+', re.IGNORECASE), r'\1[REDACTED]'),
    (re.compile(r'(secret[=:\s"]+)[^"&\s]+', re.IGNORECASE), r'\1[REDACTED]'),
]


class SensitiveDataFilter(logging.Filter):
    """Filters log messages and redacts sensitive credentials and tokens."""
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            msg = record.msg
            for pattern, replacement in REDACTION_PATTERNS:
                msg = pattern.sub(replacement, msg)
            record.msg = msg
        return True


def setup_logging():
    logger = logging.getLogger("cloudguard")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        handler.addFilter(SensitiveDataFilter())
        logger.addHandler(handler)

    return logger


logger = setup_logging()
