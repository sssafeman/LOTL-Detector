"""
Command line anomaly analyzer.

Detects suspicious patterns in command lines that indicate malicious intent.
Returns indicator names used by the v2 scoring system to compute confidence.

Each category counts once even if multiple patterns within it match.
The scorer caps the total anomaly delta at COMMAND_ANOMALY_CAP.
"""
import re
import math
import logging
from typing import List, Set

logger = logging.getLogger(__name__)


# Indicator categories with their detection patterns.
# Each category is a list of (pattern, description) tuples.
# Substring matches are case-insensitive. Regex patterns use re.IGNORECASE.

_ENCODED_PATTERNS = [
    "-encodedcommand",
    "-enc ",
    "frombase64string",
    "certutil -decode",
    "certutil -f -decode",
    "base64 -d",
    "base64 --decode",
]

_DOWNLOAD_CRADLE_PATTERNS = [
    "invoke-expression",
    "iex ",
    "downloadstring",
    "downloadfile",
    "net.webclient",
    "start-bitstransfer",
    "invoke-webrequest",
    "invoke-restmethod",
    "curl",
    "wget",
    "regsvr32 /u /s /i",
    "mshta http",
    "mshta https",
]

_OBFUSCATION_PATTERNS = [
    # PowerShell backtick escaping
    re.compile(r'`[a-z]', re.IGNORECASE),
    # Caret escaping in cmd
    re.compile(r'\^[a-zA-Z]{2,}'),
    # Environment variable reconstruction: $env:, ${env:
    "${env:",
    "$env:",
    # Character code reconstruction: [char], [convert]::toint
    "[char]",
    "[convert]",
    # String concatenation to build command names
    re.compile(r"'[a-z]'\s*\+\s*'[a-z]'", re.IGNORECASE),
]

_UNUSUAL_PATH_PATTERNS = [
    "\\temp\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\users\\public\\",
    "\\$recycle.bin\\",
    "\\\\webdav",
    "\\\\@",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
]

_SUSPICIOUS_FLAGS = [
    "-windowstyle hidden",
    "-w hidden",
    "-noninteractive",
    "-nop",
    "-executionpolicy bypass",
    "-ep bypass",
    "-exec bypass",
    "/u /s /i",
    "squiblydoo",
    "-sta",
    "-encodedcommand",
]

# Regex patterns for entropy calculation
_LONG_TOKEN_RE = re.compile(r'[A-Za-z0-9+/=]{80,}')


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not data:
        return 0.0
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return entropy


def _check_encoded(command_line: str) -> bool:
    """Check for encoded payload or command indicators."""
    lower = command_line.lower()
    return any(pattern in lower for pattern in _ENCODED_PATTERNS)


def _check_download_cradle(command_line: str) -> bool:
    """Check for download or execution cradle indicators."""
    lower = command_line.lower()
    return any(pattern in lower for pattern in _DOWNLOAD_CRADLE_PATTERNS)


def _check_obfuscation(command_line: str) -> bool:
    """Check for obfuscation or escaping indicators."""
    for pattern in _OBFUSCATION_PATTERNS:
        if isinstance(pattern, str):
            if pattern in command_line.lower():
                return True
        else:
            if pattern.search(command_line):
                return True
    return False


def _check_unusual_path(command_line: str) -> bool:
    """Check for unusual executable or payload path."""
    lower = command_line.lower()
    return any(pattern in lower for pattern in _UNUSUAL_PATH_PATTERNS)


def _check_suspicious_flags(command_line: str) -> bool:
    """Check for suspicious hidden or bypass flags."""
    lower = command_line.lower()
    return any(pattern in lower for pattern in _SUSPICIOUS_FLAGS)


def _check_high_entropy(command_line: str) -> bool:
    """Check for long or high entropy arguments."""
    # Check argument length >= 300 characters
    if len(command_line) >= 300:
        return True
    # Check for tokens >= 80 chars with entropy >= 4.5 bits/char
    for match in _LONG_TOKEN_RE.findall(command_line):
        if _shannon_entropy(match) >= 4.5:
            return True
    return False


def analyze_command(command_line: str) -> List[str]:
    """
    Analyze a command line for anomaly indicators.

    Args:
        command_line: The full command line string to analyze

    Returns:
        List of detected indicator category names. Each category appears
        at most once. Categories:
          - encoded_payload
          - download_cradle
          - obfuscation
          - unusual_path
          - suspicious_flags
          - high_entropy_argument
    """
    if not command_line:
        return []

    indicators: Set[str] = set()

    if _check_encoded(command_line):
        indicators.add("encoded_payload")

    if _check_download_cradle(command_line):
        indicators.add("download_cradle")

    if _check_obfuscation(command_line):
        indicators.add("obfuscation")

    if _check_unusual_path(command_line):
        indicators.add("unusual_path")

    if _check_suspicious_flags(command_line):
        indicators.add("suspicious_flags")

    if _check_high_entropy(command_line):
        indicators.add("high_entropy_argument")

    result = sorted(indicators)
    if result:
        logger.debug(f"Command anomalies detected: {result}")
    return result
