"""
Helper functions for parsing Linux auditd logs
"""
import re
from datetime import datetime
from typing import Dict, Any, Optional, List
import logging

logger = logging.getLogger(__name__)


def parse_auditd_timestamp(audit_timestamp: str) -> datetime:
    """
    Parse auditd timestamp to datetime object

    Auditd timestamps are in format: audit(1234567890.123:456)
    where 1234567890.123 is Unix epoch time with milliseconds

    Args:
        audit_timestamp: Timestamp string from auditd (e.g., "1642253400.123:456")

    Returns:
        datetime object

    Raises:
        ValueError: If timestamp format is invalid
    """
    if not audit_timestamp:
        raise ValueError("Empty timestamp string")

    # Extract timestamp from msg=audit(TIMESTAMP:SEQUENCE)
    match = re.search(r'audit\((\d+\.\d+):\d+\)', audit_timestamp)
    if match:
        epoch_str = match.group(1)
    else:
        # Try direct epoch format
        try:
            epoch_str = audit_timestamp
            float(epoch_str)  # Validate it's a number
        except ValueError:
            raise ValueError(f"Could not parse audit timestamp: {audit_timestamp}")

    try:
        epoch_time = float(epoch_str)
        return datetime.fromtimestamp(epoch_time)
    except (ValueError, OSError) as e:
        raise ValueError(f"Invalid epoch timestamp: {epoch_str}: {e}")


def parse_execve_args(line: str) -> str:
    """
    Parse EXECVE arguments and reconstruct the command line

    EXECVE format: type=EXECVE msg=audit(...): argc=3 a0="curl" a1="-O" a2="http://..."

    Args:
        line: EXECVE log line

    Returns:
        Reconstructed command line string

    Raises:
        ValueError: If line is not a valid EXECVE record
    """
    if 'type=EXECVE' not in line:
        raise ValueError("Not an EXECVE record")

    # Extract argc to know how many arguments to expect
    argc_match = re.search(r'argc=(\d+)', line)
    if not argc_match:
        raise ValueError("Missing argc in EXECVE record")

    argc = int(argc_match.group(1))

    # Extract all a0, a1, a2... arguments
    args = []
    for i in range(argc):
        # Match a0="value" or a0=value (with or without quotes)
        pattern = rf'a{i}="([^"]*)"'
        match = re.search(pattern, line)
        if match:
            args.append(match.group(1))
        else:
            # Try without quotes
            pattern = rf'a{i}=(\S+)'
            match = re.search(pattern, line)
            if match:
                value = match.group(1)
                # Remove trailing quote if present
                value = value.rstrip('"')
                args.append(value)
            else:
                logger.warning(f"Missing argument a{i} in EXECVE record")

    # Join arguments with spaces
    command_line = ' '.join(args)
    return command_line


def parse_syscall_line(line: str) -> Dict[str, Any]:
    """
    Parse SYSCALL record to extract metadata

    SYSCALL format: type=SYSCALL msg=audit(...): ... uid=1000 ppid=1234 cwd="/home/user" ...

    Args:
        line: SYSCALL log line

    Returns:
        Dictionary with uid, ppid, cwd, pid, exe

    Raises:
        ValueError: If line is not a valid SYSCALL record
    """
    if 'type=SYSCALL' not in line:
        raise ValueError("Not a SYSCALL record")

    result = {}

    # Extract uid
    uid_match = re.search(r'\buid=(\d+)', line)
    if uid_match:
        result['uid'] = int(uid_match.group(1))

    # Extract ppid (parent process ID)
    ppid_match = re.search(r'\bppid=(\d+)', line)
    if ppid_match:
        result['ppid'] = int(ppid_match.group(1))

    # Extract pid
    pid_match = re.search(r'\bpid=(\d+)', line)
    if pid_match:
        result['pid'] = int(pid_match.group(1))

    # Extract cwd (current working directory)
    cwd_match = re.search(r'cwd="([^"]*)"', line)
    if cwd_match:
        result['cwd'] = cwd_match.group(1)
    else:
        # Try without quotes
        cwd_match = re.search(r'cwd=(\S+)', line)
        if cwd_match:
            result['cwd'] = cwd_match.group(1)

    # Extract exe (executable path)
    exe_match = re.search(r'exe="([^"]*)"', line)
    if exe_match:
        result['exe'] = exe_match.group(1)
    else:
        # Try without quotes
        exe_match = re.search(r'exe=(\S+)', line)
        if exe_match:
            result['exe'] = exe_match.group(1)

    return result


def extract_process_name(command: str) -> str:
    """
    Extract process name from command line

    Args:
        command: Full command line (e.g., "/usr/bin/curl -O http://...")

    Returns:
        Just the executable name (e.g., "curl")
    """
    if not command:
        return ''

    # Get first argument (the executable)
    parts = command.split()
    if not parts:
        return ''

    executable = parts[0]

    # Extract basename from path
    if '/' in executable:
        return executable.split('/')[-1]

    return executable


def get_audit_msg_id(line: str) -> Optional[str]:
    """
    Extract the audit message ID from a log line

    The message ID is used to correlate EXECVE and SYSCALL records

    Args:
        line: Auditd log line

    Returns:
        Message ID (e.g., "audit(1642253400.123:456)") or None
    """
    match = re.search(r'msg=(audit\([^)]+\))', line)
    if match:
        return match.group(1)
    return None


def get_username_from_uid(uid: int) -> str:
    """
    Convert UID to username

    Args:
        uid: User ID

    Returns:
        Username or uid as string if lookup fails
    """
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError):
        # pwd module not available or uid not found
        return str(uid)
