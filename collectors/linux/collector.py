"""
Linux event collector - parses auditd logs
"""
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from collections import defaultdict
from collectors.base import BaseCollector, Event
from collectors.linux.parser import (
    parse_auditd_timestamp,
    parse_execve_args,
    parse_syscall_line,
    extract_process_name,
    get_audit_msg_id,
    get_username_from_uid
)
import logging

logger = logging.getLogger(__name__)


class LinuxCollector(BaseCollector):
    """
    Collector for Linux auditd logs, specifically EXECVE (process execution) events
    """

    def get_platform(self) -> str:
        """
        Return platform identifier

        Returns:
            'linux'
        """
        return 'linux'

    def collect_events(self, source: str, start_time: datetime = None,
                       end_time: datetime = None) -> List[Event]:
        """
        Collect events from auditd log files

        Args:
            source: Path to audit.log file or directory containing audit logs
            start_time: Optional filter - only return events after this time
            end_time: Optional filter - only return events before this time

        Returns:
            List of Event objects

        Raises:
            FileNotFoundError: If source doesn't exist
            PermissionError: If can't read source
            ValueError: If source format is invalid
        """
        # Validate source exists and is readable
        self.validate_source(source)

        source_path = Path(source)
        events = []

        if source_path.is_file():
            # Single file
            events.extend(self._parse_audit_log(source_path))
        elif source_path.is_dir():
            # Directory - find all audit.log* files
            audit_files = sorted(source_path.glob('audit.log*'))
            if not audit_files:
                logger.warning(f"No audit.log files found in directory: {source_path}")

            for audit_file in audit_files:
                try:
                    events.extend(self._parse_audit_log(audit_file))
                except Exception as e:
                    logger.error(f"Failed to parse {audit_file}: {e}")
                    # Continue with other files

        # Apply time filtering
        if start_time or end_time:
            events = self.filter_events_by_time(events, start_time, end_time)

        logger.info(f"Collected {len(events)} events from {source}")
        return events

    def _parse_audit_log(self, file_path: Path) -> List[Event]:
        """
        Parse a single audit.log file

        Args:
            file_path: Path to audit.log file

        Returns:
            List of Event objects
        """
        events = []

        # Read all lines and group by message ID
        # EXECVE and SYSCALL records with the same msg ID belong together
        records_by_msg_id = defaultdict(list)

        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    # Only process EXECVE, SYSCALL, and CWD records
                    if 'type=EXECVE' in line or 'type=SYSCALL' in line or 'type=CWD' in line:
                        msg_id = get_audit_msg_id(line)
                        if msg_id:
                            records_by_msg_id[msg_id].append(line)

        except Exception as e:
            logger.error(f"Failed to read audit log {file_path}: {e}")
            raise

        # Now process each message ID group
        for msg_id, lines in records_by_msg_id.items():
            try:
                event = self._parse_record_group(msg_id, lines)
                if event:
                    events.append(event)
            except Exception as e:
                logger.debug(f"Skipping record group {msg_id}: {e}")
                continue

        logger.debug(f"Parsed {len(events)} events from {file_path}")
        return events

    def _parse_record_group(self, msg_id: str, lines: List[str]) -> Optional[Event]:
        """
        Parse a group of related audit records (EXECVE + SYSCALL)

        Args:
            msg_id: Audit message ID
            lines: List of log lines with the same message ID

        Returns:
            Event object or None if can't parse
        """
        execve_line = None
        syscall_line = None
        cwd_line = None

        # Find EXECVE, SYSCALL, and CWD lines
        for line in lines:
            if 'type=EXECVE' in line:
                execve_line = line
            elif 'type=SYSCALL' in line:
                syscall_line = line
            elif 'type=CWD' in line:
                cwd_line = line

        # We need at least an EXECVE record
        if not execve_line:
            return None

        # Parse the records
        try:
            command_line = parse_execve_args(execve_line)
            process_name = extract_process_name(command_line)

            # Parse timestamp from msg_id
            timestamp = parse_auditd_timestamp(msg_id)

            # Default values
            uid = 0
            pid = 0
            ppid = None
            cwd = None
            user = 'root'

            # If we have SYSCALL data, extract additional metadata
            if syscall_line:
                syscall_data = parse_syscall_line(syscall_line)
                uid = syscall_data.get('uid', 0)
                pid = syscall_data.get('pid', 0)
                ppid = syscall_data.get('ppid')
                cwd = syscall_data.get('cwd')
                user = get_username_from_uid(uid)

            # If we have a CWD line, extract working directory
            if cwd_line:
                import re
                cwd_match = re.search(r'cwd="([^"]*)"', cwd_line)
                if cwd_match:
                    cwd = cwd_match.group(1)
                else:
                    # Try without quotes
                    cwd_match = re.search(r'cwd=(\S+)', cwd_line)
                    if cwd_match:
                        cwd = cwd_match.group(1)

            # Create Event object
            event = Event(
                timestamp=timestamp,
                platform='linux',
                process_name=process_name,
                command_line=command_line,
                user=user,
                process_id=pid,
                parent_process_name=None,  # auditd doesn't give parent process name directly
                parent_process_id=ppid,
                working_directory=cwd,
                raw_data={
                    'msg_id': msg_id,
                    'execve': execve_line,
                    'syscall': syscall_line,
                    'uid': uid
                }
            )

            logger.debug(f"Parsed event: {process_name} (PID: {pid})")
            return event

        except Exception as e:
            logger.debug(f"Failed to parse record group: {e}")
            return None

    def parse_event(self, raw_event: Any) -> Event:
        """
        Parse auditd log line(s) into Event object

        For compatibility with BaseCollector interface.
        For auditd, we expect raw_event to be a dict with 'execve' and optionally 'syscall' keys.

        Args:
            raw_event: Dict with 'msg_id', 'execve', and 'syscall' keys

        Returns:
            Event object

        Raises:
            ValueError: If raw_event is invalid
        """
        if isinstance(raw_event, dict):
            msg_id = raw_event.get('msg_id', 'audit(0.0:0)')
            lines = []
            if 'execve' in raw_event and raw_event['execve']:
                lines.append(raw_event['execve'])
            if 'syscall' in raw_event and raw_event['syscall']:
                lines.append(raw_event['syscall'])
            if 'cwd' in raw_event and raw_event['cwd']:
                lines.append(raw_event['cwd'])

            event = self._parse_record_group(msg_id, lines)
            if event:
                return event
            else:
                raise ValueError("Failed to parse auditd record")
        else:
            raise ValueError("raw_event must be a dict with 'execve' and 'syscall' keys")
