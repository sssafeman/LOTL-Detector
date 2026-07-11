"""
macOS event collector: parses Endpoint Security exec events (eslogger).

Reads newline-delimited JSON produced by `eslogger exec` and emits the
standardized Event objects the detection engine consumes. Mirrors the
Linux and Windows collector interfaces, including events_from_lines and
events_from_text hooks for incremental ingestion.
"""
from pathlib import Path
from datetime import datetime
from typing import Any, List
from collectors.base import BaseCollector, Event
from collectors.macos.parser import parse_exec_event, parse_es_timestamp, split_ndjson
import logging

logger = logging.getLogger(__name__)


class MacOSCollector(BaseCollector):
    """
    Collector for macOS Endpoint Security exec events in NDJSON form.
    """

    def get_platform(self) -> str:
        """Return platform identifier."""
        return "macos"

    def collect_events(self, source: str, start_time: datetime = None,
                       end_time: datetime = None) -> List[Event]:
        """
        Collect exec events from an eslogger NDJSON file or directory.

        Args:
            source: Path to a .json/.ndjson/.log file or a directory of them
            start_time: Optional lower time bound
            end_time: Optional upper time bound

        Returns:
            List of Event objects
        """
        self.validate_source(source)
        source_path = Path(source)
        events: List[Event] = []

        if source_path.is_file():
            events.extend(self._parse_file(source_path))
        elif source_path.is_dir():
            files = (
                sorted(source_path.glob("*.ndjson"))
                + sorted(source_path.glob("*.json"))
                + sorted(source_path.glob("*.log"))
            )
            if not files:
                logger.warning(f"No macOS log files found in directory: {source_path}")
            for f in files:
                try:
                    events.extend(self._parse_file(f))
                except Exception as e:
                    logger.error(f"Failed to parse {f}: {e}")

        if start_time or end_time:
            events = self.filter_events_by_time(events, start_time, end_time)

        logger.info(f"Collected {len(events)} events from {source}")
        return events

    def _parse_file(self, file_path: Path) -> List[Event]:
        """Parse a single NDJSON file of ES exec events."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception as e:
            logger.error(f"Failed to read macOS log {file_path}: {e}")
            raise
        events = self.events_from_lines(lines)
        logger.debug(f"Parsed {len(events)} events from {file_path}")
        return events

    def events_from_lines(self, lines: List[str]) -> List[Event]:
        """
        Parse events from NDJSON lines. Shared with incremental ingestion.

        Args:
            lines: Raw NDJSON lines (with or without trailing newlines)

        Returns:
            List of Event objects
        """
        events: List[Event] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                event = self.parse_event(line)
                if event:
                    events.append(event)
            except ValueError as e:
                logger.debug(f"Skipping ES record: {e}")
            except Exception as e:
                logger.debug(f"Failed to parse ES record: {e}")
        return events

    def events_from_text(self, text: str):
        """
        Parse events from an NDJSON text buffer for incremental ingestion.

        NDJSON records are single lines, so the whole complete-line buffer
        is consumed. Returns (events, consumed_chars) for the ingest layer.
        """
        return self.events_from_lines(split_ndjson(text)), len(text)

    def parse_event(self, raw_event: Any) -> Event:
        """
        Parse one ES exec event (JSON string or dict) into an Event.

        Args:
            raw_event: JSON string or dict for one ES exec event

        Returns:
            Event object

        Raises:
            ValueError: If the record is not a usable exec event
        """
        fields = parse_exec_event(raw_event)
        if fields is None:
            raise ValueError("Not a usable ES exec event")

        return Event(
            timestamp=parse_es_timestamp(fields["timestamp"]),
            platform="macos",
            process_name=fields["process_name"],
            command_line=fields["command_line"],
            user=fields["user"],
            process_id=fields["process_id"],
            parent_process_name=fields["parent_process_name"],
            parent_process_id=fields["parent_process_id"],
            working_directory=fields["working_directory"],
            raw_data=fields["raw"],
        )
