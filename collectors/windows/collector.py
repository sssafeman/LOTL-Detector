"""
Windows event collector - parses Sysmon and Windows Event logs
"""
from pathlib import Path
from datetime import datetime
from typing import List, Any
from collectors.base import BaseCollector, Event
from collectors.windows.parser import (
    parse_sysmon_xml,
    extract_process_name,
    parse_sysmon_timestamp
)
import logging

logger = logging.getLogger(__name__)


class WindowsCollector(BaseCollector):
    """
    Collector for Windows event logs, specifically Sysmon Event ID 1 (Process Creation)
    """

    def get_platform(self) -> str:
        """
        Return platform identifier

        Returns:
            'windows'
        """
        return 'windows'

    def collect_events(self, source: str, start_time: datetime = None,
                       end_time: datetime = None) -> List[Event]:
        """
        Collect events from Windows event log files

        Args:
            source: Path to .evtx/.xml file or directory containing .evtx/.xml files
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
            # Single file - determine type by extension
            if source_path.suffix.lower() == '.evtx':
                events.extend(self._parse_evtx_file(source_path))
            elif source_path.suffix.lower() == '.xml':
                events.extend(self._parse_xml_file(source_path))
            else:
                logger.warning(f"Unknown file type: {source_path.suffix}")
        elif source_path.is_dir():
            # Directory - find all .evtx and .xml files
            evtx_files = list(source_path.glob('*.evtx'))
            xml_files = list(source_path.glob('*.xml'))

            all_files = evtx_files + xml_files

            if not all_files:
                logger.warning(f"No .evtx or .xml files found in directory: {source_path}")

            # Parse .evtx files
            for evtx_file in evtx_files:
                try:
                    events.extend(self._parse_evtx_file(evtx_file))
                except Exception as e:
                    logger.error(f"Failed to parse {evtx_file}: {e}")
                    # Continue with other files

            # Parse .xml files
            for xml_file in xml_files:
                try:
                    events.extend(self._parse_xml_file(xml_file))
                except Exception as e:
                    logger.error(f"Failed to parse {xml_file}: {e}")
                    # Continue with other files

        # Apply time filtering
        if start_time or end_time:
            events = self.filter_events_by_time(events, start_time, end_time)

        logger.info(f"Collected {len(events)} events from {source}")
        return events

    def _parse_evtx_file(self, file_path: Path) -> List[Event]:
        """
        Parse a single .evtx file

        Args:
            file_path: Path to .evtx file

        Returns:
            List of Event objects
        """
        events = []

        try:
            # Import here to make it optional (only needed when actually parsing)
            from Evtx import Evtx
        except ImportError:
            logger.error("python-evtx library not installed. Install with: pip install python-evtx")
            raise ImportError("python-evtx library is required for parsing .evtx files")

        try:
            with Evtx.Evtx(str(file_path)) as log:
                for record in log.records():
                    try:
                        xml_string = record.xml()
                        event = self.parse_event(xml_string)
                        if event:
                            events.append(event)
                    except ValueError as e:
                        # Skip events we can't parse (e.g., non-Event ID 1)
                        logger.debug(f"Skipping event: {e}")
                    except Exception as e:
                        logger.error(f"Error parsing event record: {e}")
                        continue

        except Exception as e:
            logger.error(f"Failed to open/read .evtx file {file_path}: {e}")
            raise

        logger.debug(f"Parsed {len(events)} events from {file_path}")
        return events

    def _parse_xml_file(self, file_path: Path) -> List[Event]:
        """
        Parse a single .xml file containing raw Sysmon XML

        Args:
            file_path: Path to .xml file containing Sysmon event XML

        Returns:
            List of Event objects
        """
        events = []

        try:
            # Read the raw XML content
            with open(file_path, 'r', encoding='utf-8') as f:
                xml_content = f.read()

            # Try to parse as a single event
            try:
                event = self.parse_event(xml_content)
                if event:
                    events.append(event)
            except ValueError as e:
                # Skip events we can't parse (e.g., non-Event ID 1)
                logger.debug(f"Skipping event in {file_path}: {e}")
            except Exception as e:
                logger.error(f"Error parsing XML file {file_path}: {e}")

        except Exception as e:
            logger.error(f"Failed to read XML file {file_path}: {e}")
            raise

        logger.debug(f"Parsed {len(events)} events from {file_path}")
        return events

    def parse_event(self, raw_event: Any) -> Event:
        """
        Parse Sysmon Event ID 1 XML into Event object

        Args:
            raw_event: Raw XML string from event log

        Returns:
            Event object

        Raises:
            ValueError: If XML is invalid or not Event ID 1
        """
        # Parse the XML
        parsed = parse_sysmon_xml(raw_event)

        # Extract process name from full path
        process_name = extract_process_name(parsed['image'])
        parent_process_name = extract_process_name(parsed['parent_image']) if parsed['parent_image'] else None

        # Parse timestamp
        timestamp = parse_sysmon_timestamp(parsed['utc_time'])

        # Create Event object
        event = Event(
            timestamp=timestamp,
            platform='windows',
            process_name=process_name,
            command_line=parsed['command_line'],
            user=parsed['user'],
            process_id=parsed['process_id'],
            parent_process_name=parent_process_name,
            parent_process_id=parsed['parent_process_id'],
            working_directory=parsed.get('working_directory'),
            raw_data={
                'xml': raw_event,
                'parsed': parsed['raw_data']
            }
        )

        logger.debug(f"Parsed event: {process_name} (PID: {parsed['process_id']})")
        return event
