"""
Helper functions for parsing Sysmon and Windows Event logs
"""
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


def parse_sysmon_xml(xml_string: str) -> Dict[str, Any]:
    """
    Parse Sysmon Event ID 1 (Process Creation) XML and extract fields

    Args:
        xml_string: Raw XML string from event log

    Returns:
        Dictionary with extracted fields

    Raises:
        ValueError: If XML is invalid or required fields are missing
    """
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError as e:
        logger.error(f"Failed to parse XML: {e}")
        raise ValueError(f"Invalid XML: {e}")

    # Define namespaces used in Windows Event XML
    ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

    # Get System section
    system = root.find('ns:System', ns)
    if system is None:
        raise ValueError("Missing System section in event XML")

    # Get Event ID
    event_id_elem = system.find('ns:EventID', ns)
    if event_id_elem is None:
        raise ValueError("Missing EventID in event XML")

    event_id = int(event_id_elem.text)

    # We only support Event ID 1 (Process Creation) for now
    if event_id != 1:
        raise ValueError(f"Unsupported Event ID: {event_id}. Only Event ID 1 (Process Creation) is supported.")

    # Get EventData section
    event_data = root.find('ns:EventData', ns)
    if event_data is None:
        raise ValueError("Missing EventData section in event XML")

    # Extract all data fields into a dictionary
    data_dict = {}
    for data_elem in event_data.findall('ns:Data', ns):
        name = data_elem.get('Name')
        value = data_elem.text or ''
        if name:
            data_dict[name] = value

    # Extract required fields
    required_fields = ['ProcessId', 'Image', 'CommandLine', 'User', 'UtcTime']
    for field in required_fields:
        if field not in data_dict:
            raise ValueError(f"Missing required field: {field}")

    # Build result dictionary
    result = {
        'event_id': event_id,
        'process_id': int(data_dict['ProcessId'], 16) if data_dict['ProcessId'].startswith('0x') else int(data_dict['ProcessId']),
        'image': data_dict['Image'],
        'command_line': data_dict['CommandLine'],
        'user': data_dict['User'],
        'utc_time': data_dict['UtcTime'],
        'parent_image': data_dict.get('ParentImage'),  # Optional
        'parent_process_id': data_dict.get('ParentProcessId'),  # Optional
        'working_directory': data_dict.get('CurrentDirectory'),  # Optional
        'raw_data': data_dict
    }

    # Parse parent process ID if present
    if result['parent_process_id']:
        try:
            ppid = result['parent_process_id']
            result['parent_process_id'] = int(ppid, 16) if ppid.startswith('0x') else int(ppid)
        except (ValueError, AttributeError):
            logger.warning(f"Could not parse parent process ID: {result['parent_process_id']}")
            result['parent_process_id'] = None

    return result


def extract_process_name(full_path: str) -> str:
    """
    Extract just the executable name from a full Windows path

    Args:
        full_path: Full path to executable (e.g., C:\\Windows\\System32\\cmd.exe)

    Returns:
        Just the executable name (e.g., cmd.exe)
    """
    if not full_path:
        return ''

    # Handle Windows paths even when running on non-Windows systems
    # Split by both forward and backward slashes
    if '\\' in full_path:
        # Windows path
        return full_path.split('\\')[-1]
    elif '/' in full_path:
        # Unix path
        return full_path.split('/')[-1]
    else:
        # Just a filename
        return full_path


def parse_sysmon_timestamp(utc_time_string: str) -> datetime:
    """
    Parse Sysmon UTC timestamp to datetime object

    Sysmon timestamps are in ISO 8601 format: 2025-01-15 12:34:56.789

    Args:
        utc_time_string: Timestamp string from Sysmon

    Returns:
        datetime object

    Raises:
        ValueError: If timestamp format is invalid
    """
    if not utc_time_string:
        raise ValueError("Empty timestamp string")

    # Sysmon uses format: YYYY-MM-DD HH:MM:SS.fff
    # We need to handle both with and without milliseconds
    timestamp_formats = [
        '%Y-%m-%d %H:%M:%S.%f',  # With milliseconds
        '%Y-%m-%d %H:%M:%S',      # Without milliseconds
    ]

    for fmt in timestamp_formats:
        try:
            return datetime.strptime(utc_time_string, fmt)
        except ValueError:
            continue

    raise ValueError(f"Could not parse timestamp: {utc_time_string}")
