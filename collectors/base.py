"""
Base collector class - all platform-specific collectors inherit from this
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


@dataclass
class Event:
    """
    Standardized event format across all platforms
    All collectors must produce Event objects
    """
    timestamp: datetime
    platform: str  # windows, linux, macos
    process_name: str
    command_line: str
    user: str
    process_id: int
    parent_process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    working_directory: Optional[str] = None
    
    # Additional context
    raw_data: Dict[str, Any] = None  # Original log entry
    
    def __post_init__(self):
        """Ensure raw_data is always a dict"""
        if self.raw_data is None:
            self.raw_data = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for storage/API"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'platform': self.platform,
            'process_name': self.process_name,
            'command_line': self.command_line,
            'user': self.user,
            'process_id': self.process_id,
            'parent_process_name': self.parent_process_name,
            'parent_process_id': self.parent_process_id,
            'working_directory': self.working_directory,
            'raw_data': self.raw_data
        }


class BaseCollector(ABC):
    """
    Abstract base class for all platform collectors
    
    Each platform (Windows, Linux, macOS) implements this interface.
    This ensures consistent behavior across all collectors.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize collector
        
        Args:
            config: Platform-specific configuration options
        """
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
    
    @abstractmethod
    def get_platform(self) -> str:
        """
        Return platform identifier
        
        Returns:
            One of: 'windows', 'linux', 'macos'
        """
        pass
    
    @abstractmethod
    def collect_events(self, source: str, start_time: datetime = None, 
                       end_time: datetime = None) -> List[Event]:
        """
        Collect events from log source
        
        Args:
            source: Path to log file or directory
            start_time: Optional filter - only return events after this time
            end_time: Optional filter - only return events before this time
            
        Returns:
            List of Event objects
            
        Raises:
            FileNotFoundError: If source doesn't exist
            PermissionError: If can't read source
            ValueError: If source format is invalid
        """
        pass
    
    @abstractmethod
    def parse_event(self, raw_event: Any) -> Event:
        """
        Parse platform-specific log entry into Event object
        
        Args:
            raw_event: Platform-specific log entry (XML, JSON, text line, etc.)
            
        Returns:
            Event object
        """
        pass
    
    def validate_source(self, source: str) -> bool:
        """
        Validate that log source exists and is readable
        
        Args:
            source: Path to log source
            
        Returns:
            True if valid
            
        Raises:
            FileNotFoundError: If source doesn't exist
            PermissionError: If can't read source
        """
        from pathlib import Path
        
        source_path = Path(source)
        
        if not source_path.exists():
            raise FileNotFoundError(f"Log source not found: {source}")
        
        if not source_path.is_file() and not source_path.is_dir():
            raise ValueError(f"Invalid source (must be file or directory): {source}")
        
        # Try to read (will raise PermissionError if no access)
        if source_path.is_file():
            with open(source_path, 'r'):
                pass
        
        return True
    
    def filter_events_by_time(self, events: List[Event], 
                             start_time: datetime = None,
                             end_time: datetime = None) -> List[Event]:
        """
        Filter events by time range
        
        Args:
            events: List of events
            start_time: Include events after this time
            end_time: Include events before this time
            
        Returns:
            Filtered list of events
        """
        filtered = events
        
        if start_time:
            filtered = [e for e in filtered if e.timestamp >= start_time]
        
        if end_time:
            filtered = [e for e in filtered if e.timestamp <= end_time]
        
        return filtered
    
    def get_stats(self, events: List[Event]) -> Dict[str, Any]:
        """
        Get statistics about collected events
        
        Args:
            events: List of events
            
        Returns:
            Dictionary with stats
        """
        if not events:
            return {'total': 0}
        
        return {
            'total': len(events),
            'earliest': min(e.timestamp for e in events),
            'latest': max(e.timestamp for e in events),
            'unique_processes': len(set(e.process_name for e in events)),
            'unique_users': len(set(e.user for e in events))
        }