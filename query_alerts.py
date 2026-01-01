#!/usr/bin/env python3
"""
LOTL Detector - Alert Query Tool

A professional CLI tool for querying and analyzing alerts from the database.
Provides multiple output formats and powerful filtering options.
"""
import argparse
import sys
import json
import csv
import re
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.database import AlertDatabase
from core.config import get_database_path


class Colors:
    """ANSI color codes for severity levels"""
    CRITICAL = Fore.RED + Style.BRIGHT
    HIGH = Fore.LIGHTRED_EX
    MEDIUM = Fore.YELLOW
    LOW = Fore.BLUE
    SUCCESS = Fore.GREEN
    INFO = Fore.CYAN
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT
    DIM = Style.DIM


def get_severity_color(severity: str) -> str:
    """Get color code for severity level"""
    severity_colors = {
        'critical': Colors.CRITICAL,
        'high': Colors.HIGH,
        'medium': Colors.MEDIUM,
        'low': Colors.LOW
    }
    return severity_colors.get(severity.lower(), Colors.RESET)


def parse_timeframe(timeframe: str) -> datetime:
    """
    Parse timeframe string (e.g., "24h", "7d", "30d") to datetime

    Args:
        timeframe: Time range string (format: Nh, Nd, Nw, Nm)

    Returns:
        datetime object representing the start time

    Raises:
        ValueError: If timeframe format is invalid
    """
    pattern = r'^(\d+)([hdwm])$'
    match = re.match(pattern, timeframe.lower())

    if not match:
        raise ValueError(
            f"Invalid timeframe format: {timeframe}. "
            "Use format like: 24h, 7d, 4w, 3m"
        )

    value = int(match.group(1))
    unit = match.group(2)

    now = datetime.now()

    if unit == 'h':  # hours
        return now - timedelta(hours=value)
    elif unit == 'd':  # days
        return now - timedelta(days=value)
    elif unit == 'w':  # weeks
        return now - timedelta(weeks=value)
    elif unit == 'm':  # months (approximate as 30 days)
        return now - timedelta(days=value * 30)

    raise ValueError(f"Unknown time unit: {unit}")


def truncate_string(s: str, max_length: int) -> str:
    """Truncate string to max length with ellipsis"""
    if len(s) <= max_length:
        return s
    return s[:max_length - 3] + "..."


def format_timestamp(timestamp: str) -> str:
    """Format ISO timestamp to human-readable format"""
    try:
        dt = datetime.fromisoformat(timestamp)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return timestamp


def format_table_output(alerts: List[Dict[str, Any]], verbose: bool = False):
    """
    Format alerts as a colored table

    Args:
        alerts: List of alert dictionaries
        verbose: Show detailed information
    """
    if not alerts:
        print(f"{Colors.INFO}No alerts found{Colors.RESET}")
        return

    # Header
    print(f"\n{Colors.BOLD}{'ID':<6} {'Timestamp':<20} {'Severity':<10} {'Score':<6} {'Rule ID':<10} "
          f"{'Platform':<10} {'Process':<15}{Colors.RESET}")
    print(f"{Colors.DIM}{'-' * 120}{Colors.RESET}")

    # Alerts
    for alert in alerts:
        severity = alert['severity']
        color = get_severity_color(severity)

        timestamp = format_timestamp(alert['timestamp'])
        rule_id = alert.get('rule_id', 'N/A')
        platform = alert.get('platform', 'N/A')
        process = alert.get('process_name', 'N/A')
        score = alert.get('score', 0)

        print(f"{alert['id']:<6} {timestamp:<20} {color}{severity.upper():<10}{Colors.RESET} "
              f"{score:<6} {rule_id:<10} {platform:<10} {process:<15}")

        if verbose:
            # Show rule name
            rule_name = alert.get('rule_name', 'N/A')
            print(f"       {Colors.DIM}Rule:{Colors.RESET} {rule_name}")

            # Show command line (truncated)
            cmd = alert.get('command_line', 'N/A')
            print(f"       {Colors.DIM}Command:{Colors.RESET} {truncate_string(cmd, 100)}")

            # Show MITRE ATT&CK
            mitre = alert.get('mitre_attack', '')
            if mitre:
                print(f"       {Colors.DIM}MITRE:{Colors.RESET} {mitre}")

            print()  # Blank line between alerts


def format_json_output(alerts: List[Dict[str, Any]]):
    """
    Format alerts as JSON

    Args:
        alerts: List of alert dictionaries
    """
    # Convert any datetime objects to strings
    output = json.dumps(alerts, indent=2, default=str)
    print(output)


def format_csv_output(alerts: List[Dict[str, Any]]):
    """
    Format alerts as CSV

    Args:
        alerts: List of alert dictionaries
    """
    if not alerts:
        return

    # Define CSV headers
    headers = [
        'id', 'timestamp', 'severity', 'score', 'rule_id', 'rule_name',
        'platform', 'process_name', 'user', 'command_line', 'mitre_attack',
        'description'
    ]

    writer = csv.DictWriter(sys.stdout, fieldnames=headers, extrasaction='ignore')
    writer.writeheader()
    writer.writerows(alerts)


def display_summary(alerts: List[Dict[str, Any]]):
    """
    Display summary statistics

    Args:
        alerts: List of alert dictionaries
    """
    if not alerts:
        return

    print(f"\n{Colors.BOLD}SUMMARY STATISTICS{Colors.RESET}")
    print(f"{Colors.DIM}{'=' * 60}{Colors.RESET}\n")

    # Total alerts
    print(f"Total Alerts: {Colors.BOLD}{len(alerts)}{Colors.RESET}")

    # Breakdown by severity
    severity_counts = {}
    for alert in alerts:
        severity = alert['severity']
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    print(f"\nBreakdown by Severity:")
    for severity in ['critical', 'high', 'medium', 'low']:
        count = severity_counts.get(severity, 0)
        if count > 0:
            color = get_severity_color(severity)
            percentage = (count / len(alerts)) * 100
            print(f"  {color}{severity.capitalize():<10}{Colors.RESET}: {count:>4} ({percentage:>5.1f}%)")

    # Breakdown by platform
    platform_counts = {}
    for alert in alerts:
        platform = alert.get('platform', 'unknown')
        platform_counts[platform] = platform_counts.get(platform, 0) + 1

    print(f"\nBreakdown by Platform:")
    for platform, count in sorted(platform_counts.items()):
        percentage = (count / len(alerts)) * 100
        print(f"  {platform.capitalize():<10}: {count:>4} ({percentage:>5.1f}%)")

    # Average score
    scores = [alert.get('score', 0) for alert in alerts]
    avg_score = sum(scores) / len(scores) if scores else 0
    max_score = max(scores) if scores else 0
    min_score = min(scores) if scores else 0

    print(f"\nScore Statistics:")
    print(f"  Average: {Colors.BOLD}{avg_score:.1f}{Colors.RESET}/150")
    print(f"  Maximum: {Colors.BOLD}{max_score}{Colors.RESET}/150")
    print(f"  Minimum: {Colors.BOLD}{min_score}{Colors.RESET}/150")

    # Top rules
    rule_counts = {}
    for alert in alerts:
        rule_id = alert.get('rule_id', 'unknown')
        rule_name = alert.get('rule_name', 'Unknown')
        key = f"{rule_id}: {rule_name}"
        rule_counts[key] = rule_counts.get(key, 0) + 1

    if rule_counts:
        print(f"\nTop 5 Triggered Rules:")
        sorted_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        for rule, count in sorted_rules:
            percentage = (count / len(alerts)) * 100
            print(f"  {rule:<50}: {count:>4} ({percentage:>5.1f}%)")


def main():
    """Main entry point"""
    # Load database path from config
    try:
        default_db = get_database_path()
    except Exception:
        default_db = 'alerts.db'

    parser = argparse.ArgumentParser(
        description='LOTL Detector - Alert Query Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show alerts from last 24 hours
  python query_alerts.py --last 24h

  # Show critical alerts in table format
  python query_alerts.py --severity critical

  # Show Windows alerts with high scores
  python query_alerts.py --platform windows --min-score 100

  # Export alerts to JSON
  python query_alerts.py --last 7d --format json

  # Export alerts to CSV file
  python query_alerts.py --last 30d --format csv > alerts.csv

  # Show alerts for specific rule
  python query_alerts.py --rule-id LNX-002

  # Verbose output with full details
  python query_alerts.py --last 24h --verbose

  # Combine multiple filters
  python query_alerts.py --severity high --platform linux --last 48h --limit 20
        """
    )

    # Database option
    parser.add_argument(
        '--database',
        default=default_db,
        help=f'Database path (default: {default_db})'
    )

    # Filtering options
    parser.add_argument(
        '--severity',
        choices=['critical', 'high', 'medium', 'low'],
        help='Filter by severity level'
    )
    parser.add_argument(
        '--platform',
        choices=['windows', 'linux'],
        help='Filter by platform'
    )
    parser.add_argument(
        '--min-score',
        type=int,
        help='Minimum alert score (0-150)'
    )
    parser.add_argument(
        '--last',
        type=str,
        metavar='TIMEFRAME',
        help='Show alerts from last N time (e.g., 24h, 7d, 4w, 3m)'
    )
    parser.add_argument(
        '--rule-id',
        type=str,
        help='Filter by specific rule ID (e.g., WIN-001, LNX-002)'
    )

    # Output options
    parser.add_argument(
        '--limit',
        type=int,
        default=50,
        help='Maximum number of results (default: 50, 0 for unlimited)'
    )
    parser.add_argument(
        '--format',
        choices=['table', 'json', 'csv'],
        default='table',
        help='Output format (default: table)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show detailed information (table format only)'
    )
    parser.add_argument(
        '--no-summary',
        action='store_true',
        help='Skip summary statistics'
    )

    args = parser.parse_args()

    try:
        # Open database
        db = AlertDatabase(args.database)

        # Build query parameters
        query_params = {}

        if args.severity:
            query_params['severity'] = args.severity

        if args.platform:
            query_params['platform'] = args.platform

        if args.min_score is not None:
            query_params['min_score'] = args.min_score

        if args.last:
            try:
                start_time = parse_timeframe(args.last)
                query_params['start_time'] = start_time
            except ValueError as e:
                print(f"{Colors.ERROR}Error: {e}{Colors.RESET}", file=sys.stderr)
                sys.exit(1)

        # Set limit (0 means unlimited)
        limit = None if args.limit == 0 else args.limit
        query_params['limit'] = limit

        # Query alerts
        alerts = db.get_alerts(**query_params)

        # Filter by rule ID if specified (post-query filter)
        if args.rule_id:
            alerts = [a for a in alerts if a.get('rule_id') == args.rule_id]

        # Format output based on requested format
        if args.format == 'table':
            format_table_output(alerts, args.verbose)
            if not args.no_summary:
                display_summary(alerts)
        elif args.format == 'json':
            format_json_output(alerts)
        elif args.format == 'csv':
            format_csv_output(alerts)

        # Close database
        db.close()

    except FileNotFoundError:
        print(f"{Colors.ERROR}Error: Database not found: {args.database}{Colors.RESET}", file=sys.stderr)
        print(f"{Colors.INFO}Run demo_detector.py --demo first to generate some alerts{Colors.RESET}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.ERROR}Error: {e}{Colors.RESET}", file=sys.stderr)
        if '--verbose' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
