#!/usr/bin/env python3
"""
LOTL Detector - Command Line Demonstration Tool

This CLI tool demonstrates the Living Off The Land (LOTL) detection framework
by scanning log files for suspicious command executions and generating alerts.
"""
import argparse
import sys
import os
import json
import csv
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
from colorama import init, Fore, Style, Back

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.rule_loader import RuleLoader
from core.engine import DetectionEngine, Alert
from core.database import AlertDatabase
from core.scorer import Scorer
from collectors.windows.collector import WindowsCollector
from collectors.linux.collector import LinuxCollector
from collectors.base import Event


class Colors:
    """ANSI color codes for severity levels"""
    CRITICAL = Fore.RED + Style.BRIGHT
    HIGH = Fore.LIGHTRED_EX
    MEDIUM = Fore.YELLOW
    LOW = Fore.BLUE
    SUCCESS = Fore.GREEN
    INFO = Fore.CYAN
    WARNING = Fore.YELLOW
    ERROR = Fore.RED
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


def print_header(title: str):
    """Print a formatted section header"""
    print(f"\n{Colors.BOLD}{Fore.CYAN}{title}{Colors.RESET}")
    print(f"{Colors.BOLD}{Fore.CYAN}{'=' * len(title)}{Colors.RESET}\n")


def print_subheader(title: str):
    """Print a formatted subsection header"""
    print(f"\n{Colors.BOLD}{title}{Colors.RESET}")
    print(f"{'-' * len(title)}")


def print_success(message: str):
    """Print success message with checkmark"""
    print(f"{Colors.SUCCESS}✓{Colors.RESET} {message}")


def print_error(message: str):
    """Print error message with X"""
    print(f"{Colors.ERROR}✗{Colors.RESET} {message}")


def print_info(message: str):
    """Print info message"""
    print(f"{Colors.INFO}ℹ{Colors.RESET} {message}")


def print_warning(message: str):
    """Print warning message"""
    print(f"{Colors.WARNING}⚠{Colors.RESET} {message}")


def print_progress(message: str, indent: int = 0):
    """Print progress message with tree-style indicator"""
    prefix = "  " * indent
    print(f"{prefix}{Colors.DIM}├─{Colors.RESET} {message}")


def print_progress_end(message: str, indent: int = 0):
    """Print final progress message with tree-style indicator"""
    prefix = "  " * indent
    print(f"{prefix}{Colors.DIM}└─{Colors.RESET} {message}")


def display_alert(alert: Dict[str, Any], detailed: bool = False):
    """Display a single alert with formatting"""
    severity = alert['severity'].upper()
    color = get_severity_color(alert['severity'])

    # Main alert line
    print(f"\n{color}[{severity}]{Colors.RESET} {Colors.BOLD}{alert['rule_name']}{Colors.RESET} "
          f"(Score: {Colors.BOLD}{alert['score']}/150{Colors.RESET})")

    # Basic info
    print(f"  Process: {Colors.INFO}{alert.get('process_name', 'N/A')}{Colors.RESET}")

    # Command line (truncate if too long)
    cmd = alert.get('command_line', 'N/A')
    if len(cmd) > 100 and not detailed:
        cmd = cmd[:100] + "..."
    print(f"  Command: {Colors.DIM}{cmd}{Colors.RESET}")

    # MITRE ATT&CK
    if alert.get('mitre_attack'):
        mitre = ', '.join(alert['mitre_attack'])
        print(f"  MITRE: {Colors.WARNING}{mitre}{Colors.RESET}")

    # Response (first item only in non-detailed mode)
    if alert.get('response'):
        response = alert['response'][0] if not detailed else '\n         '.join(alert['response'])
        if detailed:
            print(f"  Response:")
            for resp in alert['response']:
                print(f"    • {resp}")
        else:
            print(f"  Response: {response}")

    # Detailed information
    if detailed:
        print(f"  Platform: {alert.get('platform', 'N/A')}")
        print(f"  User: {alert.get('user', 'N/A')}")
        print(f"  Timestamp: {alert.get('timestamp', 'N/A')}")
        if alert.get('parent_process'):
            print(f"  Parent: {alert.get('parent_process')}")


def display_statistics(stats: Dict[str, int]):
    """Display statistics summary"""
    print_header("STATISTICS")

    print(f"Events processed: {Colors.BOLD}{stats['events']}{Colors.RESET}")
    print(f"Alerts generated: {Colors.BOLD}{stats['alerts']}{Colors.RESET}")

    # Severity breakdown
    severity_counts = stats.get('by_severity', {})
    print(f"\nSeverity Breakdown:")
    print(f"  {Colors.CRITICAL}Critical:{Colors.RESET} {severity_counts.get('critical', 0)}")
    print(f"  {Colors.HIGH}High:{Colors.RESET}     {severity_counts.get('high', 0)}")
    print(f"  {Colors.MEDIUM}Medium:{Colors.RESET}   {severity_counts.get('medium', 0)}")
    print(f"  {Colors.LOW}Low:{Colors.RESET}      {severity_counts.get('low', 0)}")

    if stats.get('database'):
        print(f"\nDatabase: {Colors.SUCCESS}{stats['alerts']} alerts saved to {stats['database']}{Colors.RESET}")


def list_rules(rule_loader: RuleLoader, rules_dir: str):
    """List all loaded detection rules"""
    print_header("LOADED DETECTION RULES")

    rules = rule_loader.load_rules_directory(rules_dir)

    # Group by platform
    by_platform = {}
    for rule in rules:
        platform = rule.platform
        if platform not in by_platform:
            by_platform[platform] = []
        by_platform[platform].append(rule)

    # Display rules by platform
    for platform, platform_rules in sorted(by_platform.items()):
        print_subheader(f"{platform.upper()} Rules ({len(platform_rules)})")

        for rule in platform_rules:
            color = get_severity_color(rule.severity)
            print(f"\n  {Colors.BOLD}{rule.id}{Colors.RESET} - {rule.name}")
            print(f"  Severity: {color}{rule.severity.upper()}{Colors.RESET}")

            # Description (first line only)
            desc = rule.description.split('\n')[0].strip()
            if len(desc) > 80:
                desc = desc[:80] + "..."
            print(f"  {Colors.DIM}{desc}{Colors.RESET}")

            # MITRE ATT&CK
            if rule.mitre_attack:
                mitre = ', '.join(rule.mitre_attack)
                print(f"  MITRE: {Colors.WARNING}{mitre}{Colors.RESET}")

    # Summary
    print_subheader("Summary")
    by_severity = {}
    for rule in rules:
        by_severity[rule.severity] = by_severity.get(rule.severity, 0) + 1

    print(f"Total Rules: {Colors.BOLD}{len(rules)}{Colors.RESET}")
    print(f"By Severity: ", end="")
    severity_strs = []
    for sev in ['critical', 'high', 'medium', 'low']:
        count = by_severity.get(sev, 0)
        if count > 0:
            color = get_severity_color(sev)
            severity_strs.append(f"{color}{sev.capitalize()}: {count}{Colors.RESET}")
    print(" | ".join(severity_strs))


def scan_logs(platform: str, log_path: str, engine: DetectionEngine,
              verbose: bool = False) -> tuple[List[Event], List[Alert]]:
    """Scan logs and generate alerts"""

    print(f"\n{Colors.INFO}Scanning {platform.capitalize()} logs...{Colors.RESET}")

    # Initialize collector
    if platform == 'windows':
        collector = WindowsCollector()
    elif platform == 'linux':
        collector = LinuxCollector()
    else:
        raise ValueError(f"Unknown platform: {platform}")

    # Collect events
    events = []
    try:
        if verbose:
            print_progress(f"Reading logs from: {log_path}")

        events = collector.collect_events(log_path)

        if verbose and events:
            for i, event in enumerate(events):
                if i % 10 == 0:
                    print_progress(f"Parsed {i+1} events so far...")

        print_progress(f"Parsed {Colors.BOLD}{len(events)}{Colors.RESET} events")
    except Exception as e:
        print_error(f"Error collecting events: {e}")
        return [], []

    # Generate alerts
    alerts = []
    for event in events:
        event_alerts = engine.match_event(event)
        if event_alerts:
            alerts.extend(event_alerts)
            if verbose:
                for alert in event_alerts:
                    print_progress(f"Alert: {alert.rule_name}", indent=1)

    print_progress_end(f"Generated {Colors.BOLD}{len(alerts)}{Colors.RESET} alert(s)")

    return events, alerts


def export_alerts(alerts: List[Dict[str, Any]], output_path: str, format: str):
    """Export alerts to file"""

    print(f"\n{Colors.INFO}Exporting alerts to {output_path}...{Colors.RESET}")

    try:
        if format == 'json':
            with open(output_path, 'w') as f:
                json.dump(alerts, f, indent=2, default=str)
        elif format == 'csv':
            if not alerts:
                print_warning("No alerts to export")
                return

            # CSV headers
            headers = ['id', 'timestamp', 'severity', 'score', 'rule_id', 'rule_name',
                      'platform', 'process_name', 'user', 'command_line']

            with open(output_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=headers, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(alerts)

        print_success(f"Exported {len(alerts)} alerts to {output_path}")

    except Exception as e:
        print_error(f"Export failed: {e}")


def run_demo_mode(rules_dir: str, database: str, verbose: bool):
    """Run demonstration mode using sample fixtures"""

    print_header("LOTL DETECTOR - DEMO MODE")

    # Check for fixtures
    fixtures_dir = Path("tests/fixtures")
    if not fixtures_dir.exists():
        print_error("Fixtures directory not found. Please run from project root.")
        return

    # Load rules
    print(f"{Colors.INFO}Loading rules...{Colors.RESET}", end=" ")
    rule_loader = RuleLoader()
    rules = rule_loader.load_rules_directory(rules_dir)
    print_success(f"{len(rules)} rules loaded")

    # Initialize components
    print(f"{Colors.INFO}Initializing detection engine...{Colors.RESET}", end=" ")
    engine = DetectionEngine(rules)
    print_success("Ready")

    print(f"{Colors.INFO}Initializing collectors...{Colors.RESET}", end=" ")
    print_success("Windows, Linux")

    # Initialize database
    db = AlertDatabase(database)

    all_events = []
    all_alerts = []

    # Scan Windows logs
    windows_fixtures = fixtures_dir / "windows"
    if windows_fixtures.exists():
        events, alerts = scan_logs('windows', str(windows_fixtures), engine, verbose)
        all_events.extend(events)
        all_alerts.extend(alerts)

    # Scan Linux logs
    linux_fixtures = fixtures_dir / "linux"
    if linux_fixtures.exists():
        for log_file in linux_fixtures.glob("*.log"):
            events, alerts = scan_logs('linux', str(log_file), engine, verbose)
            all_events.extend(events)
            all_alerts.extend(alerts)

    # Display alerts
    if all_alerts:
        print_header("ALERTS DETECTED")

        # Sort by severity (critical first)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        sorted_alerts = sorted(all_alerts, key=lambda a: severity_order.get(a.severity, 999))

        for alert in sorted_alerts[:10]:  # Show top 10
            # Convert Alert object to dict
            alert_dict = {
                'severity': alert.severity,
                'rule_name': alert.rule_name,
                'score': alert.score,
                'process_name': alert.event.process_name,
                'command_line': alert.event.command_line,
                'mitre_attack': alert.mitre_attack,
                'response': alert.response,
                'platform': alert.event.platform,
                'user': alert.event.user,
                'timestamp': alert.timestamp.isoformat(),
                'parent_process': alert.event.parent_process_name
            }
            display_alert(alert_dict)

        if len(all_alerts) > 10:
            print(f"\n{Colors.DIM}... and {len(all_alerts) - 10} more alerts{Colors.RESET}")
    else:
        print_info("No alerts detected")

    # Save to database
    saved_count = 0
    for alert in all_alerts:
        alert_id = db.save_alert(alert)
        if alert_id:
            saved_count += 1

    # Display statistics
    by_severity = {}
    for alert in all_alerts:
        by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1

    stats = {
        'events': len(all_events),
        'alerts': len(all_alerts),
        'by_severity': by_severity,
        'database': database
    }
    display_statistics(stats)


def run_scan_mode(platform: str, log_path: str, rules_dir: str,
                  database: str, export: str, verbose: bool):
    """Run scan mode on actual log files"""

    print_header("LOTL DETECTOR - SCAN MODE")

    # Validate log path
    if not os.path.exists(log_path):
        print_error(f"Log path not found: {log_path}")
        return

    # Load rules
    print(f"{Colors.INFO}Loading rules...{Colors.RESET}", end=" ")
    rule_loader = RuleLoader()
    rules = rule_loader.load_rules_directory(rules_dir)

    # Filter rules by platform if specified
    if platform != 'both':
        rules = [r for r in rules if r.platform == platform]

    print_success(f"{len(rules)} rules loaded")

    # Initialize engine
    print(f"{Colors.INFO}Initializing detection engine...{Colors.RESET}", end=" ")
    engine = DetectionEngine(rules)
    print_success("Ready")

    # Initialize database
    db = AlertDatabase(database)

    all_events = []
    all_alerts = []

    # Scan based on platform
    if platform in ['windows', 'linux']:
        events, alerts = scan_logs(platform, log_path, engine, verbose)
        all_events.extend(events)
        all_alerts.extend(alerts)
    elif platform == 'both':
        # Try both collectors
        print_info("Scanning with both Windows and Linux collectors...")

        # Try Windows
        try:
            events, alerts = scan_logs('windows', log_path, engine, verbose)
            all_events.extend(events)
            all_alerts.extend(alerts)
        except:
            if verbose:
                print_warning("Windows collector failed, trying Linux...")

        # Try Linux
        try:
            events, alerts = scan_logs('linux', log_path, engine, verbose)
            all_events.extend(events)
            all_alerts.extend(alerts)
        except:
            if verbose:
                print_warning("Linux collector failed")

    # Display alerts
    if all_alerts:
        print_header("ALERTS DETECTED")

        # Sort by score (highest first)
        sorted_alerts = sorted(all_alerts, key=lambda a: a.score, reverse=True)

        for alert in sorted_alerts[:20]:  # Show top 20
            alert_dict = {
                'severity': alert.severity,
                'rule_name': alert.rule_name,
                'score': alert.score,
                'process_name': alert.event.process_name,
                'command_line': alert.event.command_line,
                'mitre_attack': alert.mitre_attack,
                'response': alert.response,
                'platform': alert.event.platform,
                'user': alert.event.user,
                'timestamp': alert.timestamp.isoformat(),
                'parent_process': alert.event.parent_process_name
            }
            display_alert(alert_dict, detailed=verbose)

        if len(all_alerts) > 20:
            print(f"\n{Colors.DIM}... and {len(all_alerts) - 20} more alerts{Colors.RESET}")
    else:
        print_info("No alerts detected")

    # Save to database
    saved_count = 0
    for alert in all_alerts:
        alert_id = db.save_alert(alert)
        if alert_id:
            saved_count += 1

    # Export if requested
    if export and all_alerts:
        # Convert alerts to dicts for export
        alert_dicts = []
        for i, alert in enumerate(all_alerts, 1):
            alert_dict = {
                'id': i,
                'timestamp': alert.timestamp.isoformat(),
                'severity': alert.severity,
                'score': alert.score,
                'rule_id': alert.rule_id,
                'rule_name': alert.rule_name,
                'platform': alert.event.platform,
                'process_name': alert.event.process_name,
                'user': alert.event.user,
                'command_line': alert.event.command_line,
                'mitre_attack': ','.join(alert.mitre_attack),
                'description': alert.description
            }
            alert_dicts.append(alert_dict)

        # Determine format from extension
        export_format = 'json' if export.endswith('.json') else 'csv'
        export_alerts(alert_dicts, export, export_format)

    # Display statistics
    by_severity = {}
    for alert in all_alerts:
        by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1

    stats = {
        'events': len(all_events),
        'alerts': len(all_alerts),
        'by_severity': by_severity,
        'database': database
    }
    display_statistics(stats)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='LOTL Detector - Demonstration Tool for Living Off The Land Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run demo mode with sample fixtures
  python demo_detector.py --demo

  # Scan Windows logs
  python demo_detector.py --platform windows --log-path C:\\Windows\\System32\\winevt\\Logs\\

  # Scan Linux auditd logs
  python demo_detector.py --platform linux --log-path /var/log/audit/audit.log

  # List all detection rules
  python demo_detector.py --list-rules

  # Scan and export to JSON
  python demo_detector.py --platform linux --log-path /var/log/audit/ --export alerts.json

  # Verbose output
  python demo_detector.py --demo --verbose
        """
    )

    # Mode selection
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        '--demo',
        action='store_true',
        help='Run demo mode using sample fixtures'
    )
    mode_group.add_argument(
        '--list-rules',
        action='store_true',
        help='List all loaded detection rules'
    )

    # Scan options
    parser.add_argument(
        '--platform',
        choices=['windows', 'linux', 'both'],
        default='both',
        help='Platform to scan (default: both)'
    )
    parser.add_argument(
        '--log-path',
        type=str,
        help='Path to log file or directory'
    )

    # Configuration
    parser.add_argument(
        '--rules-dir',
        type=str,
        default='rules',
        help='Rules directory (default: rules/)'
    )
    parser.add_argument(
        '--database',
        type=str,
        default='lotl_detector.db',
        help='Database file (default: lotl_detector.db)'
    )

    # Output options
    parser.add_argument(
        '--export',
        type=str,
        help='Export alerts to file (JSON or CSV based on extension)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show detailed output'
    )

    args = parser.parse_args()

    try:
        # List rules mode
        if args.list_rules:
            rule_loader = RuleLoader()
            list_rules(rule_loader, args.rules_dir)
            return

        # Demo mode
        if args.demo:
            run_demo_mode(args.rules_dir, args.database, args.verbose)
            return

        # Scan mode
        if not args.log_path:
            print_error("Error: --log-path is required for scan mode")
            print_info("Use --demo for demonstration mode, or --list-rules to see available rules")
            parser.print_help()
            sys.exit(1)

        run_scan_mode(
            args.platform,
            args.log_path,
            args.rules_dir,
            args.database,
            args.export,
            args.verbose
        )

    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}Interrupted by user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print_error(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
