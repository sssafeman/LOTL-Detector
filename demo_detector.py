#!/usr/bin/env python3
"""
LOTL Detector - Command Line Demonstration Tool

This CLI tool demonstrates the Living Off The Land (LOTL) detection framework
by scanning log files for suspicious command executions and generating alerts.
"""
import argparse
import csv
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.rule_loader import Rule, RuleLoader
from core.engine import DetectionEngine, Alert
from core.database import AlertDatabase
from core.config import get_database_path, get_rules_directory
from collectors.windows.collector import WindowsCollector
from collectors.linux.collector import LinuxCollector
from collectors.macos.collector import MacOSCollector
from collectors.base import BaseCollector, Event


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


_SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
_CSV_HEADERS = [
    'id', 'timestamp', 'severity', 'score', 'rule_id', 'rule_name',
    'platform', 'process_name', 'user', 'command_line'
]


def get_severity_color(severity: str) -> str:
    """Get color code for severity level"""
    severity_colors = {
        'critical': Colors.CRITICAL,
        'high': Colors.HIGH,
        'medium': Colors.MEDIUM,
        'low': Colors.LOW
    }
    return severity_colors.get(severity.lower(), Colors.RESET)


def print_header(title: str) -> None:
    """Print a formatted section header"""
    print(f"\n{Colors.BOLD}{Fore.CYAN}{title}{Colors.RESET}")
    print(f"{Colors.BOLD}{Fore.CYAN}{'=' * len(title)}{Colors.RESET}\n")


def print_subheader(title: str) -> None:
    """Print a formatted subsection header"""
    print(f"\n{Colors.BOLD}{title}{Colors.RESET}")
    print(f"{'-' * len(title)}")


def print_success(message: str) -> None:
    """Print success message with checkmark"""
    print(f"{Colors.SUCCESS}✓{Colors.RESET} {message}")


def print_error(message: str) -> None:
    """Print error message with X"""
    print(f"{Colors.ERROR}✗{Colors.RESET} {message}")


def print_info(message: str) -> None:
    """Print info message"""
    print(f"{Colors.INFO}ℹ{Colors.RESET} {message}")


def print_warning(message: str) -> None:
    """Print warning message"""
    print(f"{Colors.WARNING}⚠{Colors.RESET} {message}")


def print_progress(message: str, indent: int = 0) -> None:
    """Print progress message with tree-style indicator"""
    prefix = "  " * indent
    print(f"{prefix}{Colors.DIM}├─{Colors.RESET} {message}")


def print_progress_end(message: str, indent: int = 0) -> None:
    """Print final progress message with tree-style indicator"""
    prefix = "  " * indent
    print(f"{prefix}{Colors.DIM}└─{Colors.RESET} {message}")


def _display_response(response: Sequence[str], detailed: bool) -> None:
    if detailed:
        print("  Response:")
        for item in response:
            print(f"    • {item}")
        return

    print(f"  Response: {response[0]}")


def _display_alert_details(alert: Dict[str, Any]) -> None:
    print(f"  Platform: {alert.get('platform', 'N/A')}")
    print(f"  User: {alert.get('user', 'N/A')}")
    print(f"  Timestamp: {alert.get('timestamp', 'N/A')}")
    if alert.get('parent_process'):
        print(f"  Parent: {alert.get('parent_process')}")


def display_alert(alert: Dict[str, Any], detailed: bool = False) -> None:
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

    response = alert.get('response')
    if response:
        _display_response(response, detailed)

    if detailed:
        _display_alert_details(alert)


def display_statistics(stats: Dict[str, Any]) -> None:
    """Display statistics summary"""
    print_header("STATISTICS")

    print(f"Events processed: {Colors.BOLD}{stats['events']}{Colors.RESET}")
    print(f"Alerts generated: {Colors.BOLD}{stats['alerts']}{Colors.RESET}")
    if 'incidents' in stats:
        print(f"Correlated incidents: {Colors.BOLD}{stats['incidents']}{Colors.RESET}")

    # Severity breakdown
    severity_counts = stats.get('by_severity', {})
    print(f"\nSeverity Breakdown:")
    print(f"  {Colors.CRITICAL}Critical:{Colors.RESET} {severity_counts.get('critical', 0)}")
    print(f"  {Colors.HIGH}High:{Colors.RESET}     {severity_counts.get('high', 0)}")
    print(f"  {Colors.MEDIUM}Medium:{Colors.RESET}   {severity_counts.get('medium', 0)}")
    print(f"  {Colors.LOW}Low:{Colors.RESET}      {severity_counts.get('low', 0)}")

    if stats.get('database'):
        print(
            f"\nDatabase: {Colors.SUCCESS}{stats['alerts']} alerts saved to "
            f"{stats['database']}{Colors.RESET}"
        )


def _group_rules_by_platform(rules: Sequence[Rule]) -> Dict[str, List[Rule]]:
    grouped_rules: Dict[str, List[Rule]] = {}
    for rule in rules:
        grouped_rules.setdefault(rule.platform, []).append(rule)
    return grouped_rules


def _display_rule(rule: Rule) -> None:
    color = get_severity_color(rule.severity)
    print(f"\n  {Colors.BOLD}{rule.id}{Colors.RESET} - {rule.name}")
    print(f"  Severity: {color}{rule.severity.upper()}{Colors.RESET}")

    description = rule.description.split('\n')[0].strip()
    if len(description) > 80:
        description = description[:80] + "..."
    print(f"  {Colors.DIM}{description}{Colors.RESET}")

    if rule.mitre_attack:
        mitre = ', '.join(rule.mitre_attack)
        print(f"  MITRE: {Colors.WARNING}{mitre}{Colors.RESET}")


def _count_severities(items: Sequence[Any]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        counts[item.severity] = counts.get(item.severity, 0) + 1
    return counts


def _display_rule_summary(rules: Sequence[Rule]) -> None:
    print_subheader("Summary")
    severity_counts = _count_severities(rules)

    print(f"Total Rules: {Colors.BOLD}{len(rules)}{Colors.RESET}")
    print("By Severity: ", end="")
    severity_labels = []
    for severity in _SEVERITY_ORDER:
        count = severity_counts.get(severity, 0)
        if count:
            color = get_severity_color(severity)
            severity_labels.append(
                f"{color}{severity.capitalize()}: {count}{Colors.RESET}"
            )
    print(" | ".join(severity_labels))


def list_rules(rule_loader: RuleLoader, rules_dir: str) -> None:
    """List all loaded detection rules"""
    print_header("LOADED DETECTION RULES")

    rules = rule_loader.load_rules_directory(rules_dir)
    rules_by_platform = _group_rules_by_platform(rules)
    for platform, platform_rules in sorted(rules_by_platform.items()):
        print_subheader(f"{platform.upper()} Rules ({len(platform_rules)})")
        for rule in platform_rules:
            _display_rule(rule)

    _display_rule_summary(rules)


def _create_collector(platform: str) -> BaseCollector:
    collector_types = {
        'windows': WindowsCollector,
        'linux': LinuxCollector,
        'macos': MacOSCollector,
    }
    collector_type = collector_types.get(platform)
    if collector_type is None:
        raise ValueError(f"Unknown platform: {platform}")
    return collector_type()


def _report_parsing_progress(events: Sequence[Event], verbose: bool) -> None:
    if not verbose:
        return

    for index, _event in enumerate(events):
        if index % 10 == 0:
            print_progress(f"Parsed {index + 1} events so far...")


def _match_events(
    events: Sequence[Event], engine: DetectionEngine, verbose: bool
) -> List[Alert]:
    alerts = []
    for event in events:
        event_alerts = engine.match_event(event)
        alerts.extend(event_alerts)
        if verbose:
            for alert in event_alerts:
                print_progress(f"Alert: {alert.rule_name}", indent=1)
    return alerts


def scan_logs(platform: str, log_path: str, engine: DetectionEngine,
              verbose: bool = False) -> tuple[List[Event], List[Alert]]:
    """Scan logs and generate alerts"""

    print(f"\n{Colors.INFO}Scanning {platform.capitalize()} logs...{Colors.RESET}")
    collector = _create_collector(platform)

    try:
        if verbose:
            print_progress(f"Reading logs from: {log_path}")

        events = collector.collect_events(log_path)
        _report_parsing_progress(events, verbose)
        print_progress(f"Parsed {Colors.BOLD}{len(events)}{Colors.RESET} events")
    except Exception as e:
        print_error(f"Error collecting events: {e}")
        return [], []

    alerts = _match_events(events, engine, verbose)
    print_progress_end(f"Generated {Colors.BOLD}{len(alerts)}{Colors.RESET} alert(s)")

    return events, alerts


def _display_incident(incident: Any) -> None:
    color = get_severity_color(incident.severity)
    print(f"\n{color}[{incident.severity.upper()}]{Colors.RESET} "
          f"{Colors.BOLD}{incident.chain_name}{Colors.RESET} "
          f"({incident.chain_id}, score: {incident.score}, "
          f"risk: {incident.risk_band})")
    for stage in incident.stages:
        origin = "inferred parent" if stage['phantom'] else "observed event"
        print(f"  {Colors.DIM}stage{Colors.RESET} {stage['stage']}: "
              f"{stage['process_name']} (pid {stage['pid']}, {origin})")


def _display_and_save_incidents(
    incidents: Sequence[Any], db: AlertDatabase
) -> None:
    if not incidents:
        print_info("No correlated incidents detected")
        return

    print_header("CORRELATED INCIDENTS")
    for incident in incidents:
        _display_incident(incident)
        db.save_incident(incident)


def run_correlation(all_events: List[Event], rules_dir: str, db: AlertDatabase,
                    platform: Optional[str] = None) -> List[Any]:
    """
    Run lineage correlation over the collected events and persist incidents.

    Returns the list of Incident objects (empty when no chain rules exist).
    """
    from core.correlator import ChainRuleLoader, Correlator

    chains_dir = str(Path(rules_dir) / "correlation")
    try:
        chain_loader = ChainRuleLoader()
        chains = chain_loader.load_chains_directory(chains_dir, platform=platform)
    except Exception as e:
        print_warning(f"Chain rules unavailable, correlation skipped: {e}")
        return []

    if not chains or not all_events:
        return []

    correlator = Correlator(chains)
    incidents = correlator.correlate(all_events)
    _display_and_save_incidents(incidents, db)
    return incidents


def _write_json_alerts(alerts: Sequence[Dict[str, Any]], output_path: str) -> None:
    with open(output_path, 'w') as output_file:
        json.dump(alerts, output_file, indent=2, default=str)


def _write_csv_alerts(alerts: Sequence[Dict[str, Any]], output_path: str) -> None:
    with open(output_path, 'w', newline='') as output_file:
        writer = csv.DictWriter(
            output_file,
            fieldnames=_CSV_HEADERS,
            extrasaction='ignore',
        )
        writer.writeheader()
        writer.writerows(alerts)


def export_alerts(
    alerts: List[Dict[str, Any]], output_path: str, format: str
) -> None:
    """Export alerts to file"""

    print(f"\n{Colors.INFO}Exporting alerts to {output_path}...{Colors.RESET}")

    try:
        if format == 'json':
            _write_json_alerts(alerts, output_path)
        elif format == 'csv':
            if not alerts:
                print_warning("No alerts to export")
                return
            _write_csv_alerts(alerts, output_path)

        print_success(f"Exported {len(alerts)} alerts to {output_path}")

    except Exception as e:
        print_error(f"Export failed: {e}")


def _initialize_engine(
    rules_dir: str, platform: Optional[str] = None
) -> DetectionEngine:
    print(f"{Colors.INFO}Loading rules...{Colors.RESET}", end=" ")
    rule_loader = RuleLoader()
    rules = rule_loader.load_rules_directory(rules_dir)
    if platform is not None:
        rules = [rule for rule in rules if rule.platform == platform]
    print_success(f"{len(rules)} rules loaded")

    print(
        f"{Colors.INFO}Initializing detection engine...{Colors.RESET}",
        end=" ",
    )
    engine = DetectionEngine(rules)
    print_success("Ready")
    return engine


def _iter_demo_logs(fixtures_dir: Path) -> Iterator[Tuple[str, Path]]:
    windows_fixtures = fixtures_dir / "windows"
    if windows_fixtures.exists():
        yield 'windows', windows_fixtures

    linux_fixtures = fixtures_dir / "linux"
    if linux_fixtures.exists():
        for log_file in linux_fixtures.glob("*.log"):
            yield 'linux', log_file

    macos_fixtures = fixtures_dir / "macos"
    if macos_fixtures.exists():
        for log_file in macos_fixtures.glob("*.ndjson"):
            yield 'macos', log_file


def _alert_to_display_dict(alert: Alert) -> Dict[str, Any]:
    return {
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
        'parent_process': alert.event.parent_process_name,
    }


def _display_alert_collection(
    alerts: Sequence[Alert], limit: int, detailed: bool = False
) -> None:
    if not alerts:
        print_info("No alerts detected")
        return

    print_header("ALERTS DETECTED")
    for alert in alerts[:limit]:
        display_alert(_alert_to_display_dict(alert), detailed=detailed)

    remaining_count = len(alerts) - limit
    if remaining_count > 0:
        print(f"\n{Colors.DIM}... and {remaining_count} more alerts{Colors.RESET}")


def _save_alerts(alerts: Sequence[Alert], db: AlertDatabase) -> None:
    for alert in alerts:
        db.save_alert(alert)


def _display_run_statistics(
    events: Sequence[Event],
    alerts: Sequence[Alert],
    database: str,
    incident_count: Optional[int] = None,
) -> None:
    stats: Dict[str, Any] = {
        'events': len(events),
        'alerts': len(alerts),
        'by_severity': _count_severities(alerts),
        'database': database,
    }
    if incident_count is not None:
        stats['incidents'] = incident_count
    display_statistics(stats)


def run_demo_mode(rules_dir: str, database: str, verbose: bool) -> None:
    """Run demonstration mode using sample fixtures"""

    print_header("LOTL DETECTOR - DEMO MODE")

    fixtures_dir = Path("tests/fixtures")
    if not fixtures_dir.exists():
        print_error("Fixtures directory not found. Please run from project root.")
        return

    engine = _initialize_engine(rules_dir)
    print(f"{Colors.INFO}Initializing collectors...{Colors.RESET}", end=" ")
    print_success("Windows, Linux")

    db = AlertDatabase(database)
    all_events: List[Event] = []
    all_alerts: List[Alert] = []
    for platform, log_path in _iter_demo_logs(fixtures_dir):
        events, alerts = scan_logs(platform, str(log_path), engine, verbose)
        all_events.extend(events)
        all_alerts.extend(alerts)

    sorted_alerts = sorted(
        all_alerts,
        key=lambda alert: _SEVERITY_ORDER.get(alert.severity, 999),
    )
    _display_alert_collection(sorted_alerts, limit=10)
    _save_alerts(all_alerts, db)

    incidents = run_correlation(all_events, rules_dir, db)
    _display_run_statistics(
        all_events,
        all_alerts,
        database,
        incident_count=len(incidents),
    )


def _scan_best_effort(
    platform: str,
    log_path: str,
    engine: DetectionEngine,
    verbose: bool,
    failure_message: str,
) -> Tuple[List[Event], List[Alert]]:
    try:
        return scan_logs(platform, log_path, engine, verbose)
    except BaseException:
        if verbose:
            print_warning(failure_message)
        return [], []


def _collect_scan_results(
    platform: str,
    log_path: str,
    engine: DetectionEngine,
    verbose: bool,
) -> Tuple[List[Event], List[Alert]]:
    if platform in ('windows', 'linux'):
        return scan_logs(platform, log_path, engine, verbose)

    all_events: List[Event] = []
    all_alerts: List[Alert] = []

    if platform == 'both':
        print_info("Scanning with both Windows and Linux collectors...")
        scan_attempts = (
            ('windows', "Windows collector failed, trying Linux..."),
            ('linux', "Linux collector failed"),
        )
        for scan_platform, failure_message in scan_attempts:
            events, alerts = _scan_best_effort(
                scan_platform,
                log_path,
                engine,
                verbose,
                failure_message,
            )
            all_events.extend(events)
            all_alerts.extend(alerts)

    return all_events, all_alerts


def _alert_to_export_dict(alert: Alert, alert_id: int) -> Dict[str, Any]:
    return {
        'id': alert_id,
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
        'description': alert.description,
    }


def _export_scan_alerts(alerts: Sequence[Alert], output_path: str) -> None:
    alert_dicts = [
        _alert_to_export_dict(alert, alert_id)
        for alert_id, alert in enumerate(alerts, 1)
    ]
    export_format = 'json' if output_path.endswith('.json') else 'csv'
    export_alerts(alert_dicts, output_path, export_format)


def run_scan_mode(platform: str, log_path: str, rules_dir: str,
                  database: str, export: Optional[str], verbose: bool) -> None:
    """Run scan mode on actual log files"""

    print_header("LOTL DETECTOR - SCAN MODE")

    if not os.path.exists(log_path):
        print_error(f"Log path not found: {log_path}")
        return

    rule_platform = None if platform == 'both' else platform
    engine = _initialize_engine(rules_dir, platform=rule_platform)
    db = AlertDatabase(database)

    all_events, all_alerts = _collect_scan_results(
        platform,
        log_path,
        engine,
        verbose,
    )
    sorted_alerts = sorted(all_alerts, key=lambda alert: alert.score, reverse=True)
    _display_alert_collection(sorted_alerts, limit=20, detailed=verbose)
    _save_alerts(all_alerts, db)

    correlation_platform = platform if platform != 'both' else None
    run_correlation(all_events, rules_dir, db, platform=correlation_platform)

    if export and all_alerts:
        _export_scan_alerts(all_alerts, export)

    _display_run_statistics(all_events, all_alerts, database)


def _get_default_paths() -> Tuple[str, str]:
    try:
        return get_database_path(), get_rules_directory()
    except Exception:
        return 'lotl_detector.db', 'rules'


def _add_mode_arguments(parser: argparse.ArgumentParser) -> None:
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        '--demo',
        action='store_true',
        help='Run demo mode using sample fixtures',
    )
    mode_group.add_argument(
        '--list-rules',
        action='store_true',
        help='List all loaded detection rules',
    )


def _add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        '--platform',
        choices=['windows', 'linux', 'macos', 'both'],
        default='both',
        help='Platform to scan (default: both)',
    )
    parser.add_argument(
        '--log-path',
        type=str,
        help='Path to log file or directory',
    )


def _add_configuration_arguments(
    parser: argparse.ArgumentParser, rules_dir: str, db_path: str
) -> None:
    parser.add_argument(
        '--rules-dir',
        type=str,
        default=rules_dir,
        help=f'Rules directory (default: {rules_dir})',
    )
    parser.add_argument(
        '--database',
        type=str,
        default=db_path,
        help=f'Database file (default: {db_path})',
    )


def _add_output_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        '--export',
        type=str,
        help='Export alerts to file (JSON or CSV based on extension)',
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show detailed output',
    )


def _create_argument_parser(
    rules_dir: str, db_path: str
) -> argparse.ArgumentParser:
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
    _add_mode_arguments(parser)
    _add_scan_arguments(parser)
    _add_configuration_arguments(parser, rules_dir, db_path)
    _add_output_arguments(parser)
    return parser


def _run_selected_mode(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> None:
    if args.list_rules:
        list_rules(RuleLoader(), args.rules_dir)
        return

    if args.demo:
        run_demo_mode(args.rules_dir, args.database, args.verbose)
        return

    if not args.log_path:
        print_error("Error: --log-path is required for scan mode")
        print_info(
            "Use --demo for demonstration mode, or --list-rules to see "
            "available rules"
        )
        parser.print_help()
        sys.exit(1)

    run_scan_mode(
        args.platform,
        args.log_path,
        args.rules_dir,
        args.database,
        args.export,
        args.verbose,
    )


def main() -> None:
    """Main entry point"""
    db_path, rules_dir = _get_default_paths()
    parser = _create_argument_parser(rules_dir, db_path)
    args = parser.parse_args()

    try:
        _run_selected_mode(args, parser)
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
