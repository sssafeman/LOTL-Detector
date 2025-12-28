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
Detection Dashboard (Web UI)
         ↓
Core Detection Engine (rule matching, scoring)
         ↓
Platform Collectors (Windows, Linux, macOS)
         ↓
System Logs (Sysmon, auditd, etc.)
```

## Project Status

**Phase 1: Foundation** (In Progress)
- [x] Rule schema definition
- [x] Rule loader with validation
- [x] Base collector interface
- [x] Unit tests
- [ ] Windows collector
- [ ] Linux collector
- [ ] Detection engine
- [ ] API server
- [ ] Dashboard UI

## Quick Start

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

Currently detecting:
- **WIN-001:** Certutil download abuse

Planned:
- PowerShell encoded commands
- WMI lateral movement
- Regsvr32 DLL execution
- BITSAdmin abuse
- Linux reverse shells
- Cron persistence

## Contributing

See `CONTRIBUTIONS.md` for detailed contribution guidelines.

## License

MIT License - See `LICENSE` file

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Lazarus Group TTPs](https://attack.mitre.org/groups/G0032/)
- [LOLBAS Project](https://lolbas-project.github.io/)