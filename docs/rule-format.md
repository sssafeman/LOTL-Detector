# Detection Rule Format

## Overview

Rules are written in YAML and validated against `rules/schema.json`.

## Required Fields
```yaml
name: "Human-readable rule name"
id: "Unique ID in format WIN-001, LNX-001, MAC-001"
platform: "windows | linux | macos"
severity: "low | medium | high | critical"
detection:
  # At minimum, specify process_name
  process_name: "executable.exe"
```

## Optional Fields

### MITRE ATT&CK Mapping
```yaml
mitre_attack:
  - T1105  # Ingress Tool Transfer
  - T1059.001  # PowerShell
```

### Description
```yaml
description: |
  Multi-line explanation of what this rule detects,
  why it's suspicious, and context about the technique.
```

### Detection Logic

**Process matching:**
```yaml
detection:
  process_name: "powershell.exe"
  command_contains:  # All must be present (AND logic)
    - "-encodedcommand"
    - "-windowstyle hidden"
  command_regex: ".*-enc.*IEX.*"  # Regex match
```

**Parent process:**
```yaml
detection:
  process_name: "cmd.exe"
  parent_process: "winword.exe"  # Spawned by Word
```

### Whitelisting
```yaml
whitelist:
  users:
    - "SYSTEM"
    - "AdminUser"
  parent_processes:
    - "msiexec.exe"
  paths:
    - "C:\\Windows\\System32"
```

### False Positives
```yaml
false_positives:
  - "Legitimate use case 1"
  - "Legitimate use case 2"
```

### Response Actions
```yaml
response:
  - "Check file hash"
  - "Review user activity"
  - "Isolate endpoint if confirmed malicious"
```

## Example: Complete Rule
```yaml
name: "PowerShell Encoded Command"
id: "WIN-002"
platform: windows
severity: high
mitre_attack:
  - T1059.001
  - T1027

description: |
  Detects PowerShell execution with base64-encoded commands.
  Commonly used to hide malicious scripts from casual inspection.

detection:
  process_name: "powershell.exe"
  command_contains:
    - "-enc"
  OR:
    command_contains:
      - "-encodedcommand"

false_positives:
  - "Some enterprise management tools use encoded commands"

whitelist:
  parent_processes:
    - "sccm.exe"

response:
  - "Decode the base64 command"
  - "Analyze decoded script for malicious indicators"
  - "Check parent process legitimacy"
```

## Validation

Validate your rule:
```bash
python -c "
from core.rule_loader import RuleLoader
loader = RuleLoader()
rule = loader.load_rule_file('rules/windows/your_rule.yml')
print(f'Valid: {rule.name}')
"
```