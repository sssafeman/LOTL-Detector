# Detection Coverage Matrix

Maps every bundled rule to MITRE ATT&CK techniques and the LOLBAS
(Windows) or GTFOBins (Linux) entry it detects abuse of. Generated
against 22 atomic rules and 4 correlation chains.

Regenerate the inventory with:

```bash
python3 -c "from core.rule_loader import RuleLoader; \
[print(r.id, r.platform, r.severity, ';'.join(r.mitre_attack)) \
 for r in sorted(RuleLoader().load_rules_directory('rules'), key=lambda r: r.id)]"
```

## Windows Atomic Rules

| Rule | Name | Severity | Abused Binary (LOLBAS) | ATT&CK Techniques |
|------|------|----------|------------------------|-------------------|
| WIN-001 | Certutil Download Suspicious File | high | certutil.exe | T1105 Ingress Tool Transfer, T1140 Deobfuscate/Decode |
| WIN-002 | PowerShell Encoded Command Execution | high | powershell.exe | T1059.001 PowerShell, T1027 Obfuscated Files |
| WIN-003 | WMI Lateral Movement | high | wmic.exe | T1047 WMI, T1021 Remote Services |
| WIN-004 | Regsvr32 Whitelisting Bypass | high | regsvr32.exe | T1218.010 Regsvr32, T1218 System Binary Proxy |
| WIN-005 | BITSAdmin Download Abuse | high | bitsadmin.exe | T1197 BITS Jobs, T1105 Ingress Tool Transfer |
| WIN-006 | MSHTA Suspicious Script Execution | medium | mshta.exe | T1218.005 Mshta, T1059 Command and Scripting |
| WIN-007 | PowerShell WebClient Download Cradle | high | powershell.exe | T1059.001 PowerShell, T1105 Ingress Tool Transfer |
| WIN-008 | Rundll32 JavaScript Proxy Execution | high | rundll32.exe | T1218.011 Rundll32 |
| WIN-009 | Registry Hive Export for Credential Access | critical | reg.exe | T1003.002 Security Account Manager |
| WIN-010 | Msiexec Remote Package Execution | high | msiexec.exe | T1218.007 Msiexec, T1105 Ingress Tool Transfer |
| WIN-011 | CMSTP Suspicious INF Execution | high | cmstp.exe | T1218.003 CMSTP |

## Linux Atomic Rules

| Rule | Name | Severity | Abused Binary (GTFOBins) | ATT&CK Techniques |
|------|------|----------|--------------------------|-------------------|
| LNX-001 | Curl/Wget Downloading Suspicious Script | high | curl, wget | T1105 Ingress Tool Transfer, T1059.004 Unix Shell |
| LNX-002 | Bash/Netcat Reverse Shell | critical | bash, nc | T1059.004 Unix Shell, T1071.001 Web Protocols |
| LNX-003 | Crontab Modification for Persistence | high | crontab | T1053.003 Cron |
| LNX-004 | SSH with Suspicious Flags | medium | ssh | T1021.004 SSH, T1572 Protocol Tunneling |
| LNX-005 | Base64 Decode Piped to Shell | high | base64, sh | T1027 Obfuscated Files, T1059.004 Unix Shell |
| LNX-006 | Netcat Listening for Connections | high | nc | T1071 Application Layer Protocol, T1059.004 Unix Shell |
| LNX-007 | Python Reverse Shell One-Liner | critical | python | T1059.006 Python |
| LNX-008 | Systemd Service Persistence | high | systemctl, tee | T1543.002 Systemd Service |
| LNX-009 | LD_PRELOAD from User-Writable Directory | high | ld.so preload | T1574.006 Dynamic Linker Hijacking |
| LNX-010 | SSH Authorized Keys Modification | high | ssh authorized_keys | T1098.004 SSH Authorized Keys |
| LNX-011 | Wget Download and Immediate Execution | high | wget | T1105 Ingress Tool Transfer, T1059.004 Unix Shell |

## Correlation Chains

Chains combine multiple techniques across process lineage. Their
technique lists span the full behavior sequence.

| Chain | Name | Severity | ATT&CK Techniques |
|-------|------|----------|-------------------|
| CHAIN-WIN-001 | Office to Obfuscated PowerShell | critical | T1566.001 Spearphishing Attachment, T1059.001 PowerShell, T1027 Obfuscated Files |
| CHAIN-WIN-002 | Script Host to LOLBin Downloader | high | T1059.005 Visual Basic, T1218 System Binary Proxy, T1105 Ingress Tool Transfer |
| CHAIN-LNX-001 | Web Server to Shell to Payload Retrieval | critical | T1190 Exploit Public-Facing App, T1059.004 Unix Shell, T1105 Ingress Tool Transfer |
| CHAIN-LNX-002 | Cron to Shell to Remote Download | high | T1053.003 Cron, T1059.004 Unix Shell, T1105 Ingress Tool Transfer |

## Coverage by ATT&CK Tactic

Techniques above grouped by their primary tactic. A technique can serve
several tactics in the wild; this lists the tactic each rule targets.

| Tactic | Techniques Covered | Rules |
|--------|--------------------|-------|
| Initial Access | T1190, T1566.001 | CHAIN-LNX-001, CHAIN-WIN-001 |
| Execution | T1059.001, T1059.004, T1059.005, T1059.006, T1047 | WIN-002, WIN-003, WIN-007, LNX-001, LNX-002, LNX-005, LNX-006, LNX-007, LNX-011, chains |
| Persistence | T1053.003, T1543.002, T1098.004, T1197 | LNX-003, LNX-008, LNX-010, WIN-005, CHAIN-LNX-002 |
| Privilege Escalation | T1574.006 | LNX-009 |
| Defense Evasion | T1027, T1140, T1218.003, T1218.005, T1218.007, T1218.010, T1218.011 | WIN-001, WIN-002, WIN-004, WIN-006, WIN-008, WIN-010, WIN-011, LNX-005 |
| Credential Access | T1003.002 | WIN-009 |
| Lateral Movement | T1021, T1021.004 | WIN-003, LNX-004 |
| Command and Control | T1071, T1071.001, T1105, T1572 | WIN-001, WIN-005, WIN-007, WIN-010, LNX-001, LNX-002, LNX-004, LNX-006, LNX-011, chains |

## Known Gaps

The following high-value LOTL techniques are not yet covered and are
candidate rules for future work:

- T1053.005 Scheduled Task (schtasks.exe) on Windows.
- T1218.001 Compiled HTML File (hh.exe) and other InstallUtil, MSBuild
  proxy executions.
- T1055 Process Injection patterns.
- T1546 Event Triggered Execution (WMI event subscriptions).
- T1552 Unsecured Credentials beyond the SAM hive export.
- macOS coverage is entirely absent (collectors are stubs).

Correlation currently covers four chains. Additional high-signal chains
worth adding: PowerShell to certutil/bitsadmin download, scheduled task
creation from an interactive shell, and credential dumping following
lateral movement.
