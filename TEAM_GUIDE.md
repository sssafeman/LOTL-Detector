# Team Development Guide

## Getting Started

### For Person 2 (Windows Collector)
1. Fork/clone the repo
2. Create branch: `git checkout -b feature/windows-collector`
3. Read `collectors/base.py` - you MUST implement this interface
4. Read `docs/rule-format.md` - this is how you write detection rules
5. Start here: `collectors/windows/collector.py`

**Your deliverables:**
- Windows collector implementing `BaseCollector`
- 8-10 Windows LOTL detection rules
- Tests for your collector
- Sample Sysmon logs (benign + malicious)

**Resources:**
- [Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Python-evtx library](https://github.com/williballenthin/python-evtx)

### For Person 3 (Linux Collector)
1. Fork/clone the repo
2. Create branch: `git checkout -b feature/linux-collector`
3. Read `collectors/base.py` - you MUST implement this interface
4. Read `docs/rule-format.md` - this is how you write detection rules
5. Start here: `collectors/linux/collector.py`

**Your deliverables:**
- Linux collector implementing `BaseCollector`
- 6-8 Linux LOTL detection rules
- Tests for your collector
- Sample auditd logs (benign + malicious)

**Resources:**
- [auditd documentation](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-system_auditing)
- [Python-auditd library](https://github.com/linux-audit/audit-python)

### For Person 4 (API & Dashboard)
1. Fork/clone the repo
2. Create branch: `git checkout -b feature/api-dashboard`
3. Read `collectors/base.py` - understand the Event format
4. Start here: `api/server.py` and `dashboard/index.html`

**Your deliverables:**
- REST API with endpoints: /alerts, /rules, /stats
- Web dashboard showing alerts
- Basic visualization (charts/graphs)

**Resources:**
- [Flask quickstart](https://flask.palletsprojects.com/en/stable/quickstart/)
- [FastAPI tutorial](https://fastapi.tiangolo.com/tutorial/)

## Development Workflow

### Daily Updates (Required)
Post in Discord/Slack:
```
## [Your Name] - Date

Completed:
- Item 1
- Item 2

Blocked by:
- Waiting for X from Person Y

Next up:
- Item 3
```

### Before Starting Work
```bash
git checkout dev
git pull origin dev
git checkout feature/your-feature
git merge dev  # Get latest changes
```

### Submitting Work
```bash
# Test first!
pytest tests/

# Commit with good messages
git add .
git commit -m "feat(windows): add sysmon parser"
git push origin feature/your-feature

# Create PR on GitHub to dev branch
```

### Commit Message Format
```
feat(component): description      # New feature
fix(component): description       # Bug fix
test(component): description      # Tests
docs: description                 # Documentation
```

## Testing Your Code

**Everyone must write tests:**
```python
# tests/test_your_module.py
def test_something():
    # Arrange
    setup_data = ...
    
    # Act
    result = your_function(setup_data)
    
    # Assert
    assert result == expected_value
```

Run tests:
```bash
pytest tests/ -v
pytest tests/test_your_module.py -v  # Specific file
```

## Integration Points

### Person 2 & 3 depend on Person 1:
- Rule schema (`rules/schema.json`)
- BaseCollector interface (`collectors/base.py`)
- Event dataclass (`collectors/base.py`)

### Person 4 depends on Person 1:
- Event format for API responses
- Database schema

### Nobody blocks anybody:
- Use mock data until real components ready
- Implement your interface even if others aren't done

## Common Issues

**"I can't start until Person 1 finishes"**
→ Wrong! Use the interface definitions and create mock data

**"My tests fail on GitHub Actions but pass locally"**
→ Check file paths (use Path), check dependencies in requirements.txt

**"Merge conflicts when pulling dev"**
→ Ask for help in team channel, don't force push

**"My collector doesn't match the interface"**
→ Run: `python -c "from collectors.base import BaseCollector; from collectors.yourmodule import YourCollector; issubclass(YourCollector, BaseCollector)"`

## Getting Help

1. Check docs first (README.md, docs/, code comments)
2. Search issues on GitHub
3. Post in team channel with:
   - What you're trying to do
   - What you expected
   - What actually happened
   - Code snippet

## Code Style

- Use type hints
- Write docstrings for functions
- Keep functions under 50 lines
- Don't repeat yourself (DRY principle)
- Comment the "why", not the "what"