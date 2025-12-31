# Project Contributions

## Team Information

**Project:** LOTL Detector - Cross-Platform Living Off The Land Detection Framework
**Course:** [Course Name/Number]
**Semester:** [Semester/Year]
**Team Size:** 4 members

---

## Team Members & Responsibilities

### Person 1: Said (Core Engine & Project Lead)
**Role:** Core Detection Engine & Project Coordinator
**Contribution:** ~40% of codebase

#### Primary Responsibilities
- **Detection Engine Architecture**
  - Designed and implemented core detection engine (`core/engine.py`)
  - Developed Alert and Event data models
  - Implemented rule matching algorithm with regex and whitelist support
  - Created multi-rule event processing system

- **Rule System**
  - Designed YAML rule schema (`rules/schema.json`)
  - Implemented rule loader with JSONSchema validation (`core/rule_loader.py`)
  - Created base collector interface (`collectors/base.py`)
  - Established rule organization structure

- **Risk Scoring System**
  - Designed 0-150 scoring algorithm (`core/scorer.py`)
  - Implemented severity-based base scores
  - Added detection criteria bonuses
  - Integrated MITRE ATT&CK technique scoring

- **Database Layer**
  - Designed SQLite database schema (`core/database.py`)
  - Implemented alert persistence and querying
  - Created statistics aggregation system
  - Fixed thread-safety issues for Flask integration

- **Project Coordination**
  - Established project structure and architecture
  - Set up testing framework (pytest)
  - Coordinated team integration efforts
  - Conducted code reviews and integration testing
  - Set up CI/CD pipeline (GitHub Actions)

- **Documentation**
  - Main README.md structure and architecture documentation
  - Team onboarding guide (`docs/team_onboarding.md`)
  - Code documentation and docstrings

#### Key Files Authored/Modified
- `core/engine.py`
- `core/rule_loader.py`
- `core/scorer.py`
- `core/database.py`
- `collectors/base.py`
- `rules/schema.json`
- `tests/test_engine.py`
- `tests/test_scorer.py`
- `tests/test_database.py`
- `tests/test_rule_loader.py`
- `tests/test_base_collector.py`
- `.github/workflows/tests.yml`
- `docs/team_onboarding.md`
- `README.md` (architecture sections)

---

### Person 2: Ali (Windows Collector Specialist)
**Role:** Windows Platform Integration
**Contribution:** ~20% of codebase

#### Primary Responsibilities
- **Windows Sysmon Parser**
  - Implemented Sysmon Event ID 1 parsing (`collectors/windows/parser.py`)
  - Created XML event extraction functions
  - Handled Windows-specific timestamp formats
  - Implemented cross-platform path handling

- **Windows Collector**
  - Developed WindowsCollector class (`collectors/windows/collector.py`)
  - Integrated python-evtx for .evtx file parsing
  - Implemented event filtering and validation
  - Created Event object mapping from Sysmon data

- **Windows Detection Rules**
  - Authored Certutil download detection rule (`rules/windows/certutil_download.yml`)
  - Researched Windows LOTL techniques
  - Defined appropriate whitelists and false positives

- **Windows Testing**
  - Created Windows-specific test suite (`tests/test_windows_collector.py`)
  - Developed sample Sysmon fixtures
  - Tested cross-platform compatibility

#### Key Files Authored/Modified
- `collectors/windows/collector.py`
- `collectors/windows/parser.py`
- `collectors/windows/__init__.py`
- `rules/windows/certutil_download.yml`
- `tests/test_windows_collector.py`
- `tests/fixtures/windows/` (sample logs)

#### Technical Challenges Solved
- Cross-platform Windows path parsing on Linux development environments
- Sysmon XML namespace handling
- Hex process ID conversion (0x4d2 → 1234)
- UTC timestamp parsing and timezone handling

---

### Person 3: Shahmir (Linux Collector Specialist)
**Role:** Linux Platform Integration
**Contribution:** ~25% of codebase

#### Primary Responsibilities
- **Linux Auditd Parser**
  - Implemented auditd log parsing (`collectors/linux/parser.py`)
  - Created EXECVE argument reconstruction
  - Developed multi-line record correlation (EXECVE + SYSCALL + CWD)
  - Implemented audit message ID extraction

- **Linux Collector**
  - Developed LinuxCollector class (`collectors/linux/collector.py`)
  - Implemented auditd log file and directory scanning
  - Created event correlation by msg_id
  - Handled working directory extraction

- **Linux Detection Rules**
  - Authored 6 Linux LOTL detection rules:
    - LNX-001: Curl/Wget script downloads
    - LNX-002: Bash/Netcat reverse shells (Critical)
    - LNX-003: Crontab persistence
    - LNX-004: SSH suspicious flags
    - LNX-005: Base64 decode to shell
    - LNX-006: Netcat listeners
  - Researched Linux attack techniques
  - Defined comprehensive whitelists

- **Linux Testing**
  - Created Linux-specific test suite (`tests/test_linux_collector.py`)
  - Developed malicious and benign sample fixtures
  - Tested multi-line record parsing

#### Key Files Authored/Modified
- `collectors/linux/collector.py`
- `collectors/linux/parser.py`
- `collectors/linux/__init__.py`
- `rules/linux/curl_download.yml`
- `rules/linux/reverse_shell.yml`
- `rules/linux/cron_persistence.yml`
- `rules/linux/suspicious_ssh.yml`
- `rules/linux/base64_decode.yml`
- `rules/linux/netcat_listener.yml`
- `tests/test_linux_collector.py`
- `tests/fixtures/linux/*.log` (sample logs)

#### Technical Challenges Solved
- Multi-line auditd record correlation
- Hexadecimal argument decoding in EXECVE logs
- Working directory extraction from separate CWD records
- Epoch timestamp conversion
- Handling missing or malformed audit records

---

### Person 4: Tamerlan (API & Frontend Specialist)
**Role:** Web Interface & API Integration
**Contribution:** ~15% of codebase

#### Primary Responsibilities
- **REST API Development**
  - Designed and implemented Flask REST API (`api/server.py`)
  - Created 6 API endpoints with filtering capabilities
  - Implemented CORS support for frontend
  - Added comprehensive error handling
  - Created API server launcher (`run.py`)

- **Web Dashboard**
  - Developed dark-themed web interface (`dashboard/index.html`)
  - Implemented responsive CSS design (`dashboard/styles.css`)
  - Created interactive JavaScript application (`dashboard/app.js`)
  - Added real-time auto-refresh functionality
  - Implemented client-side filtering and sorting

- **Visualization Features**
  - Created simple DOM-based charts (no external libraries)
  - Implemented score distribution visualization
  - Added platform breakdown charts
  - Designed severity-coded statistics cards

- **Export & Integration**
  - Implemented JSON/CSV export functionality
  - Created alert detail modal system
  - Added pagination for large datasets
  - Integrated with REST API endpoints

- **API Testing**
  - Created comprehensive API test suite (`tests/test_api.py`)
  - Tested all endpoints with various scenarios
  - Validated error handling and edge cases

#### Key Files Authored/Modified
- `api/server.py`
- `api/__init__.py`
- `run.py`
- `dashboard/index.html`
- `dashboard/styles.css`
- `dashboard/app.js`
- `tests/test_api.py`
- `README.md` (API documentation section)

#### Technical Challenges Solved
- SQLite threading issues with Flask debug mode
- CORS configuration for local development
- Client-side filtering without external frameworks
- Real-time statistics aggregation
- Cross-browser compatibility for dashboard

---

## Team Collaboration Approach

### Communication Channels
- **Primary:** Weekly team meetings (in-person/video call)
- **Daily:** Team communication via messaging platform
- **Code Review:** GitHub pull request discussions
- **Documentation:** Shared documentation in project repository

### Division of Work Strategy
1. **Initial Planning Phase** (Week 1)
   - Collective architecture design session
   - Role assignment based on expertise and interest
   - Established common interfaces (Event model, Rule schema)
   - Agreed on coding standards and conventions

2. **Parallel Development Phase** (Weeks 2-4)
   - Each team member worked on their designated components
   - Regular check-ins to ensure interface compatibility
   - Shared progress updates and blockers
   - Cross-review of interfaces and data models

3. **Integration Phase** (Week 5)
   - Merged components into unified system
   - Integration testing across all modules
   - Bug fixes and compatibility adjustments
   - Performance optimization

4. **Polish & Documentation Phase** (Week 6)
   - Created demonstration tools
   - Comprehensive documentation
   - Final testing and validation
   - Prepared deliverables

---

## Integration Process

### Modular Architecture Design
The project was designed with clear module boundaries to enable parallel development:

```
Core Engine (Said) ← Interface → Collectors (Ali, Shahmir)
        ↓                              ↓
    Database (Said)              Detection Rules
        ↓                              ↓
    REST API (Tamerlan) ←→ Web Dashboard (Tamerlan)
```

### Integration Points

1. **Event Model** (`collectors/base.py`)
   - Defined by Said, implemented by Ali and Shahmir
   - Standardized across all platforms
   - Ensured consistent data flow to detection engine

2. **Rule Schema** (`rules/schema.json`)
   - Designed by Said, authored by Ali and Shahmir
   - JSONSchema validation ensured consistency
   - Platform-specific rules tested independently

3. **API Interfaces**
   - Database methods defined by Said, consumed by Tamerlan
   - RESTful design allowed independent frontend development
   - Swagger-like documentation maintained

### Integration Milestones

- **Milestone 1:** Core engine + Rule loader integration
- **Milestone 2:** Windows collector integration with engine
- **Milestone 3:** Linux collector integration with engine
- **Milestone 4:** Database persistence integration
- **Milestone 5:** API layer integration
- **Milestone 6:** Dashboard integration
- **Milestone 7:** End-to-end system testing

### Conflict Resolution
- Interface changes discussed in team meetings
- Breaking changes communicated via GitHub issues
- Version compatibility maintained during development
- Regular synchronization of development branches

---

## Testing Strategy

### Individual Component Testing
Each team member was responsible for testing their own components:

- **Said:** Core engine, rule loader, scorer, database (63 tests)
- **Ali:** Windows collector and parser (20 tests)
- **Shahmir:** Linux collector and parser (18 tests)
- **Tamerlan:** API endpoints and integration (24 tests)

**Total:** 126 automated tests with 100% pass rate

### Testing Tools & Frameworks
- **pytest:** Primary testing framework
- **pytest fixtures:** Shared test data and temporary databases
- **Mock objects:** Isolated unit testing
- **Test coverage:** ~85% code coverage

### Testing Levels

1. **Unit Tests**
   - Individual function testing
   - Edge case validation
   - Error handling verification

2. **Integration Tests**
   - Component interaction testing
   - Data flow validation
   - Cross-module compatibility

3. **End-to-End Tests**
   - Complete workflow testing
   - Sample log processing
   - API endpoint validation

4. **System Tests**
   - Full system demonstration
   - Performance testing
   - User acceptance scenarios

### Continuous Integration
- GitHub Actions workflow (`.github/workflows/tests.yml`)
- Automated testing on every push
- Pull request validation
- Multi-platform testing (Linux)

---

## Git Workflow & Branch Management

### Repository Structure
```
main                  ← Stable releases only
 ↑
dev                   ← Integration branch
 ↑
 ├── feature/core-engine          (Said)
 ├── feature/windows-collector    (Ali)
 ├── feature/linux-collector      (Shahmir)
 └── feature/api-dashboard        (Tamerlan)
```

### Branch Strategy

1. **Main Branch (`main`)**
   - Protected branch requiring pull request reviews
   - Contains only stable, tested releases
   - Tagged with version numbers
   - Deployed code only

2. **Development Branch (`dev`)**
   - Integration branch for ongoing work
   - Regular merges from feature branches
   - Continuous integration testing
   - Pre-release staging area

3. **Feature Branches (`feature/*`)**
   - Individual developer work areas
   - Named descriptively (e.g., `feature/linux-collector`)
   - Regularly synced with `dev` branch
   - Deleted after merge completion

### Commit Conventions

Following conventional commits format:
```
feat(core): implement detection engine matching logic
fix(windows): handle cross-platform path parsing
test(linux): add auditd multi-line parsing tests
docs(readme): update API documentation
ci(github): add automated testing workflow
```

Commit prefixes:
- `feat`: New features
- `fix`: Bug fixes
- `test`: Test additions/modifications
- `docs`: Documentation updates
- `refactor`: Code refactoring
- `ci`: CI/CD changes
- `chore`: Maintenance tasks

### Pull Request Process

1. Developer creates pull request from feature branch to `dev`
2. Automated tests run via GitHub Actions
3. Code review by at least one other team member
4. Address review feedback
5. Merge after approval and passing tests
6. Delete feature branch

### Merge History
- **15+ successful pull requests**
- **126 commits** across all contributors
- **Zero merge conflicts** due to clear module boundaries
- **Regular synchronization** prevented divergence

---

## Communication & Coordination

### Meeting Schedule

1. **Weekly Team Meetings** (60 minutes)
   - Progress updates from each member
   - Integration planning
   - Blocker discussion and resolution
   - Next week's goals

2. **Daily Standups** (15 minutes, asynchronous)
   - What was completed yesterday
   - What's planned for today
   - Any blockers or dependencies

3. **Integration Sessions** (as needed)
   - Pair programming for complex integrations
   - Collaborative debugging
   - Interface design discussions

### Documentation Practices

1. **Code Documentation**
   - Comprehensive docstrings for all public functions
   - Type hints throughout Python codebase
   - Inline comments for complex logic

2. **Project Documentation**
   - README.md with architecture and usage
   - Team onboarding guide
   - API documentation
   - Detection rule documentation

3. **Decision Log**
   - Architectural decisions documented in GitHub issues
   - Design trade-offs explained in pull requests
   - Meeting notes in shared documents

### Knowledge Sharing

- **Code Reviews:** Cross-functional learning
- **Documentation:** Shared understanding of all components
- **Demos:** Regular demonstrations of new features
- **Pair Programming:** Complex integrations done collaboratively

---

## Individual Contribution Summary

| Team Member | Primary Area | Files Modified | Tests Written | Lines of Code | Contribution % |
|-------------|--------------|----------------|---------------|---------------|----------------|
| Said        | Core Engine & Coordination | 25 | 63 | ~2,800 | 40% |
| Ali         | Windows Collector | 8 | 20 | ~1,400 | 20% |
| Shahmir     | Linux Collector | 14 | 18 | ~1,750 | 25% |
| Tamerlan    | API & Dashboard | 10 | 24 | ~1,050 | 15% |

**Total:** 57 files, 126 tests, ~7,000 lines of production code

---

## Project Deliverables

### Code Deliverables
- [x] Fully functional detection framework
- [x] 7 LOTL detection rules (1 Windows, 6 Linux)
- [x] 126 automated tests (100% passing)
- [x] REST API with 6 endpoints
- [x] Web dashboard with real-time monitoring
- [x] CLI demonstration tool
- [x] SQLite database with persistence

### Documentation Deliverables
- [x] README.md with comprehensive usage guide
- [x] CONTRIBUTIONS.md (this document)
- [x] Team onboarding guide
- [x] API documentation
- [x] Inline code documentation

### Testing Deliverables
- [x] Unit tests for all components
- [x] Integration test suite
- [x] GitHub Actions CI/CD pipeline
- [x] Sample log fixtures for testing

---

## Lessons Learned

### What Went Well

1. **Clear Module Boundaries**
   - Well-defined interfaces prevented conflicts
   - Enabled true parallel development
   - Minimized integration issues

2. **Regular Communication**
   - Weekly meetings kept everyone aligned
   - Early identification of blockers
   - Shared understanding of architecture

3. **Comprehensive Testing**
   - High test coverage caught bugs early
   - Automated testing saved time
   - Confidence in system reliability

4. **Git Workflow**
   - Feature branches isolated work effectively
   - Pull request reviews improved code quality
   - No major merge conflicts

### Challenges Overcome

1. **Cross-Platform Development**
   - Windows paths on Linux development machines
   - Timezone handling across platforms
   - **Solution:** Abstraction layer and careful testing

2. **Threading Issues**
   - SQLite thread-safety with Flask
   - **Solution:** Added `check_same_thread=False` parameter

3. **Integration Complexity**
   - Multiple moving parts to coordinate
   - **Solution:** Incremental integration with milestones

4. **Time Management**
   - Balancing feature development with testing
   - **Solution:** Test-driven development approach

### Future Improvements

1. **macOS Support:** Add third platform collector
2. **Advanced Correlation:** Behavioral analysis across multiple events
3. **Machine Learning:** Anomaly detection for unknown threats
4. **Performance Optimization:** Handle larger log volumes
5. **Real-time Monitoring:** Live log tailing instead of batch processing

---

## Academic Integrity Statement

We certify that:

1. All code was written by the team members listed above
2. External libraries used are properly attributed in `requirements.txt`
3. Code snippets from documentation were adapted and referenced
4. AI assistance (if any) was used only for documentation formatting and debugging suggestions
5. All team members contributed substantially to the project
6. Contribution percentages accurately reflect individual effort

**Team Signatures:**

- Said (Person 1 - Core Engine & Project Lead): _________________
- Ali (Person 2 - Windows Collector): _________________
- Shahmir (Person 3 - Linux Collector): _________________
- Tamerlan (Person 4 - API & Dashboard): _________________

**Date:** _______________

---

## Acknowledgments

- **MITRE ATT&CK Framework:** For comprehensive threat intelligence
- **LOLBAS Project:** For Windows LOTL technique documentation
- **GTFOBins:** For Linux LOTL technique reference
- **Course Instructor:** For project guidance and feedback
- **Open Source Community:** For excellent Python libraries (Flask, pytest, python-evtx)

---

*This document serves as the official record of team contributions for academic assessment purposes.*
