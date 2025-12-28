# Architecture Documentation

## System Overview

LOTL Detector follows a modular, platform-agnostic architecture.

### Component Diagram
```
┌─────────────────────────────────────┐
│     Dashboard (React/HTML)          │ 
│  - Alert visualization              │
│  - Rule management                  │
└──────────────┬──────────────────────┘
               │ REST API
┌──────────────▼──────────────────────┐
│     API Server (Flask/FastAPI)      │ 
│  - /alerts (GET, POST)              │
│  - /rules (GET)                     │
│  - /stats (GET)                     │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│     Detection Engine                │ 
│  - Rule matching                    │
│  - Scoring/correlation              │
│  - Alert generation                 │
└──────────────┬──────────────────────┘
               │
       ┌───────┴────────┐
       │ Rule Loader    │ 
       │ - YAML parser  │
       │ - Validation   │
       └────────────────┘
               │
    ┌──────────┴──────────┐
    ▼                     ▼
┌──────────┐        ┌──────────┐
│ Windows  │        │  Linux   │
│Collector │        │Collector │
│          │        │          │
│ Person 2 │        │ Person 3 │
└────┬─────┘        └────┬─────┘
     │                   │
     ▼                   ▼
┌─────────┐         ┌─────────┐
│ Sysmon  │         │ auditd  │
│  Logs   │         │  Logs   │
└─────────┘         └─────────┘
```

## Data Flow

1. **Log Collection:** Platform collectors parse OS-specific logs into standardized Event objects
2. **Rule Matching:** Detection engine applies rules to events
3. **Alert Generation:** Matching events become alerts with severity and context
4. **Storage:** Alerts saved to SQLite database
5. **API Access:** Dashboard queries alerts via REST API
6. **Visualization:** Users see alerts in web interface

## Key Design Decisions

### Standardized Event Format
All collectors produce `Event` objects with consistent fields regardless of platform.

**Benefits:**
- Detection engine is platform-agnostic
- Easy to add new platforms
- Simplifies testing

### YAML Rule Format
Human-readable, version-controlled, and validated against JSON Schema.

**Benefits:**
- Non-programmers can write rules
- Git tracks rule changes
- Schema catches errors early

### Abstract Collector Pattern
`BaseCollector` defines interface all platforms must implement.

**Benefits:**
- Enforces consistency
- Person 2 and 3 work independently
- Easy to mock for testing

## Database Schema
```sql
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME,
    rule_id TEXT,
    rule_name TEXT,
    severity TEXT,
    platform TEXT,
    process_name TEXT,
    command_line TEXT,
    user TEXT,
    event_data JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## Future Enhancements

- Real-time agents using ETW (Windows) and eBPF (Linux)
- Machine learning-based anomaly detection
- Process tree correlation
- Network activity enrichment