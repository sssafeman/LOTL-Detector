# Score Calibration

The v2 scoring weights were specified in the MoA design
(`docs/moa-scoring-design-2026-07-11.md`) but never validated against
labeled data. With a benign and malicious fixture corpus now covering
all 22 atomic rules, this document records the calibration run, the
observed distribution, and the conclusion.

The calibration is locked by `tests/test_score_calibration.py`: any
weight change that shifts a rule's band fails a test naming that rule.

## Method

Every malicious fixture is run through the real pipeline (collector to
engine to scorer) and the resulting alert's severity subscore,
confidence subscore, final score, and risk band are recorded. Benign
fixtures are excluded because they intentionally fail detection and
produce no alert, so they contribute no score to calibrate.

Regenerate the table with:

```bash
python3 - <<'PY'
from pathlib import Path
from core.rule_loader import RuleLoader
from core.engine import DetectionEngine
from collectors.windows.collector import WindowsCollector
from collectors.linux.collector import LinuxCollector
engine = DetectionEngine(RuleLoader().load_rules_directory("rules"))
for sub, col, glob in (("windows", WindowsCollector(), "*.xml"),
                       ("linux", LinuxCollector(), "*.log")):
    for p in sorted(Path(f"tests/fixtures/{sub}").glob(glob)):
        if "benign" in p.name:
            continue
        for e in col.collect_events(str(p)):
            for a in engine.match_event(e):
                print(a.rule_id, a.severity, a.confidence_subscore,
                      a.score, a.risk_band)
PY
```

## Observed Distribution

23 malicious detections across 22 rules (LNX-001 fires twice on its
multi-line fixture).

| Rule | Severity | Confidence | Score | Band |
|------|----------|-----------:|------:|------|
| WIN-001 | high | 56 | 75 | medium |
| WIN-002 | high | 68 | 86 | medium |
| WIN-003 | high | 63 | 81 | medium |
| WIN-004 | high | 51 | 71 | medium |
| WIN-005 | high | 56 | 75 | medium |
| WIN-006 | medium | 61 | 53 | low |
| WIN-007 | high | 75 | 91 | high |
| WIN-008 | high | 56 | 75 | medium |
| WIN-009 | critical | 65 | 111 | high |
| WIN-010 | high | 60 | 79 | medium |
| WIN-011 | high | 70 | 87 | medium |
| LNX-001 | high | 50 | 70 | medium |
| LNX-002 | critical | 40 | 83 | medium |
| LNX-003 | high | 51 | 71 | medium |
| LNX-004 | medium | 51 | 47 | low |
| LNX-005 | high | 52 | 72 | medium |
| LNX-006 | high | 51 | 71 | medium |
| LNX-007 | critical | 60 | 105 | high |
| LNX-008 | high | 56 | 75 | medium |
| LNX-009 | high | 65 | 83 | medium |
| LNX-010 | high | 60 | 79 | medium |
| LNX-011 | high | 70 | 87 | medium |

Band counts: low 2, medium 18, high 3, critical 0. Score range 47 to 111.

## Interpretation

The distribution matches the spec's intended band invariants, so the
weights are correctly calibrated, not miscalibrated.

- **Clustering in medium is by design.** A single atomic detection of a
  dual-use LOLBin (certutil, wmic, wget) is genuinely ambiguous without
  context. The medium band means "meaningful impact and evidence,
  analyst review warranted," which is the honest label for one event of
  living-off-the-land activity.

- **The high band requires strong confidence.** Per the spec, a high
  severity rule needs confidence about 74 to reach the high band. Only
  WIN-007 (a PowerShell WebClient cradle with encoded and download
  anomalies, confidence 75) clears it among high rules. Critical rules
  clear it more easily: WIN-009 (SAM hive export) and LNX-007 (Python
  reverse shell) both land in high on confidence alone.

- **No atomic detection reaches critical.** Critical band (score 120)
  needs a critical rule at confidence about 74. No single event in the
  corpus carries that much corroboration. This is where the correlation
  layer earns its place: a full chain match escalates the same behavior
  to the high or critical band (for example CHAIN-WIN-001 scores 128 on
  a two-stage Office to encoded PowerShell match).

- **Medium rules stay low.** WIN-006 (MSHTA) and LNX-004 (suspicious
  SSH) are medium severity, so they cannot exceed the medium band, and
  at their observed confidence they land in low. That is the intended
  "low impact activity cannot be inflated by confidence bonuses" rule.

## Structural Invariants (locked in tests)

1. Only critical-severity rules can reach the critical band.
2. Low rules never exceed low; medium rules never exceed medium, even at
   maximum confidence (verified against the scorer directly).
3. Criteria deltas are monotonic non-decreasing.
4. Each confidence factor moves the score in its documented direction:
   more matched criteria, a suspicious parent, and command anomalies
   raise it; benign lineage, whitelist adjacency, and partial matches
   lower it.
5. A confirmed-malicious match scores strictly above a benign-context
   control for the same rule.

## Decision

The weights are kept as specified. The spec explicitly warns against
tuning weights merely to reproduce a target distribution, and the corpus
confirms the current weights separate detections by genuine ambiguity
rather than needing adjustment. Recalibrate only when a labeled corpus of
production events (with analyst-confirmed true and false positives)
becomes available, at which point the per-rule band lock in the test
suite is the safety net for any change.
