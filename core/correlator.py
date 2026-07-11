"""
Correlation layer: matches multi-stage behavior chains across process lineage.

Sits above atomic rules. Chain rules describe an ordered sequence of stage
matchers linked by parent-child or ancestor-descendant relations inside a
bounded time window. Matching a full chain emits an Incident that preserves
the supporting events; atomic alerts are unaffected.

Scoring reuses the v2 multiplicative model:
score = clamp(round(severity * (0.25 + 0.75 * confidence / 100) * 1.5), 0, 150)
Confidence starts at 70 for a complete lineage match, gains 10 when every
stage matched an observed event (no phantom parents), and gains 5 per stage
beyond the second, capped at 100.
"""
import json
import re
import jsonschema
import yaml
from dataclasses import dataclass, field
from datetime import datetime
from math import floor
from pathlib import Path
from typing import Any, Dict, List, Optional

from collectors.base import Event
from core.engine import normalize_process_name
from core.process_tree import ProcessNode, build_forest
from core.scorer import SEVERITY_SUBSCORES, Scorer
import logging

logger = logging.getLogger(__name__)

CORRELATION_VERSION = 1

CHAIN_CONFIDENCE_BASE = 70
CHAIN_CONFIDENCE_ALL_CONCRETE = 10
CHAIN_CONFIDENCE_PER_EXTRA_STAGE = 5


class ChainStage:
    """One stage of a chain rule: a node matcher plus its lineage relation."""

    def __init__(self, stage_dict: Dict[str, Any], chain_id: str, index: int):
        self.name: str = stage_dict["name"]
        # Relation to the previous stage's matched node. The first stage
        # anchors the chain, so its relation is ignored.
        self.relation: str = stage_dict.get("relation", "child")
        self.match: Dict[str, Any] = stage_dict["match"]
        self.index = index

        self._compiled: Dict[str, Any] = {}
        for regex_key in ("command_regex", "user_pattern"):
            pattern = self.match.get(regex_key)
            if pattern:
                try:
                    self._compiled[regex_key] = re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    raise ValueError(
                        f"Chain {chain_id} stage '{self.name}' has invalid "
                        f"{regex_key} '{pattern}': {e}"
                    )

    def matches(self, node: ProcessNode, platform: str) -> bool:
        """
        Check whether a process node satisfies this stage.

        Phantom nodes carry only a process name, so any stage that
        constrains the command line or user cannot match them.
        """
        match = self.match

        if node.is_phantom and any(
            key in match
            for key in (
                "command_contains", "command_contains_any",
                "command_regex", "user_pattern",
            )
        ):
            return False

        actual_base = normalize_process_name(node.process_name, platform)

        if "process_name" in match:
            expected = normalize_process_name(match["process_name"], platform)
            if actual_base != expected:
                return False

        if "process_name_any" in match:
            expected_any = {
                normalize_process_name(name, platform)
                for name in match["process_name_any"]
            }
            if actual_base not in expected_any:
                return False

        command_lower = node.command_line.lower()

        if "command_contains" in match:
            if not all(item.lower() in command_lower for item in match["command_contains"]):
                return False

        if "command_contains_any" in match:
            if not any(item.lower() in command_lower for item in match["command_contains_any"]):
                return False

        if "command_regex" in match:
            if not self._compiled["command_regex"].search(node.command_line):
                return False

        if "user_pattern" in match:
            if not self._compiled["user_pattern"].search(node.user):
                return False

        return True


class ChainRule:
    """A multi-stage correlation rule loaded from YAML."""

    def __init__(self, rule_dict: Dict[str, Any]):
        self.name: str = rule_dict["name"]
        self.id: str = rule_dict["id"]
        self.platform: str = rule_dict["platform"]
        self.severity: str = rule_dict["severity"]
        self.mitre_attack: List[str] = rule_dict.get("mitre_attack", [])
        self.description: str = rule_dict.get("description", "")
        self.window_seconds: int = rule_dict["window_seconds"]
        self.false_positives: List[str] = rule_dict.get("false_positives", [])
        self.response: List[str] = rule_dict.get("response", [])
        self.stages: List[ChainStage] = [
            ChainStage(stage, self.id, i)
            for i, stage in enumerate(rule_dict["stages"])
        ]

    def __repr__(self) -> str:
        return f"ChainRule(id={self.id}, stages={len(self.stages)}, platform={self.platform})"


@dataclass
class Incident:
    """
    A correlated incident: one full chain match with supporting events.
    """
    chain_id: str
    chain_name: str
    severity: str
    platform: str
    host: str
    mitre_attack: List[str]
    description: str
    response: List[str]
    window_seconds: int
    first_timestamp: Optional[datetime]
    last_timestamp: Optional[datetime]
    stages: List[Dict[str, Any]] = field(default_factory=list)
    score: int = 0
    risk_band: str = "low"
    confidence: int = 0
    correlation_version: int = CORRELATION_VERSION

    def to_dict(self) -> Dict[str, Any]:
        """Convert incident to dictionary for storage and API responses."""
        return {
            "chain_id": self.chain_id,
            "chain_name": self.chain_name,
            "severity": self.severity,
            "platform": self.platform,
            "host": self.host,
            "mitre_attack": self.mitre_attack,
            "description": self.description,
            "response": self.response,
            "window_seconds": self.window_seconds,
            "first_timestamp": (
                self.first_timestamp.isoformat() if self.first_timestamp else None
            ),
            "last_timestamp": (
                self.last_timestamp.isoformat() if self.last_timestamp else None
            ),
            "stages": self.stages,
            "score": self.score,
            "risk_band": self.risk_band,
            "confidence": self.confidence,
            "correlation_version": self.correlation_version,
        }

    def __repr__(self) -> str:
        return (
            f"Incident(chain_id={self.chain_id}, score={self.score}, "
            f"risk_band={self.risk_band}, stages={len(self.stages)})"
        )


class ChainRuleLoader:
    """Loads and validates chain rules from YAML files."""

    def __init__(self, schema_path: str = "rules/chain-schema.json"):
        self.schema_path = Path(schema_path)
        with open(self.schema_path, "r") as f:
            self.schema = json.load(f)
        self.chains: List[ChainRule] = []

    def load_chain_file(self, chain_path: str) -> ChainRule:
        """Load and validate a single chain rule file."""
        with open(chain_path, "r") as f:
            chain_dict = yaml.safe_load(f)
        jsonschema.validate(instance=chain_dict, schema=self.schema)
        chain = ChainRule(chain_dict)
        logger.info(f"Loaded chain rule: {chain.id} - {chain.name}")
        return chain

    def load_chains_directory(
        self, chains_dir: str, platform: Optional[str] = None
    ) -> List[ChainRule]:
        """
        Load all chain rules from a directory.

        Raises ValueError on duplicate chain IDs. Individual files that
        fail validation are logged and skipped, matching RuleLoader.
        """
        chains_path = Path(chains_dir)
        chains: List[ChainRule] = []
        seen_ids: Dict[str, str] = {}

        if not chains_path.exists():
            logger.info(f"Chain rules directory not found, skipping: {chains_dir}")
            self.chains = []
            return []

        chain_files = sorted(
            list(chains_path.glob("**/*.yml")) + list(chains_path.glob("**/*.yaml"))
        )
        for chain_file in chain_files:
            try:
                chain = self.load_chain_file(chain_file)
                if chain.id in seen_ids:
                    raise ValueError(
                        f"Duplicate chain ID {chain.id} in {chain_file} "
                        f"(already defined in {seen_ids[chain.id]})"
                    )
                seen_ids[chain.id] = str(chain_file)
                if platform is None or chain.platform == platform:
                    chains.append(chain)
            except Exception as e:
                logger.error(f"Failed to load chain rule {chain_file}: {e}")

        self.chains = chains
        logger.info(f"Loaded {len(chains)} chain rules from {chains_dir}")
        return chains


def load_chain_rules(
    chains_dir: str = "rules/correlation", platform: Optional[str] = None
) -> List[ChainRule]:
    """Convenience function to load chain rules."""
    loader = ChainRuleLoader()
    return loader.load_chains_directory(chains_dir, platform)


class Correlator:
    """
    Matches chain rules against process lineage built from event batches.

    Deterministic: nodes are examined in (timestamp, pid, key) order and
    the earliest valid completion is taken for each anchor, so identical
    input always yields identical incidents (replay-safe).
    """

    def __init__(self, chains: List[ChainRule]):
        self.chains = chains
        logger.info(f"Correlator initialized with {len(chains)} chain rules")

    def correlate(self, events: List[Event]) -> List[Incident]:
        """
        Build per-host process trees and match all chain rules.

        Args:
            events: Normalized events from any collector

        Returns:
            List of Incident objects, ordered by first timestamp then chain ID
        """
        if not self.chains or not events:
            return []

        incidents: List[Incident] = []
        forest = build_forest(events)
        for host in sorted(forest.keys()):
            nodes = forest[host]
            for chain in self.chains:
                incidents.extend(self._match_chain(chain, nodes, host))

        incidents.sort(
            key=lambda i: (
                i.first_timestamp.isoformat() if i.first_timestamp else "",
                i.chain_id,
            )
        )
        logger.info(
            f"Correlated {len(events)} events into {len(incidents)} incidents"
        )
        return incidents

    def _match_chain(
        self, chain: ChainRule, nodes: List[ProcessNode], host: str
    ) -> List[Incident]:
        """Find all matches of one chain within one host's tree."""
        platform_nodes = [n for n in nodes if n.platform == chain.platform]
        anchors = sorted(
            (n for n in platform_nodes if chain.stages[0].matches(n, chain.platform)),
            key=ProcessNode.sort_key,
        )

        incidents: List[Incident] = []
        seen_paths = set()
        for anchor in anchors:
            path = self._extend(chain, 1, anchor, [anchor])
            if path is None:
                continue
            path_key = tuple(node.key for node in path)
            if path_key in seen_paths:
                continue
            seen_paths.add(path_key)
            incidents.append(self._build_incident(chain, path, host))
        return incidents

    def _extend(
        self,
        chain: ChainRule,
        stage_index: int,
        prev_node: ProcessNode,
        path: List[ProcessNode],
    ) -> Optional[List[ProcessNode]]:
        """
        Depth-first search for the remaining stages.

        Returns the completed path, or None when no completion exists
        under the lineage, ordering, and window constraints.
        """
        if stage_index >= len(chain.stages):
            return path

        stage = chain.stages[stage_index]
        if stage.relation == "descendant":
            candidates = list(prev_node.iter_descendants())
        else:
            candidates = list(prev_node.children)

        candidates = sorted(
            (c for c in candidates if stage.matches(c, chain.platform)),
            key=ProcessNode.sort_key,
        )

        for candidate in candidates:
            if not self._time_valid(chain, path, candidate):
                continue
            result = self._extend(chain, stage_index + 1, candidate, path + [candidate])
            if result is not None:
                return result
        return None

    @staticmethod
    def _time_valid(
        chain: ChainRule, path: List[ProcessNode], candidate: ProcessNode
    ) -> bool:
        """
        Enforce chronological ordering and the chain's time window.

        Phantom nodes have no timestamp and are exempt; the window is
        measured between the earliest and latest observed events in the
        prospective path.
        """
        if candidate.timestamp is None:
            return True

        concrete = [n.timestamp for n in path if n.timestamp is not None]
        if not concrete:
            return True

        if candidate.timestamp < max(concrete):
            return False

        span = (candidate.timestamp - min(concrete)).total_seconds()
        return span <= chain.window_seconds

    def _build_incident(
        self, chain: ChainRule, path: List[ProcessNode], host: str
    ) -> Incident:
        """Assemble an Incident from a completed chain path."""
        stages: List[Dict[str, Any]] = []
        for stage, node in zip(chain.stages, path):
            stages.append({
                "stage": stage.name,
                "node_key": node.key,
                "phantom": node.is_phantom,
                "process_name": node.process_name,
                "pid": node.pid,
                "timestamp": node.timestamp.isoformat() if node.timestamp else None,
                "event": node.event.to_dict() if node.event else None,
            })

        concrete_ts = [n.timestamp for n in path if n.timestamp is not None]
        first_ts = min(concrete_ts) if concrete_ts else None
        last_ts = max(concrete_ts) if concrete_ts else None

        all_concrete = all(not n.is_phantom for n in path)
        confidence = CHAIN_CONFIDENCE_BASE
        if all_concrete:
            confidence += CHAIN_CONFIDENCE_ALL_CONCRETE
        confidence += CHAIN_CONFIDENCE_PER_EXTRA_STAGE * max(0, len(path) - 2)
        confidence = min(confidence, 100)

        severity_sub = SEVERITY_SUBSCORES[chain.severity]
        raw = severity_sub * (0.25 + 0.75 * confidence / 100.0) * 1.5
        # Round half up like the alert scorer, not banker's rounding
        score = max(0, min(150, floor(raw + 0.5)))

        return Incident(
            chain_id=chain.id,
            chain_name=chain.name,
            severity=chain.severity,
            platform=chain.platform,
            host=host,
            mitre_attack=chain.mitre_attack,
            description=chain.description,
            response=chain.response,
            window_seconds=chain.window_seconds,
            first_timestamp=first_ts,
            last_timestamp=last_ts,
            stages=stages,
            score=score,
            risk_band=Scorer._risk_band(score),
            confidence=confidence,
        )
