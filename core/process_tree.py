"""
Process tree construction for lineage-based correlation.

Builds per-host process trees from normalized events. Parent links are
resolved by parent_process_id with a basename guard against pid reuse.
When a referenced parent has no event of its own (it started before log
collection began), a phantom node is synthesized from the child's parent
fields so chains anchored on the parent name can still match.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Iterator

from collectors.base import Event
from core.engine import normalize_process_name
from core.fingerprint import extract_host

# Safety bound for ancestry and subtree walks. Real process trees are
# shallow; anything deeper indicates corrupted linkage.
MAX_TREE_DEPTH = 64


@dataclass
class ProcessNode:
    """
    A single process in the lineage tree.

    Concrete nodes wrap an observed Event. Phantom nodes are synthesized
    parents referenced by a child event but never observed directly: they
    carry a process name and optionally a pid, but no command line, user,
    or timestamp.
    """
    key: str
    process_name: str
    platform: str
    host: str
    pid: Optional[int] = None
    event: Optional[Event] = None
    parent: Optional["ProcessNode"] = None
    children: List["ProcessNode"] = field(default_factory=list)

    @property
    def is_phantom(self) -> bool:
        """True when this node was synthesized from a child's parent fields."""
        return self.event is None

    @property
    def timestamp(self) -> Optional[datetime]:
        """Event timestamp for concrete nodes, None for phantom nodes."""
        return self.event.timestamp if self.event else None

    @property
    def command_line(self) -> str:
        """Command line for concrete nodes, empty for phantom nodes."""
        return self.event.command_line if self.event else ""

    @property
    def user(self) -> str:
        """User for concrete nodes, empty for phantom nodes."""
        return self.event.user if self.event else ""

    def sort_key(self) -> tuple:
        """Deterministic ordering key: concrete nodes by time, phantoms first."""
        ts = self.timestamp
        return (
            0 if ts is None else 1,
            ts.isoformat() if ts else "",
            self.pid if self.pid is not None else -1,
            self.key,
        )

    def iter_descendants(self, max_depth: int = MAX_TREE_DEPTH) -> Iterator["ProcessNode"]:
        """
        Yield all descendants breadth-first with a depth cap and cycle guard.
        """
        visited = {id(self)}
        frontier = [(child, 1) for child in self.children]
        while frontier:
            node, depth = frontier.pop(0)
            if id(node) in visited or depth > max_depth:
                continue
            visited.add(id(node))
            yield node
            frontier.extend((child, depth + 1) for child in node.children)

    def __repr__(self) -> str:
        kind = "phantom" if self.is_phantom else "event"
        return f"ProcessNode({self.process_name}, pid={self.pid}, {kind})"


def build_forest(events: List[Event]) -> Dict[str, List[ProcessNode]]:
    """
    Build per-host process trees from a batch of events.

    Events are grouped by host identity (empty string when the source has
    no host metadata) so pid collisions across hosts never produce false
    lineage. Within a host, each event becomes a concrete node. Parent
    links resolve to the latest event with a matching pid at or before
    the child's timestamp; when the declared parent name disagrees with
    that candidate's name, the link is refused (pid reuse guard) and a
    phantom parent is created instead.

    Args:
        events: Normalized events from any collector

    Returns:
        Mapping of host identity to the full node list for that host,
        with parent and children links populated
    """
    by_host: Dict[str, List[Event]] = {}
    for event in events:
        by_host.setdefault(extract_host(event), []).append(event)

    forest: Dict[str, List[ProcessNode]] = {}
    for host, host_events in by_host.items():
        forest[host] = _build_host_tree(host, host_events)
    return forest


def _build_host_tree(host: str, events: List[Event]) -> List[ProcessNode]:
    """Build linked nodes for a single host's events."""
    ordered = sorted(
        enumerate(events),
        key=lambda pair: (
            pair[1].timestamp.isoformat(),
            pair[1].process_id if pair[1].process_id is not None else -1,
            pair[0],
        ),
    )

    nodes: List[ProcessNode] = []
    by_pid: Dict[int, List[ProcessNode]] = {}
    for order, (_, event) in enumerate(ordered):
        node = ProcessNode(
            key=f"{host}|{event.process_id}|{order}",
            process_name=event.process_name,
            platform=event.platform,
            host=host,
            pid=event.process_id,
            event=event,
        )
        nodes.append(node)
        if event.process_id is not None:
            by_pid.setdefault(event.process_id, []).append(node)

    phantoms: Dict[tuple, ProcessNode] = {}
    phantom_count = 0
    for node in nodes:
        event = node.event
        ppid = event.parent_process_id
        parent_name = (event.parent_process_name or "").strip()
        if ppid is None and not parent_name:
            continue

        parent = _find_concrete_parent(node, ppid, parent_name, by_pid)
        if parent is None:
            # Merge phantoms by (ppid, name) when a pid is known. Without
            # a pid, every child gets its own phantom so unrelated
            # processes sharing a parent name are never linked together.
            name_norm = normalize_process_name(parent_name, event.platform)
            if ppid is not None:
                phantom_key = (ppid, name_norm)
            else:
                phantom_key = (None, name_norm, phantom_count)
            parent = phantoms.get(phantom_key)
            if parent is None:
                phantom_count += 1
                parent = ProcessNode(
                    key=f"{host}|phantom|{ppid}|{name_norm}|{phantom_count}",
                    process_name=parent_name or f"pid-{ppid}",
                    platform=event.platform,
                    host=host,
                    pid=ppid,
                    event=None,
                )
                phantoms[phantom_key] = parent

        node.parent = parent
        parent.children.append(node)

    nodes.extend(phantoms.values())
    return nodes


def _find_concrete_parent(
    node: ProcessNode,
    ppid: Optional[int],
    parent_name: str,
    by_pid: Dict[int, List[ProcessNode]],
) -> Optional[ProcessNode]:
    """
    Find the concrete parent node for a child, guarding against pid reuse.

    Returns the latest node whose pid matches ppid, whose timestamp is at
    or before the child's, and whose basename agrees with the declared
    parent name when one is present.
    """
    if ppid is None:
        return None

    candidates = by_pid.get(ppid, [])
    expected = (
        normalize_process_name(parent_name, node.platform) if parent_name else None
    )
    best: Optional[ProcessNode] = None
    for candidate in candidates:
        if candidate is node:
            continue
        if candidate.timestamp and node.timestamp and candidate.timestamp > node.timestamp:
            continue
        if expected:
            actual = normalize_process_name(candidate.process_name, candidate.platform)
            if actual != expected:
                continue
        best = candidate
    return best
