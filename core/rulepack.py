"""
Rule pack signing, verification, and staged distribution.

Manual YAML deployment does not scale and unsigned automatic updates are
a supply-chain risk (MoA finding 18). A rule pack is a directory of rule
files plus a signed manifest that pins every file's SHA-256 hash, the
pack version, and the engine contract version it targets.

Verification recomputes every hash and checks the manifest signature
before any rule is trusted, so a tampered or truncated pack is rejected.
A PackRegistry adds staged activation with rollback and an audit trail.

Signing uses HMAC-SHA256 with a shared secret. That defends against
tampering by anyone without the key, which fits a single-tenant
deployment. Asymmetric signing (publisher signs, clients verify with a
public key) is the natural upgrade and is noted in the docs. The signing
key is never logged or written into any artifact.
"""
import hashlib
import hmac
import json
import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Bump when the manifest structure changes incompatibly.
PACK_FORMAT_VERSION = 1

# The engine contract the current code implements. A pack declares the
# minimum engine version it needs; verification refuses a pack that needs
# a newer engine than this.
ENGINE_CONTRACT_VERSION = 2

MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "manifest.sig"
RULE_SUFFIXES = (".yml", ".yaml")


class PackError(Exception):
    """Raised when a pack cannot be built, signed, or verified."""


@dataclass
class VerificationResult:
    """Outcome of verifying a rule pack."""
    valid: bool
    pack_version: str
    reasons: List[str] = field(default_factory=list)
    verified_files: List[str] = field(default_factory=list)

    def raise_if_invalid(self) -> None:
        if not self.valid:
            raise PackError(
                f"Pack {self.pack_version} failed verification: "
                + "; ".join(self.reasons)
            )


def _sha256_file(path: Path) -> str:
    """Return the hex SHA-256 of a file, read in chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_manifest(manifest: Dict[str, Any]) -> bytes:
    """Serialize a manifest deterministically for signing and hashing."""
    return json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sign(manifest_bytes: bytes, key: bytes) -> str:
    """Return the hex HMAC-SHA256 signature of manifest bytes."""
    return hmac.new(key, manifest_bytes, hashlib.sha256).hexdigest()


def _iter_rule_files(rules_dir: Path) -> List[Path]:
    """
    All rule and schema files in a rules directory, sorted.

    Excludes the pack's own metadata (manifest and signature) so a built
    pack verifies against exactly the rule content it was signed over.
    """
    reserved = {MANIFEST_NAME, SIGNATURE_NAME}
    files: List[Path] = []
    for suffix in RULE_SUFFIXES:
        files.extend(rules_dir.glob(f"**/*{suffix}"))
    files.extend(rules_dir.glob("**/*.json"))
    return sorted(f for f in set(files) if f.name not in reserved)


def build_manifest(
    rules_dir: str,
    pack_version: str,
    engine_min_version: int = ENGINE_CONTRACT_VERSION,
    created_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Build an unsigned manifest for a rules directory.

    Args:
        rules_dir: Directory of rule files to package
        pack_version: Version label for this pack (e.g. "2026.07.11")
        engine_min_version: Minimum engine contract version required
        created_at: Optional timestamp (defaults to now)

    Returns:
        Manifest dict with per-file hashes, sorted by path
    """
    root = Path(rules_dir)
    if not root.is_dir():
        raise PackError(f"Rules directory not found: {rules_dir}")

    stamp = (created_at or datetime.now()).isoformat()
    entries = []
    for path in _iter_rule_files(root):
        rel = path.relative_to(root).as_posix()
        entries.append({"path": rel, "sha256": _sha256_file(path)})

    if not entries:
        raise PackError(f"No rule files found in {rules_dir}")

    return {
        "pack_format_version": PACK_FORMAT_VERSION,
        "pack_version": pack_version,
        "engine_min_version": engine_min_version,
        "created_at": stamp,
        "rule_count": len(entries),
        "rules": entries,
    }


def build_pack(
    rules_dir: str,
    output_dir: str,
    pack_version: str,
    key: bytes,
    engine_min_version: int = ENGINE_CONTRACT_VERSION,
    created_at: Optional[datetime] = None,
) -> Path:
    """
    Build a signed rule pack: copy rules, write manifest and signature.

    Args:
        rules_dir: Source rules directory
        output_dir: Destination pack directory (created if absent)
        pack_version: Version label
        key: HMAC signing key (bytes, never logged)
        engine_min_version: Minimum engine contract version
        created_at: Optional timestamp

    Returns:
        Path to the created pack directory
    """
    if not key:
        raise PackError("A non-empty signing key is required")

    root = Path(rules_dir)
    out = Path(output_dir)
    manifest = build_manifest(
        rules_dir, pack_version, engine_min_version, created_at
    )

    # Copy each listed file into the pack, preserving structure.
    for entry in manifest["rules"]:
        src = root / entry["path"]
        dst = out / entry["path"]
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)

    manifest_bytes = _canonical_manifest(manifest)
    signature = _sign(manifest_bytes, key)

    (out / MANIFEST_NAME).write_bytes(manifest_bytes)
    (out / SIGNATURE_NAME).write_text(signature)
    logger.info(
        f"Built rule pack {pack_version} with {manifest['rule_count']} "
        f"files at {out}"
    )
    return out


def verify_pack(pack_dir: str, key: bytes) -> VerificationResult:
    """
    Verify a signed rule pack.

    Checks, in order: manifest and signature present; signature valid
    (constant-time); pack format supported; engine compatibility; every
    listed file present with a matching hash; no unexpected rule files.

    Args:
        pack_dir: Pack directory to verify
        key: HMAC signing key

    Returns:
        VerificationResult with valid flag and reasons
    """
    root = Path(pack_dir)
    reasons: List[str] = []
    manifest_path = root / MANIFEST_NAME
    signature_path = root / SIGNATURE_NAME

    if not manifest_path.is_file() or not signature_path.is_file():
        return VerificationResult(
            valid=False, pack_version="unknown",
            reasons=["manifest.json or manifest.sig missing"],
        )

    manifest_bytes = manifest_path.read_bytes()
    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError as e:
        return VerificationResult(
            valid=False, pack_version="unknown",
            reasons=[f"manifest is not valid JSON: {e}"],
        )

    pack_version = manifest.get("pack_version", "unknown")

    # Signature check (constant-time) against the exact bytes on disk.
    expected_sig = _sign(manifest_bytes, key)
    actual_sig = signature_path.read_text().strip()
    if not hmac.compare_digest(expected_sig, actual_sig):
        reasons.append("signature mismatch (wrong key or tampered manifest)")

    # Compatibility checks.
    fmt = manifest.get("pack_format_version")
    if fmt != PACK_FORMAT_VERSION:
        reasons.append(
            f"unsupported pack_format_version {fmt} "
            f"(this build supports {PACK_FORMAT_VERSION})"
        )
    engine_min = manifest.get("engine_min_version", 0)
    if engine_min > ENGINE_CONTRACT_VERSION:
        reasons.append(
            f"pack needs engine version {engine_min}, "
            f"this build is {ENGINE_CONTRACT_VERSION}"
        )

    # Per-file hash checks.
    verified: List[str] = []
    listed = set()
    for entry in manifest.get("rules", []):
        rel = entry["path"]
        listed.add(rel)
        file_path = root / rel
        if not file_path.is_file():
            reasons.append(f"missing file: {rel}")
            continue
        actual = _sha256_file(file_path)
        if not hmac.compare_digest(actual, entry["sha256"]):
            reasons.append(f"hash mismatch: {rel}")
            continue
        verified.append(rel)

    # Reject unexpected rule files not covered by the manifest.
    for path in _iter_rule_files(root):
        rel = path.relative_to(root).as_posix()
        if rel not in listed:
            reasons.append(f"unlisted file present: {rel}")

    return VerificationResult(
        valid=not reasons,
        pack_version=pack_version,
        reasons=reasons,
        verified_files=verified,
    )


def load_verified_rules(pack_dir: str, key: bytes):
    """
    Verify a pack, then load its rules with the standard RuleLoader.

    Raises PackError if verification fails, so unverified rules are never
    loaded into the engine.
    """
    result = verify_pack(pack_dir, key)
    result.raise_if_invalid()
    from core.rule_loader import RuleLoader
    loader = RuleLoader(schema_path=str(Path(pack_dir) / "schema.json"))
    return loader.load_rules_directory(pack_dir)


class PackRegistry:
    """
    Staged activation and rollback for verified rule packs.

    Packs are staged into versions/<version>/ after verification. Exactly
    one version is active at a time, tracked in a pointer file with a
    history stack that rollback pops. Every action appends to an audit
    log. The registry never activates an unverified pack.
    """

    def __init__(self, root: str):
        self.root = Path(root)
        self.versions_dir = self.root / "versions"
        self.pointer_path = self.root / "active.json"
        self.audit_path = self.root / "audit.log"
        self.versions_dir.mkdir(parents=True, exist_ok=True)

    def _read_pointer(self) -> Dict[str, Any]:
        if self.pointer_path.is_file():
            return json.loads(self.pointer_path.read_text())
        return {"active": None, "history": []}

    def _write_pointer(self, pointer: Dict[str, Any]) -> None:
        self.pointer_path.write_text(
            json.dumps(pointer, indent=2, sort_keys=True)
        )

    def _audit(self, action: str, version: Optional[str], detail: str,
               when: Optional[datetime] = None) -> None:
        stamp = (when or datetime.now()).isoformat()
        line = json.dumps({
            "timestamp": stamp, "action": action,
            "version": version, "detail": detail,
        })
        with open(self.audit_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def stage(self, pack_dir: str, key: bytes,
              when: Optional[datetime] = None) -> str:
        """Verify a pack and copy it into the registry. Returns its version."""
        result = verify_pack(pack_dir, key)
        result.raise_if_invalid()
        version = result.pack_version
        dest = self.versions_dir / version
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(pack_dir, dest)
        self._audit("stage", version, f"{len(result.verified_files)} files", when)
        return version

    def activate(self, version: str, key: bytes,
                 when: Optional[datetime] = None) -> None:
        """Verify a staged version and make it active, recording the previous."""
        dest = self.versions_dir / version
        if not dest.is_dir():
            raise PackError(f"Version not staged: {version}")
        verify_pack(str(dest), key).raise_if_invalid()

        pointer = self._read_pointer()
        previous = pointer.get("active")
        if previous and previous != version:
            pointer["history"].append(previous)
        pointer["active"] = version
        self._write_pointer(pointer)
        self._audit("activate", version, f"previous={previous}", when)

    def rollback(self, key: bytes, when: Optional[datetime] = None) -> str:
        """Revert to the previous active version. Returns the restored version."""
        pointer = self._read_pointer()
        if not pointer.get("history"):
            raise PackError("No previous version to roll back to")
        previous = pointer["history"].pop()
        verify_pack(str(self.versions_dir / previous), key).raise_if_invalid()
        rolled_from = pointer.get("active")
        pointer["active"] = previous
        self._write_pointer(pointer)
        self._audit("rollback", previous, f"from={rolled_from}", when)
        return previous

    def active_version(self) -> Optional[str]:
        """Return the currently active version, or None."""
        return self._read_pointer().get("active")

    def active_path(self) -> Optional[Path]:
        """Return the directory of the active version, or None."""
        version = self.active_version()
        return self.versions_dir / version if version else None


def _main(argv: Optional[List[str]] = None) -> int:
    """CLI: build or verify a rule pack. Reads the key from an env var."""
    import argparse
    import os

    parser = argparse.ArgumentParser(
        description="Build or verify a signed rule pack.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="Build a signed pack")
    build.add_argument("rules_dir")
    build.add_argument("output_dir")
    build.add_argument("--version", required=True)

    verify = sub.add_parser("verify", help="Verify a signed pack")
    verify.add_argument("pack_dir")

    args = parser.parse_args(argv)

    key = os.environ.get("LOTL_RULEPACK_KEY", "").encode("utf-8")
    if not key:
        print("error: set LOTL_RULEPACK_KEY in the environment")
        return 2

    if args.command == "build":
        path = build_pack(args.rules_dir, args.output_dir, args.version, key)
        print(f"built pack at {path}")
        return 0

    result = verify_pack(args.pack_dir, key)
    if result.valid:
        print(f"OK: pack {result.pack_version}, "
              f"{len(result.verified_files)} files verified")
        return 0
    print(f"INVALID: pack {result.pack_version}")
    for reason in result.reasons:
        print(f"  - {reason}")
    return 1


if __name__ == "__main__":
    import sys
    sys.exit(_main())
