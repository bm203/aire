"""Checkpoints: statements about the chain head that the writer cannot forge.

The hash chain alone proves internal consistency. Someone with write access to
the store can rewrite events and recompute every later hash. A checkpoint
records the head (``seq:hash``) at a moment and makes it independent of the
writer in one or both of two ways:

* **signed** with an Ed25519 key the writer cannot read (a separate OS user, a
  signer service, an HSM or KMS), and/or
* **witnessed**: sent to a system another party controls (syslog into a SIEM,
  a file on an audit-owned share), so the record of the head lives outside the
  operator's reach.

``verify_checkpoints`` then checks every signature, that each checkpoint names
this store, that the chain still matches every checkpointed head, and,
optionally, that no more than ``max_gap`` events follow the latest checkpoint.
A checkpoint at seq N protects every event up to N, so only events after the
latest checkpoint are exposed; removing recent checkpoints (to rewrite what
they covered) shows up as a tail longer than the checkpoint interval.

Limits, stated plainly: a key on the same host and user as the writer adds
little, since whoever can rewrite the store can read it. Events after the last
checkpoint are unprotected until the next one. The checkpoint's own ``ts`` is
the checkpointing machine's clock, not a trusted timestamp. Nothing here
defends against a host compromised at recording time.

Signing needs the ``signing`` extra (``pip install 'aire[signing]'``).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aire.store.sqlite import EvidenceStore, VerificationResult

STATEMENT_VERSION = 1


class CheckpointError(Exception):
    """A checkpoint cannot be created or a checkpoint file cannot be used."""


class BrokenChainError(CheckpointError):
    """The chain is already broken, so no checkpoint may vouch for it."""


def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover
        raise CheckpointError(
            "signing requires the 'signing' extra: pip install 'aire[signing]'"
        ) from exc
    return ed25519, serialization


def canonical(statement: dict[str, Any]) -> bytes:
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def key_id(public_key) -> str:
    """Short fingerprint of a public key, so a checkpoint names its signer."""
    _, serialization = _crypto()
    raw = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return hashlib.sha256(raw).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Keys


def generate_keypair(path: str | Path) -> tuple[Path, Path]:
    """Write an Ed25519 private key (0600) to ``path`` and its public key to ``path.pub``."""
    ed25519, serialization = _crypto()
    path = Path(path)
    pub_path = path.with_name(path.name + ".pub")
    if path.exists() or pub_path.exists():
        raise CheckpointError(f"refusing to overwrite existing key file(s) at {path}")
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    pub_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return path, pub_path


def load_private_key(path: str | Path):
    ed25519, serialization = _crypto()
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise CheckpointError(f"{path} is not an Ed25519 private key")
    return key


def load_public_key(path: str | Path):
    ed25519, serialization = _crypto()
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise CheckpointError(f"{path} is not an Ed25519 public key")
    return key


# ---------------------------------------------------------------------------
# Creating checkpoints


def make_checkpoint(store: EvidenceStore, *, private_key=None) -> dict[str, Any]:
    """Verify the chain, then return a (signed) checkpoint record for its head.

    A broken chain is refused: a checkpoint vouching for tampered evidence
    would be worse than none.
    """
    store_id = store.store_id()
    if store_id is None:
        raise CheckpointError(
            "this store predates store ids; open it read-write once "
            "(`aire checkpoint` does this automatically) to assign one"
        )
    result = store.verify()
    if not result.ok:
        raise BrokenChainError(f"refusing to checkpoint a broken chain: {result.reason}")
    if result.head is None:
        raise CheckpointError("refusing to checkpoint an empty store")
    seq, head = result.head.split(":")
    statement = {
        "v": STATEMENT_VERSION,
        "store_id": store_id,
        "seq": int(seq),
        "head": head,
        "ts": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    record: dict[str, Any] = {"statement": statement}
    if private_key is not None:
        record["key_id"] = key_id(private_key.public_key())
        record["sig"] = base64.b64encode(private_key.sign(canonical(statement))).decode()
    return record


def emit(record: dict[str, Any], sink: str) -> None:
    """Send one checkpoint record to a sink.

    Sinks: ``-`` (stdout), ``file:PATH`` (appended, one JSON line), and
    ``syslog:HOST[:PORT]`` (one RFC 5424 message over UDP, default port 514).
    """
    line = json.dumps(record, sort_keys=True, separators=(",", ":"))
    if sink == "-":
        print(line)
    elif sink.startswith("file:"):
        path = Path(sink[len("file:"):])
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    elif sink.startswith("syslog:"):
        host, _, port = sink[len("syslog:"):].partition(":")
        if not host:
            raise CheckpointError("syslog sink needs a host: syslog:HOST[:PORT]")
        ts = datetime.now(UTC).isoformat(timespec="seconds")
        # <110> = facility 13 (log audit) * 8 + severity 6 (informational)
        message = f"<110>1 {ts} {socket.gethostname()} aire - checkpoint - {line}"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(message.encode("utf-8"), (host, int(port or 514)))
    else:
        raise CheckpointError(f"unknown sink {sink!r}; use -, file:PATH, or syslog:HOST[:PORT]")


# ---------------------------------------------------------------------------
# Verifying checkpoint files


@dataclass
class CheckpointReport:
    ok: bool
    checkpoints: int = 0
    signed_verified: int = 0
    signatures_unchecked: int = 0
    chain: VerificationResult | None = None
    problems: list[str] = field(default_factory=list)
    # Events after the latest checkpoint: the only part of the chain the
    # checkpoints do not protect.
    unprotected_tail: int = 0


def read_checkpoints(path: str | Path) -> list[dict[str, Any]]:
    """Read a checkpoint file, tolerating syslog-wrapped lines."""
    records = []
    for n, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        raw = raw.strip()
        if not raw:
            continue
        start = raw.find("{")
        try:
            record = json.loads(raw[start:]) if start >= 0 else None
        except json.JSONDecodeError:
            record = None
        if not isinstance(record, dict) or not isinstance(record.get("statement"), dict):
            raise CheckpointError(f"line {n} of {path} is not a checkpoint record")
        records.append(record)
    return records


def verify_checkpoints(
    store: EvidenceStore,
    records: list[dict[str, Any]],
    *,
    public_keys: list | None = None,
    max_gap: int | None = None,
) -> CheckpointReport:
    report = CheckpointReport(ok=True, checkpoints=len(records))
    store_id = store.store_id()
    keys = {key_id(k): k for k in public_keys or []}
    anchors: list[str] = []

    for i, record in enumerate(records, 1):
        st = record["statement"]
        where = f"checkpoint {i} (seq {st.get('seq')})"
        if st.get("v") != STATEMENT_VERSION:
            report.problems.append(f"{where}: unsupported statement version {st.get('v')!r}")
            continue
        if store_id is None or st.get("store_id") != store_id:
            report.problems.append(f"{where}: names a different store (replayed or misfiled)")
            continue
        if "sig" in record:
            if keys:
                key = keys.get(record.get("key_id", ""))
                if key is None:
                    report.problems.append(f"{where}: signed by an unknown key")
                    continue
                try:
                    key.verify(base64.b64decode(record["sig"]), canonical(st))
                except Exception:  # cryptography raises InvalidSignature; treat any failure alike
                    report.problems.append(f"{where}: signature does not verify")
                    continue
                report.signed_verified += 1
            else:
                report.signatures_unchecked += 1
        elif keys:
            report.problems.append(f"{where}: unsigned, but signed checkpoints were required")
            continue
        anchors.append(f"{st['seq']}:{st['head']}")

    if report.problems:
        report.ok = False
        return report

    try:
        report.chain = store.verify(anchors=anchors)
    except ValueError as exc:
        report.ok = False
        report.problems.append(str(exc))
        return report
    if not report.chain.ok:
        report.ok = False
        report.problems.append(
            f"chain does not match the checkpoints at seq {report.chain.first_bad_seq}: "
            f"{report.chain.reason}"
        )
        return report

    head_seq = int(report.chain.head.split(":")[0]) if report.chain.head else 0
    latest = max((int(a.split(":")[0]) for a in anchors), default=0)
    report.unprotected_tail = head_seq - latest
    if max_gap is not None and report.unprotected_tail > max_gap:
        report.ok = False
        report.problems.append(
            f"{report.unprotected_tail} event(s) follow the latest checkpoint "
            f"(allowed: {max_gap}); recent checkpoints may have been removed, "
            "or checkpointing stopped"
        )
    return report
