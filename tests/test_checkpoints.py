"""Checkpoints: signed and/or witnessed chain heads.

Each test names the attack it covers. The forger is the same one as in
test_store.py: someone with write access who rewrites events and recomputes
the chain, which the chain alone cannot detect.
"""

import json
import socket
import sqlite3

import pytest

pytest.importorskip("cryptography")

from tests.test_store import raw_conn, rewrite_chain  # noqa: E402

from aire.core.events import EventType  # noqa: E402
from aire.store import EvidenceStore  # noqa: E402
from aire.store.checkpoints import (  # noqa: E402
    BrokenChainError,
    CheckpointError,
    emit,
    generate_keypair,
    load_private_key,
    load_public_key,
    make_checkpoint,
    read_checkpoints,
    verify_checkpoints,
)


@pytest.fixture
def store(tmp_path):
    s = EvidenceStore(tmp_path / "evidence.db")
    yield s
    s.close()


@pytest.fixture
def keys(tmp_path):
    private, public = generate_keypair(tmp_path / "signer")
    return load_private_key(private), load_public_key(public)


def add(store, n):
    for i in range(n):
        store.append(session_id="s", app="a", event_type=EventType.TOOL_CALL,
                     payload={"gen_ai.tool.name": "search", "i": i})


class TestStoreIdentity:
    def test_store_id_is_fixed_and_immutable(self, store):
        sid = store.store_id()
        assert sid and len(sid) == 36
        with raw_conn(store) as conn, pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE meta SET value = 'other' WHERE key = 'store_id'")
        store.close()
        assert EvidenceStore(store.path).store_id() == sid  # reopen keeps it

    def test_legacy_store_gets_an_id_on_first_read_write_open(self, tmp_path):
        path = tmp_path / "legacy.db"
        s = EvidenceStore(path)
        add(s, 2)
        s.close()
        with sqlite3.connect(path) as conn:  # turn it into a store from before store ids
            conn.execute("DROP TRIGGER meta_no_delete")
            conn.execute("DROP TRIGGER meta_no_update")
            conn.execute("DROP TABLE meta")
        assert EvidenceStore(path, read_only=True).store_id() is None
        reopened = EvidenceStore(path)
        assert reopened.store_id() is not None and reopened.verify().ok


class TestMakeCheckpoint:
    def test_signed_checkpoint_names_store_and_head(self, store, keys):
        add(store, 3)
        record = make_checkpoint(store, private_key=keys[0])
        st = record["statement"]
        assert st["store_id"] == store.store_id()
        assert f"{st['seq']}:{st['head']}" == store.verify().head
        assert record["sig"] and len(record["key_id"]) == 16

    def test_unsigned_checkpoint_has_no_signature(self, store):
        add(store, 1)
        assert "sig" not in make_checkpoint(store)

    def test_refuses_to_vouch_for_a_broken_chain(self, store):
        add(store, 3)
        with raw_conn(store) as conn:
            conn.execute("DROP TRIGGER events_no_update")
            conn.execute("UPDATE events SET app = 'x' WHERE seq = 2")
            conn.commit()
        with pytest.raises(BrokenChainError):
            make_checkpoint(store)

    def test_refuses_empty_store(self, store):
        with pytest.raises(CheckpointError, match="empty"):
            make_checkpoint(store)


class TestVerifyCheckpoints:
    def test_intact_chain_with_signed_checkpoints(self, store, keys):
        add(store, 3)
        cps = [make_checkpoint(store, private_key=keys[0])]
        add(store, 3)
        cps.append(make_checkpoint(store, private_key=keys[0]))
        add(store, 1)
        report = verify_checkpoints(store, cps, public_keys=[keys[1]], max_gap=3)
        assert report.ok, report.problems
        assert report.signed_verified == 2 and report.unprotected_tail == 1

    def test_rewrite_is_caught(self, store, keys):
        """Attack: rewrite history and recompute the chain."""
        add(store, 5)
        cps = [make_checkpoint(store, private_key=keys[0])]
        rewrite_chain(store, mutate=lambda p: {**p, "gen_ai.tool.name": "delete_records"}
                      if p["i"] == 1 else p)
        assert store.verify().ok  # the chain alone cannot tell
        report = verify_checkpoints(store, cps, public_keys=[keys[1]])
        assert not report.ok
        assert "does not match the checkpoints" in report.problems[0]

    def test_forged_checkpoint_is_caught(self, store, keys):
        """Attack: rewrite, then edit the checkpoint to match the new head."""
        add(store, 4)
        cp = make_checkpoint(store, private_key=keys[0])
        rewrite_chain(store, mutate=lambda p: {**p, "i": -1})
        cp["statement"]["head"] = store.verify().head.split(":")[1]
        report = verify_checkpoints(store, [cp], public_keys=[keys[1]])
        assert not report.ok and "signature does not verify" in report.problems[0]

    def test_checkpoint_signed_by_another_key_is_caught(self, store, keys, tmp_path):
        """Attack: the writer signs its own checkpoints with a key it controls."""
        add(store, 2)
        rogue_private, _ = generate_keypair(tmp_path / "rogue")
        cp = make_checkpoint(store, private_key=load_private_key(rogue_private))
        report = verify_checkpoints(store, [cp], public_keys=[keys[1]])
        assert not report.ok and "unknown key" in report.problems[0]

    def test_unsigned_checkpoint_rejected_when_signatures_required(self, store, keys):
        add(store, 2)
        report = verify_checkpoints(store, [make_checkpoint(store)], public_keys=[keys[1]])
        assert not report.ok and "unsigned" in report.problems[0]

    def test_checkpoint_from_another_store_is_caught(self, store, keys, tmp_path):
        """Attack: replay a valid checkpoint from a different store."""
        other = EvidenceStore(tmp_path / "other.db")
        add(other, 2)
        cp = make_checkpoint(other, private_key=keys[0])
        other.close()
        add(store, 2)
        report = verify_checkpoints(store, [cp], public_keys=[keys[1]])
        assert not report.ok and "different store" in report.problems[0]

    def test_deleted_checkpoints_show_up_as_a_gap(self, store):
        """Attack: drop the checkpoints that would expose a rewrite."""
        add(store, 2)
        early = make_checkpoint(store)
        add(store, 8)
        # the later checkpoints were removed; only the early one is presented
        report = verify_checkpoints(store, [early], max_gap=5)
        assert not report.ok and "follow the latest checkpoint" in report.problems[0]
        assert verify_checkpoints(store, [early]).ok  # without --max-gap it is not a failure

    def test_unchecked_signatures_are_reported(self, store, keys):
        add(store, 1)
        report = verify_checkpoints(store, [make_checkpoint(store, private_key=keys[0])])
        assert report.ok and report.signatures_unchecked == 1


class TestSinks:
    def test_file_sink_round_trip(self, store, keys, tmp_path):
        add(store, 2)
        path = tmp_path / "checkpoints.jsonl"
        emit(make_checkpoint(store, private_key=keys[0]), f"file:{path}")
        add(store, 2)
        emit(make_checkpoint(store, private_key=keys[0]), f"file:{path}")
        assert oct(path.stat().st_mode & 0o777) == "0o600"
        records = read_checkpoints(path)
        assert verify_checkpoints(store, records, public_keys=[keys[1]]).ok

    def test_syslog_sink_delivers_a_parseable_line(self, store, tmp_path):
        add(store, 1)
        record = make_checkpoint(store)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(("127.0.0.1", 0))
            server.settimeout(5)
            emit(record, f"syslog:127.0.0.1:{server.getsockname()[1]}")
            message = server.recv(65535).decode()
        assert message.startswith("<110>1 ") and " aire - checkpoint - " in message
        witness = tmp_path / "siem-export.log"
        witness.write_text(message + "\n")  # what a SIEM export of that message looks like
        assert read_checkpoints(witness)[0] == json.loads(json.dumps(record))

    def test_unknown_sink_is_rejected(self, store):
        add(store, 1)
        with pytest.raises(CheckpointError, match="unknown sink"):
            emit(make_checkpoint(store), "ftp:somewhere")


class TestCli:
    def test_keygen_checkpoint_verify(self, store, tmp_path):
        from typer.testing import CliRunner

        from aire.cli import app

        runner = CliRunner()
        key = tmp_path / "signer"
        assert runner.invoke(app, ["keygen", str(key)]).exit_code == 0
        assert runner.invoke(app, ["keygen", str(key)]).exit_code == 2  # never overwrite

        add(store, 3)
        cps = tmp_path / "cps.jsonl"
        r = runner.invoke(app, ["checkpoint", str(store.path), "--sign", str(key),
                                "--sink", f"file:{cps}"])
        assert r.exit_code == 0, r.output
        assert "(signed) sent to" in r.output

        verify = ["verify", str(store.path), "--checkpoints", str(cps),
                  "--pubkey", str(key) + ".pub"]
        ok = runner.invoke(app, verify)
        assert ok.exit_code == 0 and "1 signature(s) verified" in ok.output

        rewrite_chain(store, mutate=lambda p: {**p, "i": 42})
        bad = runner.invoke(app, verify)
        assert bad.exit_code == 1 and "TAMPER OR GAP DETECTED" in bad.output

        assert runner.invoke(app, ["checkpoint", str(store.path), "--sink", "nope"]).exit_code == 2
        stray = runner.invoke(app, ["verify", str(store.path), "--max-gap", "3"])
        assert stray.exit_code == 2
