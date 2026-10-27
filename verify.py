#!/usr/bin/env python3
"""Independently verify this record. Needs Python 3.10+, openssl and `pip install py_ecc`.

    python3 verify.py              # everything except the fork scan (seconds)
    python3 verify.py --days 3     # + fork scan of the last 3 trading days in Rekor (~60 MB)
    python3 verify.py --months 3   # + fork scan of 3 months (~1.3 GB, asks first)
    python3 verify.py --ots        # + OpenTimestamps (pip install opentimestamps-client)
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from nyse_calendar import holiday_name  # noqa: E402
import rekor_scan  # noqa: E402

NY = ZoneInfo("America/New_York")
UTC = dt.timezone.utc
CA = {"freetsa": ["-CAfile", str(ROOT / "tsa-certs" / "freetsa-cacert.pem")]}
SYSTEM_CA = ["-CApath", "/etc/ssl/certs"]
MIN_TSAS = 2
STANDARD_TIMES = {"opening": "09:19:00", "window_open": "09:20:00", "members": "09:24:00",
                  "deadline": "09:29:30", "seal_by": "09:30:30", "close_after": "09:30:30",
                  "reveal": "11:30:00"}
# drand quicknet (League of Entropy): https://api.drand.sh/<chain>/info
DRAND_CHAIN = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
DRAND_PUBLIC_KEY = ("83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a")
DRAND_GENESIS, DRAND_PERIOD = 1692803367, 3
TICKER_RE = r"^[A-Z][A-Z\-]{0,9}$"
problems, notes = [], []


def bad(msg):
    problems.append(msg)
    print("  FAIL", msg)


def note(msg):
    notes.append(msg)
    print("  NOTE", msg)


# ---------- building blocks (also used by the ledger itself) ----------

def tsa_time(tsr: Path) -> dt.datetime:
    txt = subprocess.run(["openssl", "ts", "-reply", "-in", str(tsr), "-text"],
                         capture_output=True, text=True).stdout
    t = next(l.split(":", 1)[1].strip() for l in txt.splitlines() if l.startswith("Time stamp:"))
    t = t.replace(" GMT", "").split(".")[0]
    return dt.datetime.strptime(" ".join(t.split()), "%b %d %H:%M:%S %Y").replace(tzinfo=UTC)


def tsa_verified(data_file: Path, tokens) -> list:
    """Times of the tokens that verify for this file (certificates checked as of signing time)."""
    out = []
    for tsr in tokens:
        name = tsr.name.split(".")[-2]
        try:
            t = tsa_time(tsr)
        except StopIteration:
            bad(f"{tsr.name}: unreadable RFC 3161 token")
            continue
        r = subprocess.run(["openssl", "ts", "-verify", "-data", str(data_file), "-in", str(tsr),
                            "-attime", str(int(t.timestamp())), *CA.get(name, SYSTEM_CA)],
                           capture_output=True, text=True)
        if "Verification: OK" in r.stdout:
            out.append(t)
        else:
            bad(f"{tsr.name}: RFC 3161 token does not verify")
    return sorted(out)


def drand_time(rnd: int) -> dt.datetime:
    return dt.datetime.fromtimestamp(DRAND_GENESIS + (rnd - 1) * DRAND_PERIOD, UTC)


def drand_ok(rnd: int, signature_hex: str) -> bool:
    """BLS signature check of a drand quicknet beacon (bls-unchained-g1-rfc9380)."""
    from py_ecc.bls.hash_to_curve import hash_to_G1
    from py_ecc.bls.point_compression import decompress_G1, decompress_G2
    from py_ecc.optimized_bls12_381 import G2, pairing
    pk = bytes.fromhex(DRAND_PUBLIC_KEY)
    try:
        sig = decompress_G1(int.from_bytes(bytes.fromhex(signature_hex), "big"))
        key = decompress_G2((int.from_bytes(pk[:48], "big"), int.from_bytes(pk[48:], "big")))
    except Exception:
        return False
    msg = hashlib.sha256(rnd.to_bytes(8, "big")).digest()
    return pairing(G2, sig) == pairing(key, hash_to_G1(msg, b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_",
                                                        hashlib.sha256))


def ecdsa_ok(key_der: bytes, digest: bytes, sig: bytes) -> bool:
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        pem = base64.encodebytes(key_der).decode()
        (d / "k").write_text(f"-----BEGIN PUBLIC KEY-----\n{pem}-----END PUBLIC KEY-----\n")
        (d / "m").write_bytes(digest)
        (d / "s").write_bytes(sig)
        return subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", d / "k", "-in", d / "m",
                               "-sigfile", d / "s"], capture_output=True).returncode == 0


def rekor_problem(tle: dict, data: bytes, key_der: bytes, origin: str):
    """None if Rekor's entry is `data` signed with key_der and its inclusion proof leads to a checkpoint
    signed by the log; otherwise what's wrong."""
    try:
        body = base64.b64decode(tle["canonicalizedBody"])
        spec = json.loads(body)["spec"]["hashedRekordV002"]
        digest = hashlib.sha256(data).digest()
        if base64.b64decode(spec["data"]["digest"]) != digest:
            return "logged digest is not the entry's sha256"
        if base64.b64decode(spec["signature"]["verifier"]["publicKey"]["rawBytes"]) != key_der:
            return "logged with a different key"
        if not ecdsa_ok(key_der, digest, base64.b64decode(spec["signature"]["content"])):
            return "signature doesn't verify"
        ip = tle["inclusionProof"]
        idx, size = int(ip["logIndex"]), int(ip["treeSize"])
        root = rekor_scan.inclusion_root(rekor_scan.leaf_hash(body), idx, size,
                                         [base64.b64decode(h) for h in ip["hashes"]])
        if root is None or root != base64.b64decode(ip["rootHash"]):
            return "inclusion proof doesn't lead to the root"
        cp_size, cp_root = rekor_scan.parse_checkpoint(ip["checkpoint"]["envelope"], origin)
        if (cp_size, cp_root) != (size, root):
            return "checkpoint doesn't match the inclusion proof"
        if int(tle.get("logIndex", idx)) != idx:
            return "log index mismatch"
    except (KeyError, ValueError, TypeError) as e:
        return f"malformed Rekor proof ({e})"
    return None


# ---------- the record ----------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    span = ap.add_mutually_exclusive_group()
    span.add_argument("--days", type=int, help="fork scan of the last N trading days")
    span.add_argument("--months", type=int, help="fork scan of the last N months (large download)")
    ap.add_argument("--yes", action="store_true", help="don't ask before a large fork-scan download")
    ap.add_argument("--cache", help="keep downloaded Rekor tiles here")
    ap.add_argument("--ots", action="store_true", help="also check OpenTimestamps")
    a = ap.parse_args()
    try:
        import py_ecc  # noqa: F401
    except ImportError:
        sys.exit("needs py_ecc for drand signatures: pip install py_ecc")

    files = sorted((ROOT / "entries").glob("[0-9]" * 6 + ".json"))
    if not files:
        sys.exit("no entries")
    genesis = json.loads(files[0].read_bytes())
    key_der = base64.b64decode(genesis["ledger_pubkey"])
    T = genesis["times_ny"]

    def at(day, name):
        h, m, s = map(int, T[name].split(":"))
        return dt.datetime.combine(dt.date.fromisoformat(day), dt.time(h, m, s), NY).astimezone(UTC)

    if hashlib.sha256((ROOT / "nyse_calendar.py").read_bytes()).hexdigest() != genesis.get("calendar_sha256"):
        bad("nyse_calendar.py differs from the version fixed in the genesis entry")
    if genesis.get("drand_chain") != DRAND_CHAIN or genesis.get("drand_public_key") != DRAND_PUBLIC_KEY:
        bad("genesis names a different drand chain")
    if T != STANDARD_TIMES:
        note(f"genesis uses non-standard times {T} (test ledger?)")

    prev_hash, days, closes, rows = "0" * 64, {}, {}, []
    for i, f in enumerate(files):
        raw = f.read_bytes()
        e = json.loads(raw)
        stem = f.stem
        kind, day = e["type"], e.get("trading_date", "")
        print(f"#{e['seq']:>4} {kind:<7} {day}")
        if e["seq"] != i:
            bad(f"{f.name}: seq {e['seq']} != {i}")
        if e["prev"] != prev_hash:
            bad(f"{f.name}: chain broken (prev does not match previous file)")
        if raw != (json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode():
            bad(f"{f.name}: not in canonical form")
        prev_hash = hashlib.sha256(raw).hexdigest()

        # Rekor + seal timestamps
        rp = ROOT / "proofs" / f"{stem}.rekor.json"
        if not rp.exists():
            bad(f"{f.name}: no Rekor proof")
            continue
        r = json.loads(rp.read_text())
        if r.get("origin") not in rekor_scan.LOGS:
            bad(f"{f.name}: Rekor log {r.get('origin')!r} is not a known Sigstore log")
            continue
        why = rekor_problem({"canonicalizedBody": r["canonicalized_body"], "inclusionProof": r["inclusion_proof"],
                             "logIndex": r["log_index"]}, raw, key_der, r["origin"])
        if why:
            bad(f"{f.name}: Rekor: {why}")
            continue
        seal = ROOT / "proofs" / f"{stem}.seal.txt"
        if not seal.exists() or seal.read_text() != r["inclusion_proof"]["checkpoint"]["envelope"]:
            bad(f"{f.name}: seal.txt missing or not the checkpoint of the inclusion proof")
            continue
        seal_times = tsa_verified(seal, sorted((ROOT / "proofs").glob(f"{stem}.seal.*.tsr")))
        print(f"        Rekor #{r['log_index']}  in Rekor by {seal_times[MIN_TSAS - 1]:%Y-%m-%d %H:%M:%S} UTC"
              if len(seal_times) >= MIN_TSAS else f"        Rekor #{r['log_index']}")
        if len(seal_times) < MIN_TSAS:
            bad(f"{f.name}: fewer than {MIN_TSAS} valid RFC 3161 timestamps on its Rekor checkpoint")
        if kind == "genesis":
            continue

        # drand freshness
        bound = at(day, "close_after" if kind == "close" else "window_open")
        dr = e.get("drand") or {}
        if not drand_ok(dr.get("round", 0), dr.get("signature", "")):
            bad(f"{f.name}: drand signature invalid")
        elif drand_time(dr["round"]) < bound:
            bad(f"{f.name}: drand value dated {drand_time(dr['round']):%H:%M:%S} UTC, before "
                f"{bound.astimezone(NY):%H:%M:%S} NY")

        if kind == "close":
            closes[day] = e
            continue
        if day in days:
            bad(f"{f.name}: second day entry for {day}")
        status = kind.upper()

        if e.get("late"):
            status = "PASS (late: window missed)"
        else:
            op = ROOT / "proofs" / f"{stem}.opening.txt"
            cp = e.get("opening_checkpoint") or {}
            try:
                size, root = rekor_scan.parse_checkpoint(op.read_text(), cp.get("origin", ""))
                if (size, base64.b64encode(root).decode()) != (cp.get("size"), cp.get("root")):
                    bad(f"{f.name}: opening checkpoint file doesn't match the entry")
                elif size > r["log_index"]:
                    bad(f"{f.name}: opening checkpoint is newer than the entry")
            except (OSError, ValueError) as ex:
                bad(f"{f.name}: opening checkpoint: {ex}")
            op_times = tsa_verified(op, sorted((ROOT / "proofs").glob(f"{stem}.opening.*.tsr")))
            if len([t for t in op_times if t <= at(day, "window_open")]) < MIN_TSAS:
                bad(f"{f.name}: opening checkpoint not timestamped by {T['window_open']} NY")
            if len([t for t in seal_times if t <= at(day, "seal_by")]) < MIN_TSAS:
                note(f"{f.name}: in Rekor after {T['seal_by']} NY -> counts as PASS")
                status = "PASS (sealed late)"

        if kind == "holiday" and not holiday_name(dt.date.fromisoformat(day)):
            note(f"{day}: marked closed although not a scheduled NYSE holiday: {e.get('reason')}"
                 " (check the exchange's announcement)")
        if kind == "commit" and status == "COMMIT":
            status = check_reveal(e, stem, at)
        days[day] = status
        rows.append((day, status))

        if a.ots:
            r2 = subprocess.run(["ots", "verify", str(f.with_name(f.name + ".ots"))], capture_output=True, text=True)
            out = (r2.stdout + r2.stderr).strip().splitlines()
            print("        bitcoin ", out[-1] if out else "?")

    # one day entry + one close per weekday since genesis
    now = dt.datetime.now(UTC)
    g_at = dt.datetime.fromisoformat(genesis["recorded_at"].replace("Z", "+00:00"))
    d = g_at.astimezone(NY).date()
    while d <= now.astimezone(NY).date():
        ds = d.isoformat()
        if d.weekday() < 5 and g_at < at(ds, "opening"):
            if ds not in days and now > at(ds, "seal_by") + dt.timedelta(minutes=10):
                bad(f"{ds}: weekday with no entry")
            if ds not in closes and now > at(ds, "close_after") + dt.timedelta(minutes=10):
                bad(f"{ds}: weekday with no close entry")
        d += dt.timedelta(days=1)

    print("\nDay         Result")
    for day, status in rows:
        print(f"{day}  {status}")
    unrevealed = [d for d, s in rows if s.startswith("UNREVEALED")]
    if unrevealed:
        print(f"\nUNREVEALED days: {', '.join(unrevealed)}")

    if a.days or a.months:
        print("\nFork scan (Sigstore Rekor):")
        cmd = [sys.executable, str(ROOT / "rekor_scan.py"), "--ledger", str(ROOT)]
        cmd += ["--days", str(a.days)] if a.days else ["--months", str(a.months)]
        cmd += (["--yes"] if a.yes else []) + (["--cache", a.cache] if a.cache else [])
        sys.stdout.flush()
        if subprocess.run(cmd).returncode != 0:
            problems.append("fork scan")

    print("\nALL CHECKS PASSED" if not problems else f"\n{len(problems)} PROBLEM(S)")
    sys.exit(1 if problems else 0)


def check_reveal(e, stem, at):
    """Status of a commit: revealed pick, pending, or UNREVEALED."""
    day = e["trading_date"]
    due = at(next_weekday(day), "window_open")
    rv = ROOT / "reveals" / f"{stem}.json"
    if not rv.exists():
        if dt.datetime.now(UTC) > due:
            return "UNREVEALED"
        if dt.datetime.now(UTC) > at(day, "reveal"):
            return "committed, reveal overdue (UNREVEALED after " + due.astimezone(NY).strftime("%Y-%m-%d %H:%M NY") + ")"
        return "committed (reveal at " + at(day, "reveal").astimezone(NY).strftime("%H:%M NY") + ")"
    raw = rv.read_bytes()
    p = json.loads(raw)
    import re
    if hashlib.sha256(raw).hexdigest() != e["commitment"]:
        bad(f"{rv.name}: does not match the commitment")
        return "BAD REVEAL"
    if p.get("trading_date") != day or p.get("posted_at") != e.get("posted_at"):
        bad(f"{rv.name}: date or posting time differs from the commit entry")
    if not re.match(TICKER_RE, p.get("ticker", "")) or p.get("side") not in ("LONG", "SHORT") \
            or len(p.get("salt", "")) != 64:
        bad(f"{rv.name}: malformed pick")
    times = tsa_verified(rv, sorted((ROOT / "proofs").glob(f"{stem}.reveal.*.tsr")))
    if len(times) < MIN_TSAS or times[MIN_TSAS - 1] > due:
        return f"UNREVEALED (revealed late) {p.get('ticker')} {p.get('side')}"
    return f"{p['ticker']} {p['side']}"


def next_weekday(day):
    d = dt.date.fromisoformat(day) + dt.timedelta(days=1)
    while d.weekday() >= 5:
        d += dt.timedelta(days=1)
    return d.isoformat()


if __name__ == "__main__":
    main()
