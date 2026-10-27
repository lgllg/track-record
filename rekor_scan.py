#!/usr/bin/env python3
"""Fork check for the pick ledger against Sigstore Rekor v2. Stdlib + `openssl` only.

Every trading day the ledger pins a short window of the public Rekor log:
  start = tree size in the day's opening checkpoint (TSA-timestamped before 09:20 NY)
  end   = log index of the day's `close` entry (it holds a drand value from after the deadline)
A valid entry for that day can only sit inside this window, so downloading just these tiles shows
*every* entry ever signed with the ledger key for that day. Expected: our day entry + our close
entry, nothing else. Any other entry signed with the ledger key = fork.

Each downloaded tile is proven to be part of the log's signed checkpoint (Merkle inclusion), and
each opening checkpoint is proven to be a real past state of the log, so whoever serves the files
cannot hide entries from you. The download is streamed; nothing is kept unless you pass --cache.

  python3 rekor_scan.py --ledger .                    # last 3 trading days (~20 MB each)
  python3 rekor_scan.py --ledger . --months 3         # ~63 days, ~1.3 GB, asks first
  python3 rekor_scan.py --key ledger.pub.pem --range 170000000 170014000   # raw scan, no ledger

Ledger files used (repo root = --ledger):
  entries/NNNNNN.json      canonical JSON. 000000 = genesis with `ledger_pubkey` (base64 DER).
                           Day entries (`commit`, `pass`, `holiday`) carry `trading_date` and
                           `opening_checkpoint` {origin, size, root}; `close` entries carry `trading_date`.
  proofs/NNNNNN.rekor.json {origin, log_index}: where the entry sits in Rekor.
The Rekor digest of an entry is the sha256 of the entry file bytes.
"""
import argparse
import base64
import concurrent.futures
import datetime
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

# Rekor v2 logs and their checkpoint keys, from Sigstore's trusted_root.json
# (tuf-repo-cdn.sigstore.dev / tuf-repo-cdn.sigstage.dev). New shards get added here.
LOGS = {
    "log2025-1.rekor.sigstore.dev": "MCowBQYDK2VwAyEAt8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=",
    "log2025-alpha3.rekor.sigstage.dev": "MCowBQYDK2VwAyEAlD3dVc8yaP25mPtT/sJ59D3LLxGBgW/qYrM6x6KmOqk=",
}
TILE = 256
BYTES_PER_ENTRY = 1410        # measured 2026-10-26 on log2025-1
WARN_BYTES = 300 * 1024**2    # ask before downloading more than this
USER_AGENT = "pickledger-verify/1"


# ---------- HTTP + tiles ----------

class Log:
    def __init__(self, origin, cache=None):
        if origin not in LOGS:
            sys.exit(f"unknown Rekor log {origin!r}; known: {', '.join(LOGS)}")
        self.origin = origin
        self.url = "https://" + origin
        self.key_der = base64.b64decode(LOGS[origin])
        self.cache = Path(cache) if cache else None
        self.downloaded = 0
        self.tiles = {}

    def get(self, path):
        cached = self.cache / self.origin / path if self.cache and ".p/" not in path else None
        if cached and cached.exists():
            return cached.read_bytes()
        for attempt in range(5):
            try:
                req = urllib.request.Request(self.url + "/" + path, headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(req, timeout=60) as r:
                    data = r.read()
                break
            except urllib.error.HTTPError as e:
                if e.code not in (429, 500, 502, 503, 504) or attempt == 4:
                    raise
            except (urllib.error.URLError, TimeoutError):
                if attempt == 4:
                    raise
            time.sleep(2 ** attempt)
        self.downloaded += len(data)
        if cached:
            cached.parent.mkdir(parents=True, exist_ok=True)
            cached.write_bytes(data)
        return data

    def checkpoint(self):
        """Fetch the current checkpoint and verify the log's signature on it."""
        return parse_checkpoint(self.get("checkpoint").decode(), self.origin)

    @staticmethod
    def tile_path(prefix, index, width):
        parts = []
        while True:
            parts.insert(0, f"{index % 1000:03d}")
            index //= 1000
            if index == 0:
                break
        path = prefix + "/" + "/".join(["x" + p for p in parts[:-1]] + [parts[-1]])
        return path + (f".p/{width}" if width < TILE else "")

    def fetch_tile(self, prefix, index, width):
        """A tile with `width` items. Logs may drop old partial tiles once the full tile exists;
        then the full tile's first `width` items are the same."""
        try:
            return self.get(self.tile_path(prefix, index, width)), width
        except urllib.error.HTTPError as e:
            if e.code != 404 or width == TILE:
                raise
            return self.get(self.tile_path(prefix, index, TILE)), width

    def hash_tile(self, level, index, size):
        """Stored hashes of level `level` (nodes of height 8*level), tile `index`, for tree `size`."""
        key = (level, index, size)
        if key not in self.tiles:
            nodes = size >> (8 * level)
            width = min(TILE, nodes - index * TILE)
            # full tiles never change, so one cached copy serves every tree size
            full = (level, index, None)
            if width == TILE and full in self.tiles:
                self.tiles[key] = self.tiles[full]
            else:
                data, _ = self.fetch_tile(f"tile/{level}", index, width)
                data = data[:32 * width]
                if len(data) != 32 * width:
                    raise ValueError(f"hash tile {level}/{index}: bad length")
                self.tiles[key] = [data[i:i + 32] for i in range(0, len(data), 32)]
                if width == TILE:
                    self.tiles[full] = self.tiles[key]
        return self.tiles[key]

    def entries_tile(self, index, size):
        width = min(TILE, size - index * TILE)
        data, _ = self.fetch_tile("tile/entries", index, width)
        out, i = [], 0
        while i < len(data) and len(out) < width:
            n = int.from_bytes(data[i:i + 2], "big")
            out.append(data[i + 2:i + 2 + n])
            i += 2 + n
        if len(out) != width:
            raise ValueError(f"entries tile {index}: {len(out)} entries, expected {width}")
        return out


def ed25519_verify(spki_der, msg, sig):
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        pem = base64.encodebytes(spki_der).decode()
        (d / "k.pem").write_text(f"-----BEGIN PUBLIC KEY-----\n{pem}-----END PUBLIC KEY-----\n")
        (d / "m").write_bytes(msg)
        (d / "s").write_bytes(sig)
        r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", d / "k.pem",
                            "-rawin", "-in", d / "m", "-sigfile", d / "s"], capture_output=True)
        return r.returncode == 0


def parse_checkpoint(text, origin):
    """(size, root) of a checkpoint (signed note) after verifying the log's Ed25519 signature on it."""
    if origin not in LOGS:
        raise ValueError(f"unknown Rekor log {origin!r}")
    body, _, sigs = text.partition("\n\n")
    body += "\n"
    name0, size, root = body.splitlines()[:3]
    if name0 != origin:
        raise ValueError(f"checkpoint origin {name0!r} != {origin!r}")
    for line in sigs.splitlines():
        name, _, sig = line.removeprefix("— ").partition(" ")
        if name == origin:
            raw = base64.b64decode(sig)
            # signed note: 4-byte key hint + 64-byte Ed25519 signature
            if len(raw) == 68 and ed25519_verify(base64.b64decode(LOGS[origin]), body.encode(), raw[4:]):
                return int(size), base64.b64decode(root)
    raise ValueError("checkpoint signature by the log does not verify")


# ---------- Merkle tree (RFC 6962 / tlog-tiles) ----------

def leaf_hash(entry):
    return hashlib.sha256(b"\x00" + entry).digest()


def node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def inclusion_root(leaf, index, size, hashes):
    """Root implied by an RFC 9162 inclusion proof, or None if the proof is malformed."""
    fn, sn, r = index, size - 1, leaf
    for h in hashes:
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            r = node(h, r)
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            r = node(r, h)
        fn >>= 1
        sn >>= 1
    return r if sn == 0 else None


class Tree:
    """Computes hashes of a tree of `size` leaves from the log's hash tiles. `known` overrides
    nodes with hashes we computed ourselves from downloaded entries, so the resulting root only
    matches the signed checkpoint if those entries really are in the log at those positions."""

    def __init__(self, log, size, known=None):
        self.log, self.size, self.known = log, size, known or {}
        self.memo = {}

    def _covers_known(self, height, index):
        lo, hi = index << height, (index + 1) << height
        return any(h < height and lo <= i << h < hi for h, i in self.known)

    def subtree(self, height, index):
        """Hash of the complete subtree of 2**height leaves starting at leaf index << height."""
        if (height, index) in self.known:
            return self.known[height, index]
        if (height, index) in self.memo:
            return self.memo[height, index]
        if height % 8 == 0 and not self._covers_known(height, index):
            h = self.log.hash_tile(height // 8, index // TILE, self.size)[index % TILE]
        else:
            h = node(self.subtree(height - 1, 2 * index), self.subtree(height - 1, 2 * index + 1))
        self.memo[height, index] = h
        return h

    def range_hash(self, lo, hi):
        n = hi - lo
        if n & (n - 1) == 0 and lo % n == 0:
            return self.subtree(n.bit_length() - 1, lo // n)
        k = 1 << ((n - 1).bit_length() - 1)
        return node(self.range_hash(lo, lo + k), self.range_hash(lo + k, hi))

    def root(self):
        return self.range_hash(0, self.size)


# ---------- scanning ----------

def key_fingerprint(spki_der):
    """Bytes that appear in every encoding of the key (raw key / certificate): Ed25519 = the
    32-byte key, ECDSA P-256 = the 32-byte X coordinate (same in compressed + uncompressed form)."""
    if len(spki_der) == 44 and spki_der.startswith(bytes.fromhex("302a300506032b6570032100")):
        return spki_der[12:]
    if len(spki_der) == 91 and spki_der[26] == 4:
        return spki_der[27:59]
    sys.exit("ledger key must be Ed25519 or ECDSA P-256 (SubjectPublicKeyInfo DER)")


def entry_keys(entry_json):
    """All key material (DER bytes) an entry names as its verifier."""
    e = json.loads(entry_json)
    spec = e.get("spec", {})
    sigs = []
    for v in spec.values():
        s = v.get("signature") or v.get("signatures") or []
        sigs += s if isinstance(s, list) else [s]
    out = []
    for s in sigs:
        ver = s.get("verifier", {})
        for k in ("publicKey", "x509Certificate"):
            if k in ver:
                out.append(base64.b64decode(ver[k]["rawBytes"]))
    return out, e


def scan(log, start, end, fingerprint, size, root, workers=8):
    """Download leaves [start, end), prove them against (size, root), return our entries as
    {log_index: digest_hex}."""
    tiles = range(start // TILE, (end - 1) // TILE + 1)

    def one(t):
        entries = log.entries_tile(t, size)
        if len(entries) == TILE:
            known = {(8, t): Tree(log, 0, {(0, i): leaf_hash(e) for i, e in enumerate(entries)})
                     .range_hash(0, TILE)}
        else:
            known = {(0, t * TILE + i): leaf_hash(e) for i, e in enumerate(entries)}
        if Tree(log, size, known).root() != root:
            raise ValueError(f"entries tile {t} is not part of the signed log state")
        found = {}
        for i, raw in enumerate(entries):
            idx = t * TILE + i
            if not start <= idx < end:
                continue
            keys, e = entry_keys(raw)
            if any(fingerprint in k for k in keys):
                data = next(iter(e["spec"].values())).get("data", {})
                found[idx] = base64.b64decode(data.get("digest", "")).hex()
        return found

    out = {}
    with concurrent.futures.ThreadPoolExecutor(workers) as pool:
        for i, found in enumerate(pool.map(one, tiles), 1):
            out.update(found)
            print(f"\r  {i}/{len(tiles)} tiles, {log.downloaded / 1e6:.1f} MB", end="", file=sys.stderr)
    print(file=sys.stderr)
    return out


# ---------- ledger ----------

def load_ledger(root):
    root = Path(root)
    entries = []
    for f in sorted((root / "entries").glob("[0-9]" * 6 + ".json")):
        raw = f.read_bytes()
        proof = root / "proofs" / (f.stem + ".rekor.json")
        entries.append({
            "seq": int(f.stem),
            "obj": json.loads(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "rekor": json.loads(proof.read_text()) if proof.exists() else None,
        })
    if not entries or entries[0]["obj"].get("type") != "genesis":
        sys.exit("no genesis entry found in entries/")
    return entries


def day_windows(entries):
    """One window per trading day. Normal day: [opening checkpoint size, close index]. Late pass (the
    day's window was missed): [previous close index + 1, max(late pass, close) index] -- longer."""
    days, prev_close, out = {}, {}, []
    last_close = entries[0]
    for e in entries[1:]:
        o = e["obj"]
        d = days.setdefault(o.get("trading_date"), {})
        if o.get("type") == "close":
            d["close"] = e
            last_close = e
        else:
            d["day"] = e
            prev_close[o.get("trading_date")] = last_close
    for date, d in sorted(days.items()):
        if "day" not in d or "close" not in d:
            out.append({"date": date, "error": "day entry or close entry missing"})
            continue
        day, close = d["day"], d["close"]
        if not day["rekor"] or not close["rekor"]:
            out.append({"date": date, "error": "Rekor proof missing"})
            continue
        origin = day["rekor"]["origin"]
        own = {int(day["rekor"]["log_index"]): day["sha256"], int(close["rekor"]["log_index"]): close["sha256"]}
        if day["obj"].get("late"):
            before = prev_close[date]["rekor"]
            if not before or before["origin"] != origin:
                out.append({"date": date, "error": "late pass: no previous Rekor entry in the same log"})
                continue
            out.append({"date": date, "origin": origin, "start": int(before["log_index"]) + 1,
                        "cp_root": None, "end": max(own) + 1, "expected": own, "late": True})
            continue
        cp = day["obj"].get("opening_checkpoint") or {}
        if "size" not in cp:
            out.append({"date": date, "error": "opening checkpoint missing"})
            continue
        if not (origin == close["rekor"]["origin"] == cp.get("origin")):
            out.append({"date": date, "error": "day entry, close and checkpoint name different logs"})
            continue
        out.append({"date": date, "origin": origin, "start": int(cp["size"]),
                    "cp_root": base64.b64decode(cp["root"]),
                    "end": int(close["rekor"]["log_index"]) + 1, "expected": own})
    return out


def confirm(nbytes, assume_yes):
    print(f"Estimated download: {nbytes / 1e6:,.0f} MB (streamed; disk use ~0 unless --cache).")
    if nbytes > WARN_BYTES and not assume_yes:
        if not sys.stdin.isatty():
            sys.exit("Large download: re-run with --yes to confirm.")
        if input("This is a big download. Continue? [y/N] ").strip().lower() != "y":
            sys.exit("Cancelled.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ledger", help="path to the ledger repo")
    span = ap.add_mutually_exclusive_group()
    span.add_argument("--days", type=int, help="last N trading days (default 3)")
    span.add_argument("--months", type=int, help="last N months of trading days (large download)")
    ap.add_argument("--key", help="raw mode: PEM public key to look for")
    ap.add_argument("--range", nargs=2, type=int, metavar=("START", "END"), help="raw mode: leaf range")
    ap.add_argument("--log", default="log2025-1.rekor.sigstore.dev", help="raw mode: Rekor log origin")
    ap.add_argument("--cache", help="keep downloaded full tiles in this directory (reused next time)")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--yes", action="store_true", help="don't ask before large downloads")
    a = ap.parse_args()

    if a.range:
        if not a.key:
            ap.error("--range needs --key")
        der = subprocess.run(["openssl", "pkey", "-pubin", "-in", a.key, "-outform", "DER"],
                             capture_output=True, check=True).stdout
        log = Log(a.log, a.cache)
        size, root = log.checkpoint()
        start, end = a.range
        if not 0 <= start < end <= size:
            sys.exit(f"range must lie within the log (current size {size})")
        confirm((end - start) * BYTES_PER_ENTRY, a.yes)
        found = scan(log, start, end, key_fingerprint(der), size, root, a.workers)
        print(f"{end - start} entries scanned and proven against checkpoint size {size}")
        for idx, digest in sorted(found.items()):
            print(f"  signed with this key: log index {idx}  sha256 {digest}")
        print(f"{len(found)} match(es)")
        return

    if not a.ledger:
        ap.error("give --ledger, or --key with --range")
    entries = load_ledger(a.ledger)
    der = base64.b64decode(entries[0]["obj"]["ledger_pubkey"])
    fingerprint = key_fingerprint(der)
    windows = day_windows(entries)
    ledger_hashes = {e["sha256"]: f"{e['seq']:06d}" for e in entries}
    if a.months:
        cutoff = (datetime.date.today() - datetime.timedelta(days=round(30.44 * a.months))).isoformat()
        windows = [w for w in windows if w["date"] >= cutoff]
    else:
        windows = windows[-(a.days or 3):]
    if not windows:
        sys.exit("no trading days to check yet")
    confirm(sum((w["end"] - w["start"]) * BYTES_PER_ENTRY for w in windows if "error" not in w), a.yes)

    logs, heads, problems = {}, {}, 0
    for w in windows:
        if "error" in w:
            print(f"{w['date']}  PROBLEM  {w['error']}")
            problems += 1
            continue
        if w["origin"] not in logs:
            logs[w["origin"]] = Log(w["origin"], a.cache)
            heads[w["origin"]] = logs[w["origin"]].checkpoint()
        log = logs[w["origin"]]
        size, root = heads[w["origin"]]
        print(f"{w['date']}  window {w['start']:,} → {w['end']:,} ({w['end'] - w['start']:,} entries)")
        if w.get("late"):
            print("  late pass: longer window, from the previous close entry")
        elif Tree(log, w["start"]).root() != w["cp_root"]:
            print("  PROBLEM  opening checkpoint is not a real state of the log")
            problems += 1
            continue
        found = scan(log, w["start"], w["end"], fingerprint, size, root, a.workers)
        day_ok = True
        for idx, digest in sorted(found.items()):
            want = w["expected"].get(idx)
            if want is None and digest in ledger_hashes:
                print(f"  note     log index {idx} is another log of ledger entry {ledger_hashes[digest]}"
                      " (harmless: same file)")
            elif want is None:
                print(f"  FORK     log index {idx} is signed with the ledger key but is not in the ledger"
                      f" (sha256 {digest})")
                day_ok = False
            elif want != digest:
                print(f"  PROBLEM  log index {idx}: Rekor has {digest}, ledger file has {want}")
                day_ok = False
        for idx in sorted(set(w["expected"]) - set(found)):
            print(f"  PROBLEM  log index {idx} from the ledger is not signed with the ledger key in Rekor")
            day_ok = False
        print("  ok: no entries signed with the ledger key other than the ledger's own" if day_ok
              else "  day FAILED")
        problems += not day_ok

    total = sum(l.downloaded for l in logs.values())
    print(f"\n{len(windows)} day(s) checked, {total / 1e6:.1f} MB downloaded. "
          + ("NO FORKS FOUND" if not problems else f"{problems} PROBLEM(S)"))
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, urllib.error.URLError) as e:
        sys.exit(f"PROBLEM: {e} (check failed, nothing could be confirmed)")
