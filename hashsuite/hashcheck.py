#!/usr/bin/env python3
"""Parallel verifier for GNU-style SHA-1/SHA-256/SHA-384/SHA-512 manifests."""
import argparse
import concurrent.futures
import os
import re
import sys
import tempfile

from hashcore import SUPPORTED, hash_file, hash_stream
from hashfiles import checksum_line, same_file

_HEX = re.compile(br"^[0-9a-fA-F]+$")
_LENGTHS = {40: "sha1", 64: "sha256", 96: "sha384", 128: "sha512"}


def decode_filename(name, escaped):
    if not escaped:
        return name
    result = bytearray()
    i = 0
    while i < len(name):
        b = name[i]
        if b != 0x5c:
            result.append(b); i += 1; continue
        if i + 1 >= len(name):
            raise ValueError("trailing backslash in escaped filename")
        nxt = name[i + 1]
        if nxt == 0x5c: result.append(0x5c)
        elif nxt == ord("n"): result.append(0x0a)
        elif nxt == ord("r"): result.append(0x0d)
        else: raise ValueError("invalid escape in filename")
        i += 2
    return bytes(result)


def parse_manifest(data, manifest_name, selected):
    records, malformed = [], 0
    for line_no, line in enumerate(data.split(b"\n"), 1):
        # GNU accepts CRLF manifests; a literal CR in a filename is escaped as \r.
        if line.endswith(b"\r"):
            line = line[:-1]
        if not line or line.startswith(b"#"):
            continue
        escaped = line.startswith(b"\\")
        body = line[1:] if escaped else line
        found = None
        # Validate each digest candidate before accepting its separator. Otherwise
        # a long filename can contain "  " or " *" at a longer candidate offset.
        for length in (40, 64, 96, 128):
            candidate = body[:length]
            if (len(body) >= length + 2 and _HEX.fullmatch(candidate)
                    and body[length:length+2] in (b"  ", b" *")):
                found = (length, candidate, body[length+2:]); break
        if found is None:
            malformed += 1
            print(f"hashcheck.py: {manifest_name}:{line_no}: improperly formatted checksum line", file=sys.stderr)
            continue
        length, digest, filename = found
        if not _HEX.fullmatch(digest) or not filename:
            malformed += 1
            print(f"hashcheck.py: {manifest_name}:{line_no}: improperly formatted checksum line", file=sys.stderr)
            continue
        alg = _LENGTHS[length]
        try: filename = decode_filename(filename, escaped)
        except ValueError as exc:
            malformed += 1
            print(f"hashcheck.py: {manifest_name}:{line_no}: {exc}", file=sys.stderr)
            continue
        if alg in selected:
            records.append({"algorithm": alg, "expected": bytes.fromhex(digest.decode("ascii")),
                            "filename": filename, "manifest": manifest_name, "line": line_no})
    return records, malformed


def display_name(name):
    if any(ch in name for ch in (b"\\", b"\n", b"\r")):
        return (b"\\" + name.replace(b"\\", b"\\\\")
                .replace(b"\n", b"\\n").replace(b"\r", b"\\r"))
    return name


def main():
    personality = os.path.basename(sys.argv[0])
    p = argparse.ArgumentParser(description="Verify GNU-style SHA checksum manifests.")
    p.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 1)
    p.add_argument("--chunk-mib", type=int, default=8)
    p.add_argument("--no-advice", action="store_true")
    for alg in SUPPORTED: p.add_argument("--" + alg, action="store_true", help=f"verify {alg.upper()} records")
    p.add_argument("--quiet", action="store_true", help="do not print OK lines")
    p.add_argument("--status", action="store_true", help="suppress all output")
    p.add_argument("--strict", action="store_true", help="fail on improperly formatted lines")
    p.add_argument("--warn", action="store_true", help="warn about improperly formatted lines")
    p.add_argument("--ignore-missing", action="store_true", help="ignore missing files")
    p.add_argument("--outsha1", metavar="FILE")
    p.add_argument("--outsha256", metavar="FILE")
    p.add_argument("--outsha384", metavar="FILE")
    p.add_argument("--outsha512", metavar="FILE")
    p.add_argument("--outsha256512", metavar="FILE")
    p.add_argument("manifests", nargs="+", metavar="MANIFEST")
    a = p.parse_args()
    if a.jobs < 1 or a.chunk_mib < 1: p.error("--jobs and --chunk-mib must be positive")
    if a.manifests.count("-") > 1: p.error("standard input may be used for only one manifest")
    requested = {alg for alg in SUPPORTED if getattr(a, alg)}
    if personality in ("sha256sum", "sha512sum") and not requested: requested = {personality[:-3]}
    selected = requested or set(SUPPORTED)
    records, malformed = [], 0
    try:
        for manifest in a.manifests:
            data = sys.stdin.buffer.read() if manifest == "-" else open(manifest, "rb").read()
            recs, bad = parse_manifest(data, manifest, selected)
            records.extend(recs); malformed += bad
    except OSError as exc:
        print(f"hashcheck.py: {exc}", file=sys.stderr); return 1
    if any(r["filename"] == b"-" for r in records) and "-" in a.manifests:
        print("hashcheck.py: cannot use standard input for both a manifest and a checked file", file=sys.stderr); return 1
    if not records:
        print("hashcheck.py: no checksum records selected", file=sys.stderr); return 1
    output_paths = {"sha1": a.outsha1, "sha256": a.outsha256, "sha384": a.outsha384, "sha512": a.outsha512}
    if a.outsha256512:
        if a.outsha256 or a.outsha512: p.error("--outsha256512 conflicts with separate SHA-256/SHA-512 outputs")
        output_paths["sha256512"] = a.outsha256512
    out_algorithms = set()
    seen_outputs = []
    for key, path in output_paths.items():
        if path:
            out_algorithms.update(("sha256", "sha512") if key == "sha256512" else (key,))
            if any(manifest != "-" and same_file(path, manifest) for manifest in a.manifests):
                p.error(f"output path conflicts with an input manifest: {path}")
            if any(r["filename"] != b"-" and same_file(path, os.fsdecode(r["filename"])) for r in records):
                p.error(f"output path conflicts with a checked input file: {path}")
            if any(same_file(path, previous) for previous in seen_outputs):
                p.error("output destinations must be distinct")
            seen_outputs.append(path)
    work = {}
    for idx, rec in enumerate(records):
        item = work.setdefault(rec["filename"], {"algorithms": set(), "indices": []})
        item["algorithms"].add(rec["algorithm"]); item["indices"].append(idx)
    for item in work.values(): item["algorithms"].update(out_algorithms)
    results, failures, mismatches = {}, 0, 0
    chunk = a.chunk_mib * 1024 * 1024
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as pool:
        future_map = {}
        for name, item in work.items():
            algs = tuple(sorted(item["algorithms"]))
            if name == b"-": continue
            future_map[pool.submit(hash_file, os.fsdecode(name), algs, chunk, not a.no_advice)] = name
        if b"-" in work:
            try: results[b"-"] = (hash_stream(sys.stdin.buffer, tuple(sorted(work[b"-"]["algorithms"])), chunk), None)
            except OSError as exc: results[b"-"] = (None, exc)
        for future in concurrent.futures.as_completed(future_map):
            name = future_map[future]
            try: results[name] = (future.result(), None)
            except OSError as exc: results[name] = (None, exc)
    for rec in records:
        name = rec["filename"]; digest_map, error = results[name]
        if error:
            if not a.ignore_missing or not isinstance(error, FileNotFoundError):
                failures += 1
                print(f"hashcheck.py: {os.fsdecode(name)}: {error}", file=sys.stderr)
            if not (a.status or (a.ignore_missing and isinstance(error, FileNotFoundError))): sys.stdout.buffer.write(display_name(name) + b": FAILED open or read\n")
        elif digest_map[rec["algorithm"]] != rec["expected"]:
            mismatches += 1
            if not a.status: sys.stdout.buffer.write(display_name(name) + b": FAILED\n")
        elif not (a.quiet or a.status): sys.stdout.buffer.write(display_name(name) + b": OK\n")
    if malformed and (a.warn or a.strict):
        print(f"hashcheck.py: WARNING: {malformed} improperly formatted line(s)", file=sys.stderr)
    # Optional inventories are atomic and include every successfully read file,
    # even if an existing checksum record for that file did not match.
    for key, path in output_paths.items():
        if not path: continue
        algs = ("sha256", "sha512") if key == "sha256512" else (key,)
        temp_name = None
        try:
            fd, temp_name = tempfile.mkstemp(prefix=".hashcheck-", dir=os.path.dirname(os.path.abspath(path)))
            with os.fdopen(fd, "wb") as out:
                for name in work:
                    digest_map, error = results.get(name, (None, OSError("not processed")))
                    if error is None:
                        for alg in algs: out.write(checksum_line(digest_map[alg], os.fsdecode(name)))
                out.flush(); os.fsync(out.fileno())
            os.replace(temp_name, path); temp_name = None
        except OSError as exc:
            failures += 1
            print(f"hashcheck.py: cannot write {path}: {exc}", file=sys.stderr)
        finally:
            if temp_name is not None:
                try: os.unlink(temp_name)
                except OSError: pass
    sys.stdout.buffer.flush()
    return 1 if failures or mismatches or (malformed and a.strict) else 0


if __name__ == "__main__": sys.exit(main())
