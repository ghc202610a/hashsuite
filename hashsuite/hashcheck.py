#!/usr/bin/env python3
"""Parallel verifier for GNU-compatible SHA-256/SHA-512 checksum manifests."""

import argparse
import concurrent.futures
import os
import re
import sys

from hashcore import hash_file, hash_stream

_HEX = re.compile(br"^[0-9a-fA-F]+$")


def decode_filename(name, escaped):
    if not escaped:
        return name
    result = bytearray()
    i = 0
    while i < len(name):
        byte = name[i]
        if byte != 0x5c:
            result.append(byte)
            i += 1
            continue
        if i + 1 >= len(name):
            raise ValueError("trailing backslash in escaped filename")
        nxt = name[i + 1]
        if nxt == ord("\\"):
            result.append(ord("\\"))
        elif nxt == ord("n"):
            result.append(ord("\n"))
        else:
            raise ValueError("invalid escape in filename")
        i += 2
    return bytes(result)


def parse_manifest(data, manifest_name, selected):
    """Return (records, malformed_count); records retain manifest order."""
    records = []
    malformed = 0
    for line_number, line in enumerate(data.split(b"\n"), 1):
        if not line:
            continue
        escaped = line.startswith(b"\\")
        body = line[1:] if escaped else line
        # SHA-256 is tested first: a long SHA-256 filename can itself
        # contain a space at byte offset 128.
        if len(body) >= 67 and body[64:66] in (b"  ", b" *"):
            digest = body[:64]
            separator = body[64:66]
            filename = body[66:]
        elif len(body) >= 131 and body[128:130] in (b"  ", b" *"):
            digest = body[:128]
            separator = body[128:130]
            filename = body[130:]
        else:
            malformed += 1
            print(f"hashcheck.py: {manifest_name}:{line_number}: improperly formatted checksum line", file=sys.stderr)
            continue
        if len(digest) not in (64, 128) or not _HEX.fullmatch(digest) or separator not in (b"  ", b" *") or not filename:
            malformed += 1
            print(f"hashcheck.py: {manifest_name}:{line_number}: improperly formatted checksum line", file=sys.stderr)
            continue
        algorithm = "sha256" if len(digest) == 64 else "sha512"
        try:
            filename = decode_filename(filename, escaped)
        except ValueError as exc:
            malformed += 1
            print(f"hashcheck.py: {manifest_name}:{line_number}: {exc}", file=sys.stderr)
            continue
        if algorithm not in selected:
            continue
        records.append({
            "algorithm": algorithm,
            "expected": bytes.fromhex(digest.decode("ascii")),
            "filename": filename,
            "manifest": manifest_name,
            "line": line_number,
        })
    return records, malformed


def display_name(name):
    escaped = b"\\" in name or b"\n" in name
    if escaped:
        name = name.replace(b"\\", b"\\\\").replace(b"\n", b"\\n")
        return b"\\" + name
    return name


def main():
    parser = argparse.ArgumentParser(description="Parallel GNU-compatible SHA-256/SHA-512 checksum verifier.")
    parser.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 1,
                        help="maximum concurrent workers (default: CPU count)")
    parser.add_argument("--chunk-mib", type=int, default=8, metavar="N",
                        help="read buffer size in MiB (default: 8)")
    parser.add_argument("--no-advice", action="store_true", help="disable Linux sequential/NOREUSE advice")
    parser.add_argument("--sha256", action="store_true", help="verify SHA-256 records only (default: infer)")
    parser.add_argument("--sha512", action="store_true", help="verify SHA-512 records only (default: infer)")
    parser.add_argument("manifests", nargs="+", metavar="MANIFEST",
                        help="checksum manifest(s); use - for standard input")
    args = parser.parse_args()
    if args.jobs < 1 or args.chunk_mib < 1:
        parser.error("--jobs and --chunk-mib must be positive")
    if args.manifests.count("-") > 1:
        parser.error("standard input may be used for only one manifest")

    # No switches means infer and verify all recognized algorithms.
    selected = {"sha256", "sha512"}
    if args.sha256 or args.sha512:
        selected = set()
        if args.sha256:
            selected.add("sha256")
        if args.sha512:
            selected.add("sha512")

    all_records = []
    malformed = 0
    try:
        for manifest in args.manifests:
            if manifest == "-":
                data = sys.stdin.buffer.read()
            else:
                with open(manifest, "rb") as stream:
                    data = stream.read()
            records, bad = parse_manifest(data, manifest, selected)
            all_records.extend(records)
            malformed += bad
    except OSError as exc:
        print(f"hashcheck.py: {exc}", file=sys.stderr)
        return 1

    if any(record["filename"] == b"-" for record in all_records) and "-" in args.manifests:
        print("hashcheck.py: cannot use standard input for both a manifest and a checked file", file=sys.stderr)
        return 1

    if not all_records:
        print("hashcheck.py: no checksum records selected", file=sys.stderr)
        return 1

    # Group records by exact filesystem-byte filename. Each distinct file is read once.
    work = {}
    for index, record in enumerate(all_records):
        key = record["filename"]
        item = work.setdefault(key, {"algorithms": set(), "records": []})
        item["algorithms"].add(record["algorithm"])
        item["records"].append(index)

    chunk_size = args.chunk_mib * 1024 * 1024
    results = {}
    future_keys = {}
    failures = 0
    mismatches = 0
    cursor = 0

    def emit_ready():
        nonlocal cursor, failures, mismatches
        while cursor < len(all_records):
            record = all_records[cursor]
            key = record["filename"]
            if key not in results:
                break
            result, error = results[key]
            name = display_name(key)
            if error is not None:
                status = b"FAILED open or read"
                failures += 1
            elif result[record["algorithm"]] == record["expected"]:
                status = b"OK"
            else:
                status = b"FAILED"
                mismatches += 1
            sys.stdout.buffer.write(name + b": " + status + b"\n")
            cursor += 1

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            # Queue stdin first so it can be consumed once while file workers run.
            for filename, item in work.items():
                algorithms = tuple(sorted(item["algorithms"]))
                if filename == b"-":
                    future = pool.submit(hash_stream, sys.stdin.buffer, algorithms, chunk_size)
                else:
                    path = os.fsdecode(filename)
                    future = pool.submit(hash_file, path, algorithms, chunk_size, not args.no_advice)
                future_keys[future] = filename

            for future in concurrent.futures.as_completed(future_keys):
                key = future_keys[future]
                try:
                    results[key] = (future.result(), None)
                except OSError as exc:
                    results[key] = (None, exc)
                    print(f"hashcheck.py: {os.fsdecode(key)}: {exc}", file=sys.stderr)
                emit_ready()
    except OSError as exc:
        print(f"hashcheck.py: output or input error: {exc}", file=sys.stderr)
        return 1

    sys.stdout.buffer.flush()
    total_failed = failures + mismatches + malformed
    if mismatches:
        noun = "checksum" if mismatches == 1 else "checksums"
        print(f"hashcheck.py: WARNING: {mismatches} computed {noun} did NOT match", file=sys.stderr)
    if malformed:
        noun = "line is" if malformed == 1 else "lines are"
        print(f"hashcheck.py: WARNING: {malformed} {noun} improperly formatted", file=sys.stderr)
    return 1 if total_failed else 0


if __name__ == "__main__":
    sys.exit(main())
