#!/usr/bin/env python3
"""Generate GNU sha256sum/sha512sum-compatible checksum manifests."""

import argparse
import concurrent.futures
import os
import sys
import threading

from hashcore import hash_file


def checksum_line(digest, filename):
    """GNU checksum binary-mode record, including escaped filenames."""
    name = os.fsencode(filename)
    escaped = b"\\" in name or b"\n" in name
    if escaped:
        name = name.replace(b"\\", b"\\\\").replace(b"\n", b"\\n")
    return (b"\\" if escaped else b"") + digest.hex().encode("ascii") + b" *" + name + b"\n"


def same_file(path1, path2):
    if os.path.abspath(path1) == os.path.abspath(path2):
        return True
    try:
        return os.path.samefile(path1, path2)
    except (OSError, ValueError):
        return os.path.realpath(path1) == os.path.realpath(path2)


def main():
    parser = argparse.ArgumentParser(description="Parallel GNU-compatible SHA-256/SHA-512 checksum generator.")
    parser.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 1,
                        help="maximum concurrent file workers (default: CPU count)")
    parser.add_argument("--chunk-mib", type=int, default=8, metavar="N",
                        help="read buffer size in MiB (default: 8)")
    parser.add_argument("-o256", "--output256", default="SHA256SUMS", metavar="FILE")
    parser.add_argument("-o512", "--output512", default="SHA512SUMS", metavar="FILE")
    parser.add_argument("--truncate", action="store_true", help="truncate rather than append")
    parser.add_argument("--no-advice", action="store_true", help="disable Linux sequential/NOREUSE advice")
    parser.add_argument("files", nargs="+", metavar="FILE")
    args = parser.parse_args()
    if args.jobs < 1 or args.chunk_mib < 1:
        parser.error("--jobs and --chunk-mib must be positive")
    for out in (args.output256, args.output512):
        for filename in args.files:
            if same_file(out, filename):
                parser.error(f"output file is also an input file: {filename}")
    if same_file(args.output256, args.output512):
        parser.error("SHA-256 and SHA-512 output files must differ")

    mode = "wb" if args.truncate else "ab"
    try:
        out256 = open(args.output256, mode)
        try:
            out512 = open(args.output512, mode)
        except OSError:
            out256.close()
            raise
    except OSError as exc:
        parser.error(f"cannot open output file: {exc}")

    errors = 0
    lock = threading.Lock()
    chunk_size = args.chunk_mib * 1024 * 1024
    try:
        with out256, out512:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
                futures = {pool.submit(hash_file, name, ("sha256", "sha512"),
                                       chunk_size, not args.no_advice): name
                           for name in args.files}
                for future in concurrent.futures.as_completed(futures):
                    filename = futures[future]
                    try:
                        digests = future.result()
                    except OSError as exc:
                        errors += 1
                        print(f"hashfiles.py: {filename}: {exc}", file=sys.stderr)
                        continue
                    line256 = checksum_line(digests["sha256"], filename)
                    line512 = checksum_line(digests["sha512"], filename)
                    with lock:
                        out256.write(line256)
                        out512.write(line512)
                    print(f"OK: {filename}", file=sys.stderr)
    except OSError as exc:
        print(f"hashfiles.py: output error: {exc}", file=sys.stderr)
        return 1
    print(f"Completed: {len(args.files) - errors} successful, {errors} failed.", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
