#!/usr/bin/env python3
"""Parallel checksum-manifest generator (GNU checksum text format)."""
import argparse
import concurrent.futures
import os
import sys

from hashcore import DEFAULTS, SUPPORTED, hash_file


def checksum_line(digest, filename):
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
    personality = os.path.basename(sys.argv[0])
    if personality in ("sha256sum", "sha512sum") and "--check" in sys.argv[1:]:
        import hashcheck
        sys.argv.remove("--check")
        return hashcheck.main()
    default_algorithms = {"sha256sum": ("sha256",), "sha512sum": ("sha512",)}.get(personality, DEFAULTS)
    p = argparse.ArgumentParser(description="Generate parallel SHA checksum manifests.")
    p.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 1)
    p.add_argument("--chunk-mib", type=int, default=8, metavar="N")
    p.add_argument("--no-advice", action="store_true")
    p.add_argument("-b", "--binary", action="store_true", help="read files in binary mode (default)")
    p.add_argument("-t", "--text", action="store_true", help="accepted for GNU-style compatibility")
    p.add_argument("--truncate", action="store_true", help="overwrite output manifests instead of appending")
    p.add_argument("--sha1", action="store_true", help="also calculate SHA-1")
    p.add_argument("--sha256", action="store_true", help="calculate SHA-256")
    p.add_argument("--sha384", action="store_true", help="also calculate SHA-384")
    p.add_argument("--sha512", action="store_true", help="calculate SHA-512")
    p.add_argument("--outsha1", metavar="FILE")
    p.add_argument("--outsha256", metavar="FILE")
    p.add_argument("--outsha384", metavar="FILE")
    p.add_argument("--outsha512", metavar="FILE")
    p.add_argument("--outsha256512", metavar="FILE", help="write SHA-256 and SHA-512 records to one file")
    p.add_argument("-o256", "--output256", dest="legacy256", help=argparse.SUPPRESS)
    p.add_argument("-o512", "--output512", dest="legacy512", help=argparse.SUPPRESS)
    p.add_argument("files", nargs="+", metavar="FILE")
    a = p.parse_args()
    if a.jobs < 1 or a.chunk_mib < 1:
        p.error("--jobs and --chunk-mib must be positive")

    explicit = any((a.sha1, a.sha256, a.sha384, a.sha512))
    if explicit:
        algorithms = tuple(x for x, enabled in (("sha1", a.sha1), ("sha256", a.sha256), ("sha384", a.sha384), ("sha512", a.sha512)) if enabled)
    else:
        algorithms = default_algorithms
    outputs = {"sha1": a.outsha1, "sha256": a.outsha256 or a.legacy256, "sha384": a.outsha384,
               "sha512": a.outsha512 or a.legacy512}
    if a.outsha256512:
        if a.outsha256 or a.outsha512 or a.legacy256 or a.legacy512:
            p.error("--outsha256512 cannot be combined with separate SHA-256/SHA-512 output options")
        outputs["sha256512"] = a.outsha256512
        algorithms = tuple(dict.fromkeys((*algorithms, "sha256", "sha512")))
    if not any(outputs.values()):
        if personality in ("sha256sum", "sha512sum"):
            outputs[default_algorithms[0]] = "-"
        else:
            outputs["sha1"] = "SHA1SUMS" if "sha1" in algorithms else None
            outputs["sha256"] = "SHA256SUMS" if "sha256" in algorithms else None
            outputs["sha384"] = "SHA384SUMS" if "sha384" in algorithms else None
            outputs["sha512"] = "SHA512SUMS" if "sha512" in algorithms else None
    for alg, path in list(outputs.items()):
        if path and alg not in algorithms:
            algorithms = tuple((*algorithms, *(('sha256', 'sha512') if alg == 'sha256512' else (alg,))))
    destinations = [v for v in outputs.values() if v]
    for i, out in enumerate(destinations):
        for inp in a.files:
            if same_file(out, inp):
                p.error(f"output file is also an input file: {inp}")
        if any(same_file(out, other) for other in destinations[:i]):
            p.error("output destinations must be distinct")

    chunk = a.chunk_mib * 1024 * 1024
    errors = 0
    # Preserve input order regardless of worker completion order.
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as pool:
        futures = [pool.submit(hash_file, f, algorithms, chunk, not a.no_advice) for f in a.files]
        results = []
        for filename, future in zip(a.files, futures):
            try:
                results.append((filename, future.result(), None))
            except OSError as exc:
                errors += 1
                results.append((filename, None, exc))
                print(f"hashfiles.py: {filename}: {exc}", file=sys.stderr)

    try:
        mode = "wb" if a.truncate else "ab"
        for key, path in outputs.items():
            if not path:
                continue
            algs = ("sha256", "sha512") if key == "sha256512" else (key,)
            if path == "-":
                out = sys.stdout.buffer
                close_out = False
            else:
                out = open(path, mode)
                close_out = True
            try:
                for filename, digests, error in results:
                    if error is None:
                        for alg in algs:
                            out.write(checksum_line(digests[alg], filename))
                out.flush()
            finally:
                if close_out: out.close()
    except OSError as exc:
        print(f"hashfiles.py: output error: {exc}", file=sys.stderr)
        return 1
    print(f"Completed: {len(a.files) - errors} successful, {errors} failed.", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
