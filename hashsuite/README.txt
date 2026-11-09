Parallel SHA-256 / SHA-512 utilities
====================================

Contents
--------
hashcore.py   Shared one-pass hashing engine.
hashfiles.py  Parallel manifest generator.
hashcheck.py  Parallel GNU-compatible manifest verifier.

Requirements
------------
Python 3.8+; standard library only.

Install
-------
Extract the shar archive, then run the scripts from the extracted directory
(or put all three files in the same directory). The scripts are executable.

Generate both manifests (append by default):
    ./hashfiles.py FILE [FILE ...]

Start fresh:
    ./hashfiles.py --truncate FILE [FILE ...]

Choose worker count and read chunk size:
    ./hashfiles.py -j 16 --chunk-mib 32 FILE [FILE ...]

Custom manifest names:
    ./hashfiles.py -o256 SHA256SUMS -o512 SHA512SUMS FILE [FILE ...]

Verify one or more manifests; algorithms are inferred from digest lengths:
    ./hashcheck.py SHA256SUMS SHA512SUMS

Filter a mixed manifest:
    ./hashcheck.py --sha256 mixed.sums
    ./hashcheck.py --sha512 mixed.sums

Read a manifest from stdin:
    cat SHA256SUMS | ./hashcheck.py -

Verify stdin as a checked file (manifest must come from a file):
    cat FILE | ./hashcheck.py stdin-checksums.sums

Both utilities accept -j N, --chunk-mib N, and --no-advice.

Design notes
------------
* Each file is read once, with all required hash algorithms updated from the
  same chunk buffer.
* Files are processed concurrently with ThreadPoolExecutor.
* The checker deduplicates identical filename byte strings across manifests.
* Checker output follows manifest argument order and record order, regardless
  of worker completion order.
* A filename of '-' in a checksum record refers to standard input. Standard
  input is consumed once and hashed with all algorithms needed for that record.
* A manifest argument of '-' means the manifest itself comes from stdin; it
  cannot simultaneously be used as the checked-file stream.
* GNU checksum filename escaping for backslashes and newlines is supported.
* Filesystem advice is best-effort and never required for correctness.
* Output generation appends unless --truncate is supplied. As with ordinary
  separate output files, a crash cannot make the two manifest updates atomic.

Compatibility
-------------
Generated records use GNU checksum binary-mode syntax and can be checked by
sha256sum --check and sha512sum --check on Linux. The checker accepts GNU-style
SHA-256 and SHA-512 records, including text/binary markers and escaped names.
