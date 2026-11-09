hashsuite
=========

Python 3 streaming checksum tools. Requires only the Python standard library.

Files
-----
hashcore.py   Shared streaming hashing engine.
hashfiles.py  Parallel manifest generator.
hashcheck.py  Parallel GNU-style manifest verifier.
sha256sum     SHA-256 GNU-style front-end wrapper.
sha512sum     SHA-512 GNU-style front-end wrapper.

Combined generation
-------------------
  ./hashfiles.py file1 file2

By default this appends SHA256SUMS and SHA512SUMS in the current directory.
Use --truncate to replace them. Use -j N and --chunk-mib N to tune parallel
file processing and read-buffer size. --no-advice disables best-effort
POSIX sequential/no-reuse advice.

Optional algorithms
-------------------
  ./hashfiles.py --sha1 --sha256 --sha384 --sha512 file1 file2

SHA-1 and SHA-384 are supported but are not calculated by default. The
verifier recognizes SHA-1, SHA-256, SHA-384, and SHA-512 records by digest
length. Use --sha1, --sha256, --sha384, and/or --sha512 to select algorithms;
without selectors it verifies every recognized algorithm in the manifest(s).

GNU-style personalities
-----------------------
  ./sha256sum file1 file2
  ./sha256sum --check SHA256SUMS
  ./sha512sum file1 file2
  ./sha512sum --check SHA512SUMS

The wrappers use the basename personality. They support common checksum
workflows, not every GNU coreutils option or edge case. Files are read in
binary mode. A filename of '-' denotes standard input in check manifests.

Verifier examples
-----------------
  ./hashcheck.py SHA256SUMS SHA512SUMS
  ./hashcheck.py --sha384 SHA384SUMS
  ./hashcheck.py -j 4 SHA256SUMS

Generation output options
-------------------------
  --outsha1 FILE --outsha256 FILE --outsha384 FILE --outsha512 FILE
  --outsha256512 FILE

Without explicit output paths, combined mode appends SHA256SUMS and/or
SHA512SUMS as applicable. Output paths must not collide with input files or
with one another. Generation preserves input argument order.

Verification can also refresh inventory files in the same file-reading pass:
  ./hashcheck.py SHA256SUMS --outsha512 SHA512SUMS.new
  ./hashcheck.py SHA256SUMS --outsha256512 BASELINES.new
The optional --outsha1, --outsha256, --outsha384, and --outsha512 options
write separate inventories; --outsha256512 writes both algorithms to one file.
These outputs are replaced atomically and include files that were readable even
when an existing manifest checksum mismatched. Verification still exits nonzero
for mismatches or read failures. Output paths may not collide with manifests or
checked input files.
