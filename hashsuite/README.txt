hashsuite
=========

Python 3 streaming checksum tools. Requires only the Python standard library.

Files
-----
hashcore.py       Shared streaming hashing engine.
hashfiles.py      Parallel manifest generator.
hashcheck.py      Parallel multi-algorithm manifest verifier.
sha256sum         SHA-256 GNU-style front end (symlink to hashfiles.py).
sha512sum         SHA-512 GNU-style front end (symlink to hashfiles.py).
tests/            Regression tests and deterministic filename-corpus tests.

Generation
----------

Combined SHA-256 + SHA-512 generation (default):
  ./hashfiles.py file1 file2

By default, append records to SHA256SUMS and SHA512SUMS in the current directory.
Use --truncate to replace those files. Use -j N and --chunk-mib N to tune
parallel file processing and read buffer size. --no-advice disables optional
POSIX sequential/no-reuse file-cache advice.

Optional algorithms:
  ./hashfiles.py --sha1 --sha384 file1 file2
  ./hashfiles.py --sha1 --sha256 --sha384 --sha512 file1

Per-algorithm outputs:
  ./hashfiles.py --sha1 --sha384 --outsha1 SHA1SUMS --outsha384 SHA384SUMS file1
  ./hashfiles.py --outsha256512 BOTH.SUMS file1 file2

The sha256sum and sha512sum front ends calculate only their named algorithm:
  ./sha256sum file1 file2
  ./sha512sum file1 file2
  cat file | ./sha256sum -

On Unix, default output uses the GNU text-mode marker (two spaces). --binary
or -b uses the binary marker (space plus '*'). --text or -t selects text mode.
Files are always opened in binary mode by Python; on Unix this is equivalent
for hashing purposes. A filename containing backslash, LF, or CR is escaped
using GNU's leading-backslash convention and \\, \n, and \r escapes. Filename
bytes are preserved using the filesystem encoding/surrogateescape interface.

Verification
------------

  ./hashcheck.py SHA256SUMS SHA512SUMS
  ./hashcheck.py --sha384 SHA384SUMS
  ./sha256sum --check SHA256SUMS
  ./sha512sum --check SHA512SUMS

With no algorithm selector, hashcheck.py recognizes SHA-1, SHA-256, SHA-384,
and SHA-512 by digest length. With selectors, it verifies only selected
algorithms. Multiple manifests and duplicate records are supported; each
unique checked pathname is read once, with all required digests calculated in
that pass. Results are printed in manifest order.

The verifier can refresh inventories during the same file-reading pass:
  ./hashcheck.py SHA256SUMS --outsha512 SHA512SUMS.new
  ./hashcheck.py SHA256SUMS --outsha256512 BASELINES.new

Inventory outputs are written through temporary files and atomically replaced.
Successfully read files are included even if an existing checksum mismatches.
An output path may not alias an input manifest, checked input, or another
output path. Standard input can be used as checked data when the manifest is a
file; it cannot simultaneously supply both the manifest and checked data.

Common verification options include --quiet, --status, --ignore-missing,
--warn, and --strict. These tools implement common GNU checksum workflows,
not every coreutils option or input format. In particular, --zero and BSD/tag
formats are not currently implemented.

Tests
-----

Run the local regression suite from this directory:
  python3 -m unittest discover -s tests -v

The suite includes byte-oriented and seeded-random valid Unix filename cases,
long components and paths, CR/LF/backslash escaping, non-UTF-8 names, CRLF
manifests, stdin, all four algorithms, output-path collision checks, and
GNU differential tests when GNU coreutils sha*sum commands are installed.
The GNU differential tests compare generated output and cross-check manifests
in both directions. The seeded corpus is deterministic and reproducible.


Verifier malformed-line controls
-------------------------------
Malformed checksum records are ignored by default, matching the usual GNU
checksum behavior.  --warn prints diagnostics for malformed records; --strict
returns a failure status if any malformed record is present.  The two options
can be combined.  --status suppresses diagnostics and normal result output.

Inventory output staging
------------------------
When hashcheck.py is asked to write multiple inventory files, it writes and
flushes all temporary files before replacing any requested destination.  This
prevents a failure while preparing a later output from leaving an earlier
inventory partially refreshed.  Each final replacement is atomic on its own.

The default worker count is capped at 32 to avoid creating an excessive number
of threads on machines reporting very large CPU counts; use --jobs to override.
