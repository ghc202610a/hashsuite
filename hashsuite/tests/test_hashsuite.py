#!/usr/bin/env python3
"""Focused regression and GNU differential tests for hashsuite.

Run from the extracted suite directory with: python3 -m unittest discover -s tests -v
GNU differential cases are skipped when the corresponding GNU utility is absent.
"""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


def has_gnu_sum(algorithm):
    exe = shutil.which(algorithm + "sum")
    if not exe:
        return False
    version = subprocess.run([exe, "--version"], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True).stdout
    return "GNU coreutils" in version


GNU_SHA256 = has_gnu_sum("sha256")


def run(args, *, cwd, input_bytes=None):
    return subprocess.run([PYTHON, *map(str, args)], cwd=cwd, input=input_bytes,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class HashSuiteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write_name(self, name, payload=b"test payload\x00\xff"):
        path = os.fsencode(self.cwd) + b"/" + name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
        return path

    @unittest.skipUnless(GNU_SHA256, "GNU coreutils sha256sum unavailable")
    def test_default_output_matches_gnu_text_mode(self):
        (self.cwd / "ordinary").write_bytes(b"abc\x00\xff")
        ours = run([ROOT / "hashfiles.py", "ordinary"], cwd=self.cwd)
        self.assertEqual(ours.returncode, 0, ours.stderr)
        gnu = subprocess.run(["sha256sum", "ordinary"], cwd=self.cwd,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Combined default mode emits SHA-256 and SHA-512 to separate files;
        # use the sha256sum personality for the GNU single-algorithm comparison.
        wrapper = ROOT / "sha256sum"
        ours_single = subprocess.run([str(wrapper), "ordinary"], cwd=self.cwd,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(ours_single.returncode, 0, ours_single.stderr)
        self.assertEqual(ours_single.stdout, gnu.stdout)

    @unittest.skipUnless(GNU_SHA256, "GNU coreutils sha256sum unavailable")
    def test_binary_marker(self):
        (self.cwd / "f").write_bytes(b"x")
        ours = run([ROOT / "sha256sum", "--binary", "f"], cwd=self.cwd)
        gnu = subprocess.run(["sha256sum", "--binary", "f"], cwd=self.cwd,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(ours.returncode, 0, ours.stderr)
        self.assertEqual(ours.stdout, gnu.stdout)

    @unittest.skipUnless(GNU_SHA256, "GNU coreutils sha256sum unavailable")
    def test_stdin_generation(self):
        ours = run([ROOT / "sha256sum", "-"], cwd=self.cwd, input_bytes=b"stdin payload")
        gnu = subprocess.run(["sha256sum", "-"], cwd=self.cwd, input=b"stdin payload",
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(ours.returncode, 0, ours.stderr)
        self.assertEqual(ours.stdout, gnu.stdout)

    @unittest.skipUnless(GNU_SHA256, "GNU coreutils sha256sum unavailable")
    def test_escaped_names_round_trip(self):
        names = [b"space name", b"tab\tname", b"line\nbreak", b"carriage\rreturn",
                 b"back\\slash", b"both\n\r\\", b"nonutf8-\xff", b"leading space"]
        for n, name in enumerate(names):
            self.write_name(name, f"payload-{n}".encode())
        paths = [os.fsdecode(os.fsencode(self.cwd) + b"/" + name) for name in names]
        manifest = self.cwd / "SUMS"
        generated = run([ROOT / "sha256sum", *paths], cwd=self.cwd)
        self.assertEqual(generated.returncode, 0, generated.stderr)
        manifest.write_bytes(generated.stdout)
        gnu = subprocess.run(["sha256sum", *paths], cwd=self.cwd,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(gnu.returncode, 0, gnu.stderr)
        self.assertEqual(generated.stdout, gnu.stdout)
        checked = run([ROOT / "hashcheck.py", "--status", "SUMS"], cwd=self.cwd)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        (self.cwd / "GNU.SUMS").write_bytes(gnu.stdout)
        checked_gnu = run([ROOT / "hashcheck.py", "--status", "GNU.SUMS"], cwd=self.cwd)
        self.assertEqual(checked_gnu.returncode, 0, checked_gnu.stderr)

    def test_long_filename_with_separator_like_bytes(self):
        # A SHA-256 record whose filename has enough hex bytes and a fake
        # separator at the SHA-512 offset. The parser must select SHA-256.
        name = b"a" * 62 + b" *" + b"tail"
        self.write_name(name, b"long name")
        digest = hashlib.sha256(b"long name").hexdigest().encode()
        record = digest + b"  " + name + b"\n"
        (self.cwd / "SUMS").write_bytes(record)
        checked = run([ROOT / "hashcheck.py", "--status", "SUMS"], cwd=self.cwd)
        self.assertEqual(checked.returncode, 0, checked.stderr)


    def test_duplicate_stdout_output_destination_rejected(self):
        (self.cwd / "f").write_bytes(b"x")
        result = run([ROOT / "hashfiles.py", "--outsha256", "-", "--outsha512", "-", "f"],
                     cwd=self.cwd)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_output_cannot_alias_manifest(self):
        (self.cwd / "f").write_bytes(b"x")
        digest = hashlib.sha256(b"x").hexdigest()
        (self.cwd / "SUMS").write_text(f"{digest}  f\n")
        before = (self.cwd / "SUMS").read_bytes()
        (self.cwd / "alias").symlink_to(self.cwd / "SUMS")
        result = run([ROOT / "hashcheck.py", "SUMS", "--outsha256", "alias"], cwd=self.cwd)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.cwd / "SUMS").read_bytes(), before)

    def test_two_output_names_must_not_alias(self):
        (self.cwd / "f").write_bytes(b"x")
        digest = hashlib.sha256(b"x").hexdigest()
        (self.cwd / "SUMS").write_text(f"{digest}  f\n")
        (self.cwd / "out").write_bytes(b"preserve")
        (self.cwd / "alias").symlink_to(self.cwd / "out")
        result = run([ROOT / "hashcheck.py", "SUMS", "--outsha256", "out",
                      "--outsha512", "alias"], cwd=self.cwd)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.cwd / "out").read_bytes(), b"preserve")

    def test_output_manifest_with_cr_filename(self):
        name = b"cr\rname"
        self.write_name(name, b"payload")
        path = os.fsdecode(os.fsencode(self.cwd) + b"/" + name)
        (self.cwd / "SUMS").write_bytes(b"\\" + hashlib.sha256(b"payload").hexdigest().encode() + b"  " + name.replace(b"\r", b"\\r") + b"\n")
        result = run([ROOT / "hashcheck.py", "--status", "SUMS", "--outsha256", "NEW"], cwd=self.cwd)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"\\r", (self.cwd / "NEW").read_bytes())


    @unittest.skipUnless(GNU_SHA256, "GNU coreutils sha256sum unavailable")
    def test_deterministic_random_filename_corpus(self):
        # Reproducible byte-oriented filename corpus: all bytes except NUL and
        # slash are legal in a Linux filename component. Keep each under 255 B.
        import random
        rng = random.Random(0x5A17)
        names = set()
        alphabet = [b for b in range(1, 256) if b != 0x2f]
        while len(names) < 64:
            length = rng.randint(1, 180)
            name = bytes(rng.choice(alphabet) for _ in range(length))
            if name not in (b".", b".."):
                names.add(name)
        names = sorted(names)
        for i, name in enumerate(names):
            self.write_name(name, hashlib.sha256(str(i).encode()).digest())
        args = [os.fsdecode(os.fsencode(self.cwd) + b"/" + name) for name in names]
        ours = subprocess.run([str(ROOT / "sha256sum"), *args], cwd=self.cwd,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        gnu = subprocess.run(["sha256sum", *args], cwd=self.cwd,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(ours.returncode, 0, ours.stderr)
        self.assertEqual(gnu.returncode, 0, gnu.stderr)
        self.assertEqual(ours.stdout, gnu.stdout)
        (self.cwd / "CORPUS.SUMS").write_bytes(ours.stdout)
        check = run([ROOT / "hashcheck.py", "--status", "CORPUS.SUMS"], cwd=self.cwd)
        self.assertEqual(check.returncode, 0, check.stderr)

    @unittest.skipUnless(GNU_SHA256, "GNU coreutils sha256sum unavailable")
    def test_long_path_and_crlf_manifest(self):
        current = self.cwd
        for i in range(12):
            current = current / (f"d{i:02d}_" + "x" * 170)
            current.mkdir()
        target = current / ("leaf_" + "y" * 170)
        target.write_bytes(b"long path payload")
        rel = os.path.relpath(target, self.cwd)
        gnu = subprocess.run(["sha256sum", rel], cwd=self.cwd,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(gnu.returncode, 0, gnu.stderr)
        (self.cwd / "CRLF.SUMS").write_bytes(gnu.stdout.replace(b"\n", b"\r\n"))
        checked = run([ROOT / "hashcheck.py", "--status", "CRLF.SUMS"], cwd=self.cwd)
        self.assertEqual(checked.returncode, 0, checked.stderr)


    def test_stdin_verification(self):
        digest = hashlib.sha256(b"pipe-data").hexdigest()
        (self.cwd / "STDIN.SUMS").write_text(f"{digest}  -\n")
        result = run([ROOT / "hashcheck.py", "--status", "STDIN.SUMS"],
                     cwd=self.cwd, input_bytes=b"pipe-data")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_comment_and_crlf_manifest_lines(self):
        (self.cwd / "f").write_bytes(b"x")
        digest = hashlib.sha256(b"x").hexdigest()
        (self.cwd / "SUMS").write_bytes(b"# generated comment\r\n" + digest.encode() + b"  f\r\n")
        result = run([ROOT / "hashcheck.py", "--status", "SUMS"], cwd=self.cwd)
        self.assertEqual(result.returncode, 0, result.stderr)


    @unittest.skipUnless(GNU_SHA256, "GNU coreutils sha256sum unavailable")
    def test_full_byte_set_and_max_component_name(self):
        # Every non-NUL, non-slash byte is legal in a Linux filename component.
        all_bytes = bytes(b for b in range(1, 256) if b != 0x2f)
        max_name = b"z" * 255
        self.write_name(all_bytes, b"all filename bytes")
        self.write_name(max_name, b"255-byte component")
        args = [os.fsdecode(os.fsencode(self.cwd) + b"/" + name)
                for name in (all_bytes, max_name)]
        ours = subprocess.run([str(ROOT / "sha256sum"), *args], cwd=self.cwd,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        gnu = subprocess.run(["sha256sum", *args], cwd=self.cwd,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(ours.returncode, 0, ours.stderr)
        self.assertEqual(gnu.returncode, 0, gnu.stderr)
        self.assertEqual(ours.stdout, gnu.stdout)
        (self.cwd / "ALLBYTES.SUMS").write_bytes(ours.stdout)
        checked = run([ROOT / "hashcheck.py", "--status", "ALLBYTES.SUMS"], cwd=self.cwd)
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_mismatch_still_generates_inventory(self):
        (self.cwd / "f").write_bytes(b"actual")
        wrong = hashlib.sha256(b"not actual").hexdigest()
        (self.cwd / "BAD.SUMS").write_text(f"{wrong}  f\n")
        result = run([ROOT / "hashcheck.py", "BAD.SUMS", "--outsha256", "REFRESHED"], cwd=self.cwd)
        self.assertNotEqual(result.returncode, 0)
        expected = hashlib.sha256(b"actual").hexdigest().encode()
        self.assertTrue((self.cwd / "REFRESHED").read_bytes().startswith(expected))

    def test_all_four_algorithms_and_inventory(self):
        (self.cwd / "f").write_bytes(b"algorithm payload")
        result = run([ROOT / "hashfiles.py", "--sha1", "--sha256", "--sha384", "--sha512",
                      "--outsha1", "A1", "--outsha256", "A256", "--outsha384", "A384",
                      "--outsha512", "A512", "f"], cwd=self.cwd)
        self.assertEqual(result.returncode, 0, result.stderr)
        for alg, filename in (("sha1", "A1"), ("sha256", "A256"), ("sha384", "A384"), ("sha512", "A512")):
            checked = run([ROOT / "hashcheck.py", "--status", filename], cwd=self.cwd)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            if has_gnu_sum(alg):
                gnu = subprocess.run([alg + "sum", "f"], cwd=self.cwd,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(gnu.returncode, 0, gnu.stderr)
                self.assertEqual((self.cwd / filename).read_bytes(), gnu.stdout)

    @unittest.skipUnless(GNU_SHA256, "GNU coreutils sha256sum unavailable")
    def test_gnu_manifest_checks_in_our_verifier(self):
        names = [b"with space", b"with\nnewline", b"with\rreturn", b"with\\slash"]
        for i, name in enumerate(names):
            self.write_name(name, f"gnu-{i}".encode())
        args = [os.fsdecode(os.fsencode(self.cwd) + b"/" + name) for name in names]
        gnu = subprocess.run(["sha256sum", *args], cwd=self.cwd,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(gnu.returncode, 0, gnu.stderr)
        (self.cwd / "GNU.SUMS").write_bytes(gnu.stdout)
        ours = run([ROOT / "hashcheck.py", "--status", "GNU.SUMS"], cwd=self.cwd)
        self.assertEqual(ours.returncode, 0, ours.stderr)


if __name__ == "__main__":
    unittest.main()
