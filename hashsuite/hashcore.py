#!/usr/bin/env python3
"""Shared streaming hash engine for hashfiles.py and hashcheck.py."""

import hashlib
import os


def _new_hashers(algorithms):
    return {name: hashlib.new(name) for name in algorithms}


def _advise(fd, enabled=True):
    """Best-effort sequential/no-reuse advice; advice failures are non-fatal."""
    if not enabled or not hasattr(os, "posix_fadvise"):
        return
    for attr in ("POSIX_FADV_SEQUENTIAL", "POSIX_FADV_NOREUSE"):
        advice = getattr(os, attr, None)
        if advice is not None:
            try:
                os.posix_fadvise(fd, 0, 0, advice)
            except OSError:
                pass


def hash_stream(stream, algorithms=("sha256", "sha512"), chunk_size=8 * 1024 * 1024):
    """Hash a readable binary stream once; return {algorithm: digest_bytes}."""
    hashers = _new_hashers(algorithms)
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        for hasher in hashers.values():
            hasher.update(chunk)
    return {name: hasher.digest() for name, hasher in hashers.items()}


def hash_file(filename, algorithms=("sha256", "sha512"),
              chunk_size=8 * 1024 * 1024, advise=True):
    """Hash a file once; return {algorithm: digest_bytes}."""
    with open(filename, "rb") as stream:
        _advise(stream.fileno(), advise)
        return hash_stream(stream, algorithms, chunk_size)
