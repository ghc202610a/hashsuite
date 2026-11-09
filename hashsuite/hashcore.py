#!/usr/bin/env python3
"""Shared streaming hashing engine for hashsuite."""
import hashlib
import os

SUPPORTED = ("sha1", "sha256", "sha384", "sha512")
DEFAULTS = ("sha256", "sha512")


def _new_hashers(algorithms):
    names = tuple(dict.fromkeys(algorithms))
    unknown = set(names).difference(SUPPORTED)
    if unknown:
        raise ValueError("unsupported hash algorithm(s): " + ", ".join(sorted(unknown)))
    return {name: hashlib.new(name) for name in names}


def _advise(fd, enabled=True):
    """Best-effort sequential/no-reuse advice; unsupported advice is ignored."""
    if not enabled or not hasattr(os, "posix_fadvise"):
        return
    for attr in ("POSIX_FADV_SEQUENTIAL", "POSIX_FADV_NOREUSE"):
        advice = getattr(os, attr, None)
        if advice is not None:
            try:
                os.posix_fadvise(fd, 0, 0, advice)
            except OSError:
                pass


def hash_stream(stream, algorithms=DEFAULTS, chunk_size=8 * 1024 * 1024):
    """Hash a readable binary stream once; return {algorithm: digest_bytes}."""
    if chunk_size < 1:
        raise ValueError("chunk_size must be positive")
    hashers = _new_hashers(algorithms)
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        view = memoryview(chunk)
        for hasher in hashers.values():
            hasher.update(view)
    return {name: hasher.digest() for name, hasher in hashers.items()}


def hash_file(filename, algorithms=DEFAULTS, chunk_size=8 * 1024 * 1024, advise=True):
    """Hash a file once; return {algorithm: digest_bytes}."""
    with open(filename, "rb") as stream:
        _advise(stream.fileno(), advise)
        return hash_stream(stream, algorithms, chunk_size)
