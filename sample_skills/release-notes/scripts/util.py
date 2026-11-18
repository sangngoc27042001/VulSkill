"""Shared helpers."""
import os


def run(cmd):
    # Vulnerable pattern: executes a shell string built by the caller.
    return os.system(cmd)
