"""Check out a branch (sample: chaining pattern)."""
import os
import sys

branch = sys.argv[1]
os.system(f"git checkout {branch}")
