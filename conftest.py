import os
import sys

# Ensure the repo root (the `aegis` package + data/) is importable when pytest
# is run from anywhere.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
