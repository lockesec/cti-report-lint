"""Tests run against the source tree (src/ layout) without an install; CI also
runs them against the installed package."""
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
