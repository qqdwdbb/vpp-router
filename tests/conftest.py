"""Make test helpers and benchmark modules importable after the directory split."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / 'tests' / 'unit', ROOT / 'tests' / 'integration', ROOT / 'benchmarks'):
    sys.path.insert(0, str(path))
