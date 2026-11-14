import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# NHI_SRC lets experiments/code_mutants.py run this suite against a mutated copy of src/
sys.path[:0] = [os.environ.get("NHI_SRC", str(ROOT / "src")), str(ROOT / "fixtures")]
