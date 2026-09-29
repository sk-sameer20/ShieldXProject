print("1. Starting import of run_demo")
import sys
from pathlib import Path
PROJECT_ROOT = Path("c:/Users/stkha/Desktop/SIH/sih26145-c2-dga-detector").resolve()
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "backend" / "sih26145-streaming-engine"))

import importlib.util
spec = importlib.util.spec_from_file_location("run_demo", str(PROJECT_ROOT / "backend" / "sih26145-streaming-engine" / "run_demo.py"))
run_demo = importlib.util.module_from_spec(spec)

print("2. Executing run_demo module")
spec.loader.exec_module(run_demo)

print("3. Module loaded successfully")
