import time
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

def run_tests():
    print("--- TEST A: Import C2 inference module ---")
    t0 = time.time()
    from src.c2.inference import _get_detector as get_c2_detector
    t_import_c2 = time.time() - t0
    print(f"C2 import completed in {t_import_c2:.4f}s")

    print("\n--- TEST B: Load C2 model ---")
    t0 = time.time()
    c2_detector = get_c2_detector()
    t_load_c2 = time.time() - t0
    print(f"C2 model load completed in {t_load_c2:.4f}s")

    print("\n--- TEST C: Run C2 inference ---")
    t0 = time.time()
    from src.c2.inference import run_c2_detection
    record = {"timestamp": 1234567890, "dst_ip": "1.1.1.1", "duration": 1.0, "orig_bytes": 100, "resp_bytes": 100}
    run_c2_detection([record, record], src_ip="10.0.0.1")
    t_infer_c2 = time.time() - t0
    print(f"C2 inference completed in {t_infer_c2:.4f}s")

    print("\n--- TEST D: Import DGA inference module ---")
    t0 = time.time()
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '0'
    from src.dga.inference import DGADetectorPanel, run_dga_detection
    t_import_dga = time.time() - t0
    print(f"DGA import completed in {t_import_dga:.4f}s")

    print("\n--- TEST E: Load DGA v6 & v2 models (Panel) ---")
    t0 = time.time()
    dga_panel = DGADetectorPanel()
    t_load_dga = time.time() - t0
    print(f"DGA Panel load completed in {t_load_dga:.4f}s")

    print("\n--- TEST F: Run DGA inference ---")
    t0 = time.time()
    run_dga_detection("google.com", src_ip="10.0.0.1")
    t_infer_dga = time.time() - t0
    print(f"DGA inference completed in {t_infer_dga:.4f}s")

if __name__ == "__main__":
    run_tests()
