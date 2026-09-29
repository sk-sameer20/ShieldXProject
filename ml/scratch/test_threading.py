import sys
import time
import asyncio
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

async def test_5():
    print("TEST 5: Import TF on main thread, load model via asyncio.to_thread")
    t0 = time.time()
    # 1. Import on main thread (triggers `import tensorflow as tf` in inference.py)
    from src.dga.inference import run_dga_detection
    print("  [+] Imported run_dga_detection on main thread")
    
    # 2. Call prediction (which initializes DGADetectorPanel and calls tf.keras.models.load_model) inside worker thread
    print("  [+] Starting worker thread to load model...")
    t_start = time.time()
    try:
        res = await asyncio.wait_for(
            asyncio.to_thread(run_dga_detection, "test5.com", src_ip="10.0.0.1"),
            timeout=15.0
        )
        print(f"  [+] Threaded Load & Inference: {time.time() - t_start:.4f}s")
        print(f"  [+] Result: {res.detected}")
    except asyncio.TimeoutError:
        print("  [-] TIMEOUT! Hang confirmed in TEST 5.")
    except Exception as e:
        print(f"  [-] EXCEPTION: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "5":
        asyncio.run(test_5())
