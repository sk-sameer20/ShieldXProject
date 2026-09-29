"""
tests/conftest.py — pytest configuration for SIH26145 C2+DGA/DNS module.
Adds project root to sys.path so all src.* imports resolve correctly.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
