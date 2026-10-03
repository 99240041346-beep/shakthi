"""Render bootstrap for the packaged CAMPUS SHAKTHI source.

The repository keeps the complete application in campus_shakthi_src.tar.gz.
This small loader extracts that package on first import so Render can use the
normal 'pip install -r requirements.txt' and 'gunicorn app:app' commands.
"""
from pathlib import Path
import importlib.util
import sys
import tarfile

ROOT = Path(__file__).resolve().parent
SRC = ROOT / ".campus_shakthi_runtime"
SOURCE_APP = SRC / "app.py"

if not SOURCE_APP.exists():
    archive = ROOT / "campus_shakthi_src.tar.gz"
    if not archive.exists():
        raise RuntimeError("campus_shakthi_src.tar.gz is missing from the repository")
    SRC.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:gz") as tf:
        tf.extractall(SRC)

sys.path.insert(0, str(SRC))
spec = importlib.util.spec_from_file_location("campus_shakthi_application", SOURCE_APP)
if spec is None or spec.loader is None:
    raise RuntimeError("Unable to load CAMPUS SHAKTHI application")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
app = module.app
