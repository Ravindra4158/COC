import importlib.util
import sys
from pathlib import Path

# Load graphify-challenge-submission/rank_vulnerabilities.py
_sub_path = Path(__file__).resolve().parent / "graphify-challenge-submission" / "rank_vulnerabilities.py"
_spec = importlib.util.spec_from_file_location("submission_rank_vulnerabilities", _sub_path)
_mod = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _mod
_spec.loader.exec_module(_mod)

# Expose all attributes in root module namespace
for _attr in dir(_mod):
    if not _attr.startswith("__"):
        globals()[_attr] = getattr(_mod, _attr)

if __name__ == "__main__":
    _mod.main()

