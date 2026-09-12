"""Root-level entrypoint for rank_vulnerabilities.py.

Delegates directly to graphify-challenge-submission/rank_vulnerabilities.py.
Supports both synthetic development mode and general CSV evaluation mode.
"""

import sys
from pathlib import Path

# Add challenge submission folder to sys.path
submission_dir = Path(__file__).resolve().parent / "graphify-challenge-submission"
sys.path.insert(0, str(submission_dir))

from rank_vulnerabilities import main

if __name__ == "__main__":
    main()
