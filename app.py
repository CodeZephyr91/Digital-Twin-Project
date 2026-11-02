"""Main entrypoint for 5G Lab Doctor Streamlit application.

Usage:
    streamlit run app.py
"""

import sys
from pathlib import Path

# Ensure root directory is in sys.path
root_dir = Path(__file__).resolve().parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

# Import dashboard module
import dashboard

# Crucial: Execute dashboard rendering on every Streamlit script rerun cycle
dashboard.render_dashboard()
