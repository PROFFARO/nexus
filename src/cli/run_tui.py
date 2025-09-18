#!/usr/bin/env python3
"""
NEXUS TUI Launcher - Simple launcher for the Textual interface
"""

import sys
import subprocess
from pathlib import Path

def main():
    """Launch the NEXUS TUI"""
    try:
        # Check if textual is installed
        import textual
        import rich
    except ImportError:
        print("❌ Missing dependencies!")
        print("Please install required packages:")
        print("pip install textual rich")
        print("Or: pip install -r requirements-textual.txt")
        return 1
    
    # Launch the TUI
    try:
        from nexus_tui import main as tui_main
        tui_main()
    except Exception as e:
        print(f"❌ Error launching TUI: {e}")
        print("Falling back to original CLI...")
        
        # Fallback to original CLI
        cli_path = Path(__file__).parent / "nexus_cli.py"
        subprocess.run([sys.executable, str(cli_path)] + sys.argv[1:])
        
    return 0

if __name__ == "__main__":
    sys.exit(main())