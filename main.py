#!/usr/bin/env python3
"""
Entry point for Ruleset Builder
This file is used by PyInstaller to build the executable
"""

if __name__ == "__main__":
    import sys
    import os

    # Ensure the script directory is in the path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

    # Import and run the main application
    from ruleset_builder import main
    main()
