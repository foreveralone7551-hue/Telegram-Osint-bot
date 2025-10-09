#!/usr/bin/env python3
"""
Wrapper script to run blackbird with proper environment setup
"""
import os
import sys
import subprocess
from pathlib import Path

def run_blackbird(args):
    """Run blackbird with the correct environment"""
    blackbird_dir = Path(__file__).parent / "blackbird-osint"
    
    # Try to find a Python executable that has the required dependencies
    python_executables = [
        sys.executable,  # Current Python
        "python",        # System Python
        "python3",       # Python 3
        str(Path(sys.executable).parent / "python.exe"),  # Same directory as current
    ]
    
    for python_exe in python_executables:
        try:
            # Test if this Python has rich
            result = subprocess.run([
                python_exe, "-c", "import rich; print('OK')"
            ], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                print(f"Using Python: {python_exe}")
                # Run blackbird with this Python
                cmd = [python_exe, str(blackbird_dir / "blackbird.py")] + args
                return subprocess.run(cmd, cwd=str(blackbird_dir))
        except Exception:
            continue
    
    # If no Python with rich found, try to install it
    print("Installing rich module...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "rich"], check=True)
        # Try again with current Python
        cmd = [sys.executable, str(blackbird_dir / "blackbird.py")] + args
        return subprocess.run(cmd, cwd=str(blackbird_dir))
    except Exception as e:
        print(f"Failed to install rich: {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run_blackbird.py [blackbird_args...]")
        sys.exit(1)
    
    result = run_blackbird(sys.argv[1:])
    if result is None:
        sys.exit(1)
    sys.exit(result.returncode)
