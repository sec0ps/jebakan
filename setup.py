#!/usr/bin/env python3
"""
Setup script for the Python Honeypot System
This script helps set up the required directory structure and dependencies.
"""

import os
import sys
import subprocess
import argparse
import shutil
from pathlib import Path

# Required Python packages
REQUIRED_PACKAGES = [
    "colorama",        # For terminal colors
    "matplotlib",      # For data visualization
    "requests",        # For webhook alerting
    "paramiko",        # For SSH service
]

def check_python_version():
    """Check if Python version is 3.6+"""
    if sys.version_info < (3, 6):
        print("Error: Python 3.6 or higher is required")
        sys.exit(1)

def create_directory_structure():
    """Create the necessary directory structure"""
    directories = [
        "config",
        "logs",
        "data",
        "data/http",
        "data/reports",
        "data/reports/visualizations",
        "services",
        "utils",
    ]

    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"Created directory: {directory}")

def install_dependencies():
    """Install required Python packages"""
    print("\nInstalling required packages...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
        for package in REQUIRED_PACKAGES:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print("All dependencies installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error installing dependencies: {e}")
        return False
    return True

def create_service_init():
    """Create __init__.py for the services package"""
    init_path = Path("services/__init__.py")
    if not init_path.exists():
        with open(init_path, "w") as f:
            f.write('"""Service modules for the honeypot system"""\n')
        print(f"Created {init_path}")

def create_utils_init():
    """Create __init__.py for the utils package"""
    init_path = Path("utils/__init__.py")
    if not init_path.exists():
        with open(init_path, "w") as f:
            f.write('"""Utility modules for the honeypot system"""\n')
        print(f"Created {init_path}")

def main():
    """Main setup function"""
    parser = argparse.ArgumentParser(description="Setup script for Python Honeypot System")
    parser.add_argument("--no-deps", action="store_true", help="Skip installing dependencies")
    args = parser.parse_args()

    print("Setting up Python Honeypot System...")

    # Check Python version
    check_python_version()

    # Create directory structure
    create_directory_structure()

    # Create package __init__.py files
    create_service_init()
    create_utils_init()

    # Install dependencies (unless --no-deps flag is used)
    if not args.no_deps:
        if not install_dependencies():
            print("Warning: Some dependencies could not be installed.")
    else:
        print("Skipping dependency installation as requested.")

    print("\nSetup completed successfully!")
    print("\nTo run the honeypot, use: python honeypot.py")

if __name__ == "__main__":
    main()
