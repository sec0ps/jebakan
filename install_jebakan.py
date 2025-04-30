# =============================================================================
# Jebakan - Python-Based Honeypot System
# =============================================================================
#
# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2025 Keith Pachulski. All rights reserved.
#
# License: This software is licensed under the MIT License.
#          You are free to use, modify, and distribute this software
#          in accordance with the terms of the license.
#
# Purpose: This module is part of the Jebakan honeypot system, designed to
#          create convincing decoy systems to attract and detect attackers.
#          It provides service emulation, attack logging, and threat intelligence
#          gathering capabilities for cybersecurity research and network protection.
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind,
#             express or implied, including but not limited to the warranties
#             of merchantability, fitness for a particular purpose, and non-infringement.
#             In no event shall the authors or copyright holders be liable for any claim,
#             damages, or other liability, whether in an action of contract, tort, or otherwise,
#             arising from, out of, or in connection with the software or the use or other dealings
#             in the software.
#
# =============================================================================
#!/usr/bin/env python3
"""
Installer script for the Jebakan Honeypot System

This script:
1. Installs all required Python dependencies
2. Creates a dedicated jebakan user and group
3. Creates the /opt/jebakan directory
4. Moves all program files to /opt/jebakan
"""

import os
import sys
import shutil
import subprocess
import pwd
import grp
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('jebakan-installer')

# Import required modules
import os
import sys
import shutil
import subprocess
import pwd
import grp
import logging
from pathlib import Path

# Installation directory
INSTALL_DIR = '/opt/jebakan'
USER_NAME = 'jebakan'
GROUP_NAME = 'jebakan'

def install_jebakan():
    """Install Jebakan Honeypot"""
    logger.info("Starting Jebakan installation...")
    
    # Install dependencies
    install_dependencies()
    
    # Create user and group
    create_user_and_group()
    
    # Set up installation directory
    setup_installation_directory()
    
    # Copy program files
    copy_program_files()
    
    # Create log directory
    create_log_directory()
    
    # Create systemd service
    create_systemd_service()
    
    logger.info("Installation completed successfully")
    print("\nJebakan Honeypot has been installed to /opt/jebakan")
    print("To start the service, run: sudo systemctl start jebakan")
    print("To enable at boot: sudo systemctl enable jebakan")

def check_root():
    """Check if script is running with root privileges"""
    if os.geteuid() != 0:
        logger.error("This script must be run as root")
        sys.exit(1)
    logger.info("Running with root privileges")

def install_dependencies():
    """Install required Python dependencies from requirements.txt"""
    logger.info("Installing Python dependencies from requirements.txt...")
    
    # Get current directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    requirements_file = os.path.join(current_dir, "requirements.txt")
    
    # Check if requirements.txt exists
    if not os.path.isfile(requirements_file):
        logger.error("requirements.txt file not found in the current directory")
        logger.error("Please create a requirements.txt file with your dependencies")
        sys.exit(1)
    
    try:
        # Make sure pip is up to date
        logger.info("Upgrading pip...")
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], 
                       check=True)
        
        # Install dependencies from requirements.txt
        logger.info(f"Installing dependencies from {requirements_file}...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", requirements_file], 
                      check=True)
            
        logger.info("All dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install dependencies: {e}")
        sys.exit(1)

def create_user_and_group():
    """Create the jebakan user and group if they don't exist"""
    logger.info(f"Creating {USER_NAME} user and group...")
    
    # Check if group exists
    try:
        grp.getgrnam(GROUP_NAME)
        logger.info(f"Group {GROUP_NAME} already exists")
    except KeyError:
        # Create group
        subprocess.run(["groupadd", GROUP_NAME], check=True)
        logger.info(f"Group {GROUP_NAME} created")
    
    # Check if user exists
    try:
        pwd.getpwnam(USER_NAME)
        logger.info(f"User {USER_NAME} already exists")
    except KeyError:
        # Create user with home directory at /opt/jebakan
        subprocess.run(["useradd", 
                       "-r",                      # System account
                       "-g", GROUP_NAME,          # Primary group
                       "-d", "/opt/jebakan",      # Home directory
                       "-s", "/bin/false",        # No login shell
                       "-c", "Honeypot Service",  # Comment
                       USER_NAME], check=True)
        logger.info(f"User {USER_NAME} created with home directory at /opt/jebakan")

def setup_installation_directory():
    """Create the installation directory with proper permissions"""
    logger.info(f"Setting up installation directory at {INSTALL_DIR}")
    
    # Create directory if it doesn't exist
    os.makedirs(INSTALL_DIR, exist_ok=True)
    logger.info(f"Created {INSTALL_DIR} directory")
    
    # Get user and group IDs
    uid = pwd.getpwnam(USER_NAME).pw_uid
    gid = grp.getgrnam(GROUP_NAME).gr_gid
    
    # Change ownership
    os.chown(INSTALL_DIR, uid, gid)
    logger.info(f"Changed ownership of {INSTALL_DIR} to {USER_NAME}:{GROUP_NAME}")
    
    # Set permissions (0750 = rwxr-x---)
    os.chmod(INSTALL_DIR, 0o750)
    logger.info(f"Set permissions on {INSTALL_DIR}")

def copy_program_files():
    """Copy program files from current directory to installation directory"""
    logger.info("Copying program files...")
    
    # Get current directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Files to ignore during copy
    ignore_patterns = [
        '__pycache__', 
        '*.pyc', 
        '*.pyo', 
        '*.log',
        'venv',
        'env',
#        '.git',
        '.idea',
        '.vscode'
    ]
    
    # Helper function for ignoring files
    def ignore_func(dir, files):
        return [f for f in files for pattern in ignore_patterns 
                if f == pattern or (pattern.startswith('*') and f.endswith(pattern[1:]))]
    
    # Copy files
    for item in os.listdir(current_dir):
        src = os.path.join(current_dir, item)
        dst = os.path.join(INSTALL_DIR, item)
        
        if os.path.isdir(src):
            shutil.copytree(src, dst, ignore=ignore_func, dirs_exist_ok=True)
            logger.info(f"Copied directory {item}")
        elif os.path.isfile(src) and not any(src.endswith(ext) for ext in ['.pyc', '.pyo', '.log']):
            shutil.copy2(src, dst)
            logger.info(f"Copied file {item}")
    
    # Get user and group IDs
    uid = pwd.getpwnam(USER_NAME).pw_uid
    gid = grp.getgrnam(GROUP_NAME).gr_gid
    
    # Change ownership of all copied files
    for root, dirs, files in os.walk(INSTALL_DIR):
        for d in dirs:
            os.chown(os.path.join(root, d), uid, gid)
        for f in files:
            os.chown(os.path.join(root, f), uid, gid)
    
    logger.info("File permissions updated")

def create_log_directory():
    """Create log directory with proper permissions"""
    log_dir = os.path.join(INSTALL_DIR, 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    # Get user and group IDs
    uid = pwd.getpwnam(USER_NAME).pw_uid
    gid = grp.getgrnam(GROUP_NAME).gr_gid
    
    # Change ownership
    os.chown(log_dir, uid, gid)
    
    # Set permissions (0755 = rwxr-xr-x)
    os.chmod(log_dir, 0o755)
    logger.info("Created and configured logs directory")

def uninstall_jebakan():
    """Uninstall Jebakan Honeypot"""
    logger.info("Starting Jebakan uninstallation...")
    
    # Confirm uninstallation
    confirm = input("Are you sure you want to uninstall Jebakan? This will remove all files and data. (y/N): ").strip().lower()
    if confirm != 'y':
        logger.info("Uninstallation cancelled")
        print("Uninstallation cancelled.")
        return
    
    # Stop the service if it's running
    logger.info("Stopping Jebakan service...")
    try:
        subprocess.run(["systemctl", "stop", "jebakan"], check=False)
        logger.info("Jebakan service stopped")
    except Exception as e:
        logger.warning(f"Error stopping service: {e}")
    
    # Disable the service
    logger.info("Disabling Jebakan service...")
    try:
        subprocess.run(["systemctl", "disable", "jebakan"], check=False)
        logger.info("Jebakan service disabled")
    except Exception as e:
        logger.warning(f"Error disabling service: {e}")
    
    # Remove systemd service file
    service_path = "/etc/systemd/system/jebakan.service"
    if os.path.exists(service_path):
        os.remove(service_path)
        logger.info("Removed systemd service file")
    
    # Reload systemd
    try:
        subprocess.run(["systemctl", "daemon-reload"], check=True)
    except Exception as e:
        logger.warning(f"Error reloading systemd: {e}")
    
    # Remove installation directory
    if os.path.exists(INSTALL_DIR):
        try:
            shutil.rmtree(INSTALL_DIR)
            logger.info(f"Removed {INSTALL_DIR} directory")
        except Exception as e:
            logger.error(f"Error removing installation directory: {e}")
    
    # Remove user and group
    try:
        subprocess.run(["userdel", USER_NAME], check=False)
        logger.info(f"Removed user {USER_NAME}")
    except Exception as e:
        logger.warning(f"Error removing user: {e}")
    
    try:
        subprocess.run(["groupdel", GROUP_NAME], check=False)
        logger.info(f"Removed group {GROUP_NAME}")
    except Exception as e:
        logger.warning(f"Error removing group: {e}")
    
    logger.info("Uninstallation completed")
    print("\nJebakan Honeypot has been uninstalled from your system.")

def create_systemd_service():
    """Create a systemd service file for the honeypot"""
    service_content = """[Unit]
Description=Jebakan Honeypot Service
After=network.target

[Service]
Type=simple
User=jebakan
Group=jebakan
WorkingDirectory=/opt/jebakan
ExecStart=/usr/bin/python3 /opt/jebakan/jebakan.py -d
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
"""
    
    service_path = "/etc/systemd/system/jebakan.service"
    with open(service_path, 'w') as f:
        f.write(service_content)
    
    os.chmod(service_path, 0o644)
    logger.info("Created systemd service file")
    
    # Reload systemd
    try:
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        logger.info("Reloaded systemd daemon")
    except subprocess.CalledProcessError as e:
        logger.warning(f"Failed to reload systemd: {e}")

def main():
    """Main installation function"""
    banner = """
    ===============================================================
                             JEBAKAN INSTALLER
                 Modular Python Honeypot System for 
                       Cybersecurity Research
    ===============================================================
    """
    print(banner)
    
    # Check if running as root
    check_root()
    
    # Prompt for action
    print("\nPlease select an option:")
    print("1. Install Jebakan Honeypot")
    print("2. Uninstall Jebakan Honeypot")
    print("Q. Quit")
    
    choice = input("\nEnter your choice (1/2/Q): ").strip().lower()
    
    if choice == '1':
        install_jebakan()
    elif choice == '2':
        uninstall_jebakan()
    elif choice in ['q', 'quit', 'exit']:
        print("Exiting installer.")
        sys.exit(0)
    else:
        print("Invalid option. Exiting.")
        sys.exit(1)

if __name__ == "__main__":
    main()
