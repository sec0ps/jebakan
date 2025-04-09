#!/usr/bin/env python3
"""
Honeypot - A modular Python honeypot system for cybersecurity research
"""

import socket
import threading
import logging
import datetime
import json
import os
import time
import argparse
import signal
import sys
from typing import Dict, List, Any, Optional

# Import service modules
from services.ssh_service import SSHService
from services.http_service import HTTPService
from services.ftp_service import FTPService
from services.telnet_service import TelnetService

# Import utilities
from utils.config_manager import load_config, save_config
from utils.analytics import AnalyticsEngine
from utils.alert_manager import AlertManager

# Global variables
running = True
active_services = []
logger = None

def setup_logging(config):
    """Set up logging based on configuration"""
    if not os.path.exists(config["logging"]["dir"]):
        os.makedirs(config["logging"]["dir"])
    
    logging.basicConfig(
        filename=f"{config['logging']['dir']}/honeypot_{datetime.datetime.now().strftime('%Y%m%d')}.log",
        level=getattr(logging, config["logging"]["level"]),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Add console handler if enabled
    if config["logging"]["console"]:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, config["logging"]["level"]))
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        logging.getLogger().addHandler(console_handler)
    
    return logging.getLogger("honeypot")

def signal_handler(sig, frame):
    """Handle interrupt signals gracefully"""
    global running
    print("\nShutting down honeypot services...")
    running = False
    sys.exit(0)

def start_services(config):
    """Start all enabled services based on configuration"""
    global active_services
    
    # Start SSH service if enabled
    if config["services"]["ssh"]["enabled"]:
        try:
            ssh_service = SSHService(
                host=config["network"]["bind_ip"], 
                port=config["services"]["ssh"]["port"],
                config=config
            )
            ssh_thread = threading.Thread(target=ssh_service.start)
            ssh_thread.daemon = True
            ssh_thread.start()
            active_services.append(("SSH", ssh_service, ssh_thread))
            logger.info(f"SSH honeypot started on port {config['services']['ssh']['port']}")
        except Exception as e:
            logger.error(f"Failed to start SSH service: {e}")
    
    # Start HTTP service if enabled
    if config["services"]["http"]["enabled"]:
        try:
            http_service = HTTPService(
                host=config["network"]["bind_ip"],
                port=config["services"]["http"]["port"],
                config=config
            )
            http_thread = threading.Thread(target=http_service.start)
            http_thread.daemon = True
            http_thread.start()
            active_services.append(("HTTP", http_service, http_thread))
            logger.info(f"HTTP honeypot started on port {config['services']['http']['port']}")
        except Exception as e:
            logger.error(f"Failed to start HTTP service: {e}")

    # Start FTP service if enabled
    if config["services"]["ftp"]["enabled"]:
        try:
            ftp_service = FTPService(
                host=config["network"]["bind_ip"],
                port=config["services"]["ftp"]["port"],
                config=config
            )
            ftp_thread = threading.Thread(target=ftp_service.start)
            ftp_thread.daemon = True
            ftp_thread.start()
            active_services.append(("FTP", ftp_service, ftp_thread))
            logger.info(f"FTP honeypot started on port {config['services']['ftp']['port']}")
        except Exception as e:
            logger.error(f"Failed to start FTP service: {e}")
            
    # Start Telnet service if enabled
    if config["services"]["telnet"]["enabled"]:
        try:
            telnet_service = TelnetService(
                host=config["network"]["bind_ip"],
                port=config["services"]["telnet"]["port"],
                config=config
            )
            telnet_thread = threading.Thread(target=telnet_service.start)
            telnet_thread.daemon = True
            telnet_thread.start()
            active_services.append(("Telnet", telnet_service, telnet_thread))
            logger.info(f"Telnet honeypot started on port {config['services']['telnet']['port']}")
        except Exception as e:
            logger.error(f"Failed to start Telnet service: {e}")

def main():
    global logger, running
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Python Honeypot System")
    parser.add_argument("-c", "--config", help="Path to configuration file", default="config/honeypot.json")
    parser.add_argument("-v", "--verbose", help="Increase output verbosity", action="store_true")
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.config)
    
    # Override config settings from command line if specified
    if args.verbose:
        config["logging"]["level"] = "DEBUG"
        config["logging"]["console"] = True
    
    # Set up logging
    logger = setup_logging(config)
    logger.info("Starting honeypot system...")
    
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Initialize alert manager
    alert_manager = AlertManager(config)
    
    # Initialize analytics engine
    analytics_engine = AnalyticsEngine(config)
    
    # Start services
    start_services(config)
    
    # Start analytics engine if enabled
    if config["analytics"]["enabled"]:
        analytics_thread = threading.Thread(target=analytics_engine.start)
        analytics_thread.daemon = True
        analytics_thread.start()
        logger.info("Analytics engine started")
    
    # Start dashboard server if enabled
    if config["dashboard"]["enabled"]:
        from utils.dashboard import DashboardServer
        dashboard = DashboardServer(config, analytics_engine)
        dashboard_thread = threading.Thread(target=dashboard.start)
        dashboard_thread.daemon = True
        dashboard_thread.start()
        logger.info(f"Dashboard server started on port {config['dashboard']['port']}")
    
    logger.info(f"Honeypot started with {len(active_services)} service(s)")
    
    # Keep the main thread alive
    try:
        while running:
            time.sleep(1)
    except KeyboardInterrupt:
        running = False
        logger.info("Shutting down honeypot...")
    
if __name__ == "__main__":
    main()
