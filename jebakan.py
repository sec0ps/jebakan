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
import re
import geoip2.database
from typing import Dict, Any, Tuple, Optional
import colorama
from colorama import Fore, Style, init
from utils.config_manager import load_config, save_config

base_dir = os.path.dirname(os.path.abspath(__file__))

pid_dir = os.path.join(base_dir, "config")
if not os.path.exists(pid_dir):
    os.makedirs(pid_dir)

PID_FILE = os.path.join(pid_dir, "jebakan.pid")

# Initialize colorama for colored terminal output
init(autoreset=True)

running = True
active_services = []
logger = None
config_path = os.path.join(base_dir, "honeypot.json")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

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
    global running, active_services, logger
    
    print("\nShutting down honeypot services...")
    running = False
    
    # Clean up services before exit
    cleanup_services(active_services)

    if os.path.exists(PID_FILE):
        os.remove(PID_FILE)

    sys.exit(0)

def cleanup_services(active_services):
    """
    Clean up all running services and release ports
    
    Args:
        active_services: List of tuples containing (service_name, service_object, thread)
    """
    global logger
    
    print(f"{Fore.YELLOW}Cleaning up services and releasing ports...{Style.RESET_ALL}")
    
    for service_name, service_obj, thread in active_services:
        try:
            # Stop the service if it has a stop method
            if hasattr(service_obj, 'stop'):
                service_obj.stop()
                logger.info(f"Stopped {service_name} service")
            
            # Ensure socket is closed
            if hasattr(service_obj, 'sock'):
                try:
                    service_obj.sock.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                try:
                    service_obj.sock.close()
                    logger.info(f"Closed socket for {service_name}")
                except:
                    pass
            
            # Set running flag to False if exists
            if hasattr(service_obj, 'running'):
                service_obj.running = False
        except Exception as e:
            logger.error(f"Error cleaning up {service_name}: {e}")
    
    # Give threads a moment to clean up
    time.sleep(1)
    
    # Force kill any remaining threads
    for service_name, service_obj, thread in active_services:
        if thread.is_alive():
            logger.warning(f"Force stopping thread for {service_name}")
            
    print(f"{Fore.GREEN}Services cleaned up successfully{Style.RESET_ALL}")

def check_port_available(host, port):
    """Check if a port is available on the host"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            s.close()
            return True
        except OSError:
            return False

class UnifiedLogger:
    """Unified logger for all honeypot activities with SIEM integration and geolocation"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("unified_logger")
        self.log_dir = config.get("logging", {}).get("dir", "logs/")
        self.unified_log_file = os.path.join(self.log_dir, "honeypot_attacks.json")
        self.siem_config = config.get("siem-server", None)
        self.geoip_db_path = config.get("geoip_db_path", "GeoLite2-City.mmdb")
        self.siem_position_file = os.path.join(self.log_dir, "siem_last_position.txt")
        self.siem_queue_file = os.path.join(self.log_dir, "siem_queue.json")
        
        # SIEM connection state
        self.siem_connected = False
        self.last_connection_attempt = 0
        self.connection_retry_interval = 30  # seconds
        self.consecutive_failures = 0
        self.max_consecutive_failures = 3  # After this many failures, we'll mark as disconnected
        
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        
        if not os.path.exists(self.unified_log_file):
            with open(self.unified_log_file, 'w') as f:
                f.write("")
                
        # Initialize queue file if it doesn't exist
        if not os.path.exists(self.siem_queue_file):
            with open(self.siem_queue_file, 'w') as f:
                f.write("[]")
        
        # Load GeoIP database if available
        self.geoip_reader = None
        if os.path.exists(self.geoip_db_path):
            try:
                self.geoip_reader = geoip2.database.Reader(self.geoip_db_path)
                self.logger.info("GeoIP database loaded successfully.")
            except Exception as e:
                self.logger.error(f"Failed to load GeoIP database: {e}")

        if self.siem_config:
            # Start with a connection test
            self._check_siem_connection()
            
            # Start the sender thread
            self.siem_sender = threading.Thread(target=self._siem_sender_thread, daemon=True)
            self.siem_sender.start()
            self.logger.info(f"SIEM logging enabled to {self.siem_config['ip_address']}:{self.siem_config['port']}")
    
    def log_attack(self, service: str, attacker_ip: str, attacker_port: int, 
                   command: str, additional_data: Dict[str, Any] = None) -> None:
        """Log an attack to the unified log file"""
        log_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "service": service,
            "attacker_ip": attacker_ip,
            "attacker_port": attacker_port,
            "command": command
        }

        # Add geolocation enrichment
        if self.geoip_reader:
            try:
                response = self.geoip_reader.city(attacker_ip)
                geo_info = {
                    "country": response.country.name,
                    "city": response.city.name,
                    "asn": response.traits.autonomous_system_organization,
                    "isp": response.traits.isp,
                }
                log_entry["geolocation"] = {k: v for k, v in geo_info.items() if v}
            except Exception:
                log_entry["geolocation"] = {}

        # Add additional data if provided
        if additional_data:
            log_entry["additional_data"] = additional_data

        # Write to unified log file
        with open(self.unified_log_file, 'a') as f:
            f.write(json.dumps(log_entry) + "\n")
    
    def _load_last_position(self) -> int:
        """Load the last position sent to SIEM from file"""
        try:
            if os.path.exists(self.siem_position_file):
                with open(self.siem_position_file, 'r') as f:
                    content = f.read().strip()
                    if content:
                        return int(content)
            return 0
        except Exception as e:
            self.logger.error(f"Error loading last SIEM position: {e}")
            return 0
    
    def _save_last_position(self, position: int) -> None:
        """Save the last position sent to SIEM to file"""
        try:
            with open(self.siem_position_file, 'w') as f:
                f.write(str(position))
        except Exception as e:
            self.logger.error(f"Error saving last SIEM position: {e}")
    
    def _load_queue(self) -> list:
        """Load the queue of logs waiting to be sent to SIEM"""
        try:
            if os.path.exists(self.siem_queue_file):
                with open(self.siem_queue_file, 'r') as f:
                    content = f.read().strip()
                    if content:
                        return json.loads(content)
            return []
        except Exception as e:
            self.logger.error(f"Error loading SIEM queue: {e}")
            return []
    
    def _save_queue(self, queue: list) -> None:
        """Save the queue of logs waiting to be sent to SIEM"""
        try:
            with open(self.siem_queue_file, 'w') as f:
                f.write(json.dumps(queue))
        except Exception as e:
            self.logger.error(f"Error saving SIEM queue: {e}")
    
    def _add_to_queue(self, log_entry: str) -> None:
        """Add a log entry to the queue for later sending"""
        try:
            queue = self._load_queue()
            queue.append(log_entry)
            self._save_queue(queue)
            self.logger.debug(f"Added log to SIEM queue. Queue size: {len(queue)}")
        except Exception as e:
            self.logger.error(f"Error adding to SIEM queue: {e}")
    
    def _process_queue(self) -> None:
        """Process all entries in the queue and try to send them to SIEM"""
        if not self.siem_connected:
            return
            
        queue = self._load_queue()
        if not queue:
            return
            
        self.logger.info(f"Attempting to process SIEM queue with {len(queue)} entries")
        remaining_queue = []
        
        for log_entry in queue:
            send_success = self._send_to_siem(log_entry)
            if not send_success:
                # If send fails, keep this entry and all remaining ones in the queue
                remaining_queue.append(log_entry)
                remaining_queue.extend(queue[queue.index(log_entry) + 1:])
                break
                
        if len(remaining_queue) < len(queue):
            self.logger.info(f"Successfully sent {len(queue) - len(remaining_queue)} queued logs to SIEM")
        
        self._save_queue(remaining_queue)
    
    def _check_siem_connection(self) -> bool:
        """Test the connection to the SIEM server"""
        current_time = time.time()
        
        # Only try to reconnect every connection_retry_interval seconds
        if (not self.siem_connected and 
            current_time - self.last_connection_attempt < self.connection_retry_interval):
            return self.siem_connected
            
        self.last_connection_attempt = current_time
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((self.siem_config["ip_address"], int(self.siem_config["port"])))
                
                # If we get here, connection succeeded
                if not self.siem_connected:
                    self.logger.info(f"SIEM connection established to {self.siem_config['ip_address']}:{self.siem_config['port']}")
                
                self.siem_connected = True
                self.consecutive_failures = 0
                return True
                
        except Exception as e:
            self.consecutive_failures += 1
            
            if self.siem_connected:
                self.logger.warning(f"SIEM connection lost: {e}")
                
            if self.consecutive_failures >= self.max_consecutive_failures:
                if self.siem_connected:
                    self.logger.error(f"SIEM connection marked as down after {self.consecutive_failures} consecutive failures")
                self.siem_connected = False
            
            return False
    
    def _siem_sender_thread(self) -> None:
        """Thread that monitors the log file and sends new entries to SIEM"""
        last_sent_position = self._load_last_position()
        self.logger.info(f"Starting SIEM sender thread from position: {last_sent_position}")
        
        while True:
            try:
                # Check connection status first
                connection_status = self._check_siem_connection()
                
                # If connected, try to process any queued logs
                if connection_status:
                    self._process_queue()
                    
                # Process new logs from the main log file
                if os.path.exists(self.unified_log_file):
                    with open(self.unified_log_file, 'r') as f:
                        f.seek(last_sent_position)
                        new_lines = f.readlines()
                        
                        if new_lines:
                            current_position = last_sent_position
                            for line in new_lines:
                                if line.strip():
                                    line_position = current_position + len(line)
                                    
                                    # If connected, try to send directly
                                    if self.siem_connected:
                                        send_success = self._send_to_siem(line.strip())
                                        if send_success:
                                            last_sent_position = line_position
                                        else:
                                            # If send fails, add to queue and stop processing for now
                                            self._add_to_queue(line.strip())
                                            break
                                    else:
                                        # If disconnected, add to queue and continue to next line
                                        self._add_to_queue(line.strip())
                                        last_sent_position = line_position
                                
                                current_position += len(line)
                            
                            # Save our position
                            self._save_last_position(last_sent_position)
                
                # Sleep before next check
                # Use shorter sleep if we're connected, longer if not
                sleep_time = 5 if self.siem_connected else self.connection_retry_interval
                time.sleep(sleep_time)
                
            except Exception as e:
                self.logger.error(f"Error in SIEM sender thread: {e}")
                time.sleep(10)
    
    def _send_to_siem(self, log_entry: str) -> bool:
        """
        Send a log entry to the configured SIEM server
        
        Returns:
            bool: True if send was successful, False otherwise
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((self.siem_config["ip_address"], int(self.siem_config["port"])))
                sock.sendall((log_entry + "\n").encode('utf-8'))
                self.logger.debug(f"Sent log to SIEM: {log_entry}")
                return True
                
        except Exception as e:
            # Only log error if we think we're connected - prevents log flooding
            if self.siem_connected:
                self.logger.error(f"Failed to send log to SIEM: {e}")
                
            # Track connection state
            self.consecutive_failures += 1
            if self.consecutive_failures >= self.max_consecutive_failures:
                if self.siem_connected:
                    self.logger.warning(f"SIEM connection marked as down after {self.consecutive_failures} consecutive failures")
                self.siem_connected = False
                
            return False

def daemonize():
    """Daemonize the current process (Unix-like systems only)."""
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        print(f"Fork #1 failed: {e}", file=sys.stderr)
        sys.exit(1)

    os.chdir("/")
    os.setsid()
    os.umask(0)

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        print(f"Fork #2 failed: {e}", file=sys.stderr)
        sys.exit(1)

    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    with open('/dev/null', 'rb', 0) as dev_null:
        os.dup2(dev_null.fileno(), sys.stdin.fileno())
    with open('/dev/null', 'ab', 0) as dev_null:
        os.dup2(dev_null.fileno(), sys.stdout.fileno())
        os.dup2(dev_null.fileno(), sys.stderr.fileno())

    # Save PID to config directory
    with open(PID_FILE, 'w') as f:
        f.write(str(os.getpid()))

def stop_daemon():
    """Stop the running daemon process"""
    if not os.path.exists(PID_FILE):
        print("No running daemon found.")
        return

    try:
        with open(PID_FILE, 'r') as f:
            pid = int(f.read().strip())

        os.kill(pid, signal.SIGTERM)
        print(f"Sent SIGTERM to daemon (PID {pid}).")

    except ProcessLookupError:
        print(f"No process with PID {pid} found.")

    except Exception as e:
        print(f"Failed to stop daemon: {e}")

    finally:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)

def print_banner():
    """Print the honeypot banner"""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║  {Fore.YELLOW}    ██╗███████╗██████╗  █████╗ ██╗  ██╗ █████╗ ███╗   ██╗{Fore.CYAN}    ║
║  {Fore.YELLOW}    ██║██╔════╝██╔══██╗██╔══██╗██║ ██╔╝██╔══██╗████╗  ██║{Fore.CYAN}    ║
║  {Fore.YELLOW}    ██║█████╗  ██████╔╝███████║█████╔╝ ███████║██╔██╗ ██║{Fore.CYAN}    ║
║  {Fore.YELLOW}██╗ ██║██╔══╝  ██╔══██╗██╔══██║██╔═██╗ ██╔══██║██║╚██╗██║{Fore.CYAN}    ║
║  {Fore.YELLOW}╚█████╔╝███████╗██████╔╝██║  ██║██║  ██╗██║  ██║██║ ╚████║{Fore.CYAN}    ║
║  {Fore.YELLOW} ╚════╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝{Fore.CYAN}    ║
║                                                           ║
║    {Fore.GREEN}A modular Python honeypot system for cybersecurity research{Fore.CYAN}    ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_service_menu(config):
    """Print the service selection menu"""
    print(f"\n{Fore.CYAN}=== Available Services ===")
    print(f"{Fore.YELLOW}Select services to enable (comma-separated list or 'all'):")

    # Default ports for services that might be missing from config
    default_ports = {
        "ssh": 2222,
        "http": 8080,
        "ftp": 2121,
        "telnet": 2323,
        "mysql": 3306,
        "mssql": 1433,
        "rdp": 3389,
        "vnc": 5900,
        "redis": 6379,
        "elasticsearch": 9200,
        "docker": 2375
    }

    services = []
    for service_name, default_port in default_ports.items():
        # Get port from config if it exists, otherwise use default
        port = config["services"].get(service_name, {}).get("port", default_port)
        services.append((service_name, port))

    for i, (service, port) in enumerate(services, 1):
        port_status = check_port_available(config["network"]["bind_ip"], port)
        if port_status:
            status = f"{Fore.GREEN}[Available]"
        else:
            status = f"{Fore.RED}[Port in use]"

        print(f"{i}. {service.upper()} (Port {port}) {status}")

    print(f"\n{Fore.YELLOW}Additional options:")
    print(f"{Fore.CYAN}S. {Fore.WHITE}Configure SIEM")
    print(f"{Fore.CYAN}Q. {Fore.WHITE}Quit\n")

def main():
    global logger, running

    # Handle 'help' manually BEFORE parsing arguments
    if len(sys.argv) > 1 and sys.argv[1].lower() == "help":
        print("\nUsage:")
        print("  python jebakan.py --help          Show this help message and exit")
        print("  python jebakan.py --config-siem    Configure SIEM integration")
        print("  python jebakan.py [options]        Start honeypot with selected options")
        sys.exit(0)

    parser = argparse.ArgumentParser(description="Python Honeypot System")
    parser.add_argument("-c", "--config", help="Path to configuration file", default="config/honeypot.json")
    parser.add_argument("-v", "--verbose", help="Increase output verbosity", action="store_true")
    parser.add_argument("-n", "--no-prompt", help="Start with default services (no interactive prompt)", action="store_true")
    parser.add_argument("--interaction", choices=["low", "medium", "high"],
                        help="Set global interaction level for all services")
    parser.add_argument("--services", help="Comma-separated list of services to enable or 'all'", type=str)
    parser.add_argument("--config-siem", action="store_true", help="Configure SIEM integration")
    args = parser.parse_args()

    print_banner()
    config = load_config(args.config)

    if args.verbose:
        config["logging"]["level"] = "DEBUG"
        config["logging"]["console"] = True

    # Apply global interaction level if specified
    if args.interaction:
        for service in config.get("services", {}):
            config["services"].setdefault(service, {})
            config["services"][service]["interaction_level"] = args.interaction

        default_ports = {
            "ssh": 2222, "http": 8080, "ftp": 2121, "telnet": 2323,
            "mysql": 3306, "mssql": 1433, "rdp": 3389, "vnc": 5900,
            "redis": 6379, "elasticsearch": 9200, "docker": 2375
        }
        for svc, port in default_ports.items():
            if svc not in config["services"]:
                config["services"][svc] = {
                    "enabled": False,
                    "port": port,
                    "interaction_level": args.interaction
                }

        config["global_interaction_level"] = args.interaction
        save_config(config, args.config)

    logger = setup_logging(config)
    logger.info("Starting honeypot system...")

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if args.no_prompt:
        services_to_enable = [s for s, scfg in config["services"].items() if scfg.get("enabled")]

    else:
        result = select_services(config, args)
        if result is None:
            print(f"{Fore.YELLOW}Exiting...")
            return
        services_to_enable = result

        print(f"[DEBUG] main(): Got services_to_enable: {services_to_enable}")

        save_config(config, args.config)

    started_services = start_services(config, services_to_enable, unified_logger)


def print_status(started_services):
    """Print the status of started services"""
    if not started_services:
        print(f"\n{Fore.RED}No services were started.")
        return

    print(f"\n{Fore.GREEN}=== Honeypot Status ===")
    print(f"{Fore.CYAN}The following services are running:")

    for service, port in started_services:
        print(f"  {Fore.GREEN}✓ {service} on port {port}")

    print(f"\n{Fore.YELLOW}Press Ctrl+C to stop the honeypot.")
    print(f"{Style.RESET_ALL}")


def select_services(config, args):
    """Prompt user to select services to enable"""
    from utils.config_manager import save_config

    if "global_interaction_level" not in config:
        config["global_interaction_level"] = args.interaction or "high"

    print_service_menu(config)

    service_map = [
        "ssh", "http", "ftp", "telnet", "mysql", "mssql",
        "rdp", "vnc", "redis", "elasticsearch", "docker"
    ]
    default_ports = {
        "ssh": 2222, "http": 8080, "ftp": 2121, "telnet": 2323,
        "mysql": 3306, "mssql": 1433, "rdp": 3389, "vnc": 5900,
        "redis": 6379, "elasticsearch": 9200, "docker": 2375
    }

    while True:
        try:
            raw = input(f"\n{Fore.GREEN}Enter your selection: {Style.RESET_ALL}")
            cleaned = raw.strip().lower()
            print(f"[DEBUG] Raw input: {repr(raw)}")

            if cleaned == 'q':
                return None

            if cleaned == 's':
                print(f"\n{Fore.CYAN}=== SIEM Configuration ==={Style.RESET_ALL}")
                ip_address = input("Enter SIEM server IP address: ").strip()
                port = input("Enter SIEM server port: ").strip()

                try:
                    socket.inet_aton(ip_address)
                    port = int(port)
                    if not (1 <= port <= 65535):
                        raise ValueError("Port must be between 1 and 65535")

                    if "services" not in config:
                        config["services"] = {}

                    config["services"]["siem"] = {
                        "enabled": True,
                        "ip_address": ip_address,
                        "port": port
                    }

                    save_config(config, args.config)
                    print(f"{Fore.GREEN}SIEM configuration saved successfully{Style.RESET_ALL}")

                except socket.error:
                    print(f"{Fore.RED}Invalid IP address format{Style.RESET_ALL}")
                except ValueError as e:
                    print(f"{Fore.RED}Invalid port: {e}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}Error updating configuration: {e}{Style.RESET_ALL}")

                continue

            if cleaned == 'all':
                cleaned = ','.join(str(i) for i in range(1, len(service_map) + 1))
                print(f"[DEBUG] Interpreting 'all' as: {cleaned}")

            cleaned = cleaned.replace(' ', '')
            selected_services = []

            for part in cleaned.split(','):
                if part.isdigit():
                    idx = int(part) - 1
                    if 0 <= idx < len(service_map):
                        selected_services.append(service_map[idx])
                elif part in service_map:
                    selected_services.append(part)

            print(f"[DEBUG] Selected services: {selected_services}")
            services_to_enable = []

            for svc in selected_services:
                config["services"].setdefault(svc, {
                    "port": default_ports[svc],
                    "enabled": True,
                    "interaction_level": config["global_interaction_level"]
                })
                config["services"][svc]["enabled"] = True
                config["services"][svc].setdefault("interaction_level", config["global_interaction_level"])
                services_to_enable.append(svc)

            if not services_to_enable:
                print(f"{Fore.RED}No valid services selected. Please try again.")
                continue

            save_config(config, args.config)
            logger.info(f"Saved configuration to {args.config}")
            return services_to_enable

        except Exception as e:
            print(f"{Fore.RED}Error: {e}. Please try again.")

def start_services(config, services_to_enable, unified_logger=None):
    """Start all enabled services based on configuration"""
    global active_services

    started_services = []

    # Print debugging information
    print(f"Attempting to start services: {services_to_enable}")

    try:
        if "ssh" in services_to_enable:
            try:
                # Check if port is available
                if check_port_available(config["network"]["bind_ip"], config["services"]["ssh"]["port"]):
                    from services.ssh_service import SSHService

                    print(f"Starting SSH service on {config['network']['bind_ip']}:{config['services']['ssh']['port']}")

                    ssh_service = SSHService(
                        host=config["network"]["bind_ip"],
                        port=config["services"]["ssh"]["port"],
                        config=config,
                        unified_logger=unified_logger
                    )
                    ssh_thread = threading.Thread(target=ssh_service.start)
                    ssh_thread.daemon = True
                    ssh_thread.start()
                    active_services.append(("SSH", ssh_service, ssh_thread))
                    started_services.append(("SSH", config["services"]["ssh"]["port"]))
                    print(f"SSH honeypot started on port {config['services']['ssh']['port']}")
                else:
                    print(f"Port {config['services']['ssh']['port']} is already in use, cannot start SSH service")
            except ImportError as e:
                print(f"Failed to import SSH service module: {e}")
            except Exception as e:
                print(f"Failed to start SSH service: {e}")
                import traceback
                traceback.print_exc()

        if "http" in services_to_enable:
            try:
                # Check if port is available
                if check_port_available(config["network"]["bind_ip"], config["services"]["http"]["port"]):
                    from services.http_service import HTTPService

                    print(f"Starting HTTP service on {config['network']['bind_ip']}:{config['services']['http']['port']}")

                    http_service = HTTPService(
                        host=config["network"]["bind_ip"],
                        port=config["services"]["http"]["port"],
                        config=config,
                        unified_logger=unified_logger
                    )
                    http_thread = threading.Thread(target=http_service.start)
                    http_thread.daemon = True
                    http_thread.start()
                    active_services.append(("HTTP", http_service, http_thread))
                    started_services.append(("HTTP", config["services"]["http"]["port"]))
                    print(f"HTTP honeypot started on port {config['services']['http']['port']}")
                else:
                    print(f"Port {config['services']['http']['port']} is already in use, cannot start HTTP service")
            except ImportError as e:
                print(f"Failed to import HTTP service module: {e}")
            except Exception as e:
                print(f"Failed to start HTTP service: {e}")
                import traceback
                traceback.print_exc()

        if "ftp" in services_to_enable:
            try:
                # Check if port is available
                if check_port_available(config["network"]["bind_ip"], config["services"]["ftp"]["port"]):
                    from services.ftp_service import FTPService

                    print(f"Starting FTP service on {config['network']['bind_ip']}:{config['services']['ftp']['port']}")

                    ftp_service = FTPService(
                        host=config["network"]["bind_ip"],
                        port=config["services"]["ftp"]["port"],
                        config=config,
                        unified_logger=unified_logger
                    )
                    ftp_thread = threading.Thread(target=ftp_service.start)
                    ftp_thread.daemon = True
                    ftp_thread.start()
                    active_services.append(("FTP", ftp_service, ftp_thread))
                    started_services.append(("FTP", config["services"]["ftp"]["port"]))
                    print(f"FTP honeypot started on port {config['services']['ftp']['port']}")
                else:
                    print(f"Port {config['services']['ftp']['port']} is already in use, cannot start FTP service")
            except ImportError as e:
                print(f"Failed to import FTP service module: {e}")
            except Exception as e:
                print(f"Failed to start FTP service: {e}")
                import traceback
                traceback.print_exc()

        if "telnet" in services_to_enable:
            try:
                # Check if port is available
                if check_port_available(config["network"]["bind_ip"], config["services"]["telnet"]["port"]):
                    from services.telnet_service import TelnetService

                    print(f"Starting Telnet service on {config['network']['bind_ip']}:{config['services']['telnet']['port']}")

                    telnet_service = TelnetService(
                        host=config["network"]["bind_ip"],
                        port=config["services"]["telnet"]["port"],
                        config=config,
                        unified_logger=unified_logger
                    )
                    telnet_thread = threading.Thread(target=telnet_service.start)
                    telnet_thread.daemon = True
                    telnet_thread.start()
                    active_services.append(("Telnet", telnet_service, telnet_thread))
                    started_services.append(("Telnet", config["services"]["telnet"]["port"]))
                    print(f"Telnet honeypot started on port {config['services']['telnet']['port']}")
                else:
                    print(f"Port {config['services']['telnet']['port']} is already in use, cannot start Telnet service")
            except ImportError as e:
                print(f"Failed to import Telnet service module: {e}")
            except Exception as e:
                print(f"Failed to start Telnet service: {e}")
                import traceback
                traceback.print_exc()

        if "mysql" in services_to_enable:
            try:
                # Check if port is available
                if check_port_available(config["network"]["bind_ip"], config["services"]["mysql"]["port"]):
                    from services.mysql_service import MySQLService

                    print(f"Starting MySQL service on {config['network']['bind_ip']}:{config['services']['mysql']['port']}")

                    mysql_service = MySQLService(
                        host=config["network"]["bind_ip"],
                        port=config["services"]["mysql"]["port"],
                        config=config,
                        unified_logger=unified_logger
                    )
                    mysql_thread = threading.Thread(target=mysql_service.start)
                    mysql_thread.daemon = True
                    mysql_thread.start()
                    active_services.append(("MySQL", mysql_service, mysql_thread))
                    started_services.append(("MySQL", config["services"]["mysql"]["port"]))
                    print(f"MySQL honeypot started on port {config['services']['mysql']['port']}")
                else:
                    print(f"Port {config['services']['mysql']['port']} is already in use, cannot start MySQL service")
            except ImportError as e:
                print(f"Failed to import MySQL service module: {e}")
            except Exception as e:
                print(f"Failed to start MySQL service: {e}")
                import traceback
                traceback.print_exc()

        if "mssql" in services_to_enable:
            try:
                # Check if port is available
                if check_port_available(config["network"]["bind_ip"], config["services"]["mssql"]["port"]):
                    from services.mssql_service import MSSQLService

                    print(f"Starting MSSQL service on {config['network']['bind_ip']}:{config['services']['mssql']['port']}")

                    mssql_service = MSSQLService(
                        host=config["network"]["bind_ip"],
                        port=config["services"]["mssql"]["port"],
                        config=config,
                        unified_logger=unified_logger
                    )
                    mssql_thread = threading.Thread(target=mssql_service.start)
                    mssql_thread.daemon = True
                    mssql_thread.start()
                    active_services.append(("MSSQL", mssql_service, mssql_thread))
                    started_services.append(("MSSQL", config["services"]["mssql"]["port"]))
                    print(f"MSSQL honeypot started on port {config['services']['mssql']['port']}")
                else:
                    print(f"Port {config['services']['mssql']['port']} is already in use, cannot start MSSQL service")
            except ImportError as e:
                print(f"Failed to import MSSQL service module: {e}")
            except Exception as e:
                print(f"Failed to start MSSQL service: {e}")
                import traceback
                traceback.print_exc()

        if "rdp" in services_to_enable:
            try:
                # Check if port is available
                if check_port_available(config["network"]["bind_ip"], config["services"]["rdp"]["port"]):
                    from services.rdp_service import RDPService

                    print(f"Starting RDP service on {config['network']['bind_ip']}:{config['services']['rdp']['port']}")

                    rdp_service = RDPService(
                        host=config["network"]["bind_ip"],
                        port=config["services"]["rdp"]["port"],
                        config=config,
                        unified_logger=unified_logger
                    )
                    rdp_thread = threading.Thread(target=rdp_service.start)
                    rdp_thread.daemon = True
                    rdp_thread.start()
                    active_services.append(("RDP", rdp_service, rdp_thread))
                    started_services.append(("RDP", config["services"]["rdp"]["port"]))
                    print(f"RDP honeypot started on port {config['services']['rdp']['port']}")
                else:
                    print(f"Port {config['services']['rdp']['port']} is already in use, cannot start RDP service")
            except ImportError as e:
                print(f"Failed to import RDP service module: {e}")
            except Exception as e:
                print(f"Failed to start RDP service: {e}")
                import traceback
                traceback.print_exc()

        if "vnc" in services_to_enable:
            try:
                # Check if port is available
                if check_port_available(config["network"]["bind_ip"], config["services"]["vnc"]["port"]):
                    from services.vnc_service import VNCService

                    print(f"Starting VNC service on {config['network']['bind_ip']}:{config['services']['vnc']['port']}")

                    vnc_service = VNCService(
                        host=config["network"]["bind_ip"],
                        port=config["services"]["vnc"]["port"],
                        config=config,
                        unified_logger=unified_logger
                    )
                    vnc_thread = threading.Thread(target=vnc_service.start)
                    vnc_thread.daemon = True
                    vnc_thread.start()
                    active_services.append(("VNC", vnc_service, vnc_thread))
                    started_services.append(("VNC", config["services"]["vnc"]["port"]))
                    print(f"VNC honeypot started on port {config['services']['vnc']['port']}")
                else:
                    print(f"Port {config['services']['vnc']['port']} is already in use, cannot start VNC service")
            except ImportError as e:
                print(f"Failed to import VNC service module: {e}")
            except Exception as e:
                print(f"Failed to start VNC service: {e}")
                import traceback
                traceback.print_exc()

        if "redis" in services_to_enable:
            try:
                # Check if port is available
                if check_port_available(config["network"]["bind_ip"], config["services"]["redis"]["port"]):
                    from services.redis_service import RedisService

                    print(f"Starting Redis service on {config['network']['bind_ip']}:{config['services']['redis']['port']}")

                    redis_service = RedisService(
                        host=config["network"]["bind_ip"],
                        port=config["services"]["redis"]["port"],
                        config=config,
                        unified_logger=unified_logger
                    )
                    redis_thread = threading.Thread(target=redis_service.start)
                    redis_thread.daemon = True
                    redis_thread.start()
                    active_services.append(("Redis", redis_service, redis_thread))
                    started_services.append(("Redis", config["services"]["redis"]["port"]))
                    print(f"Redis honeypot started on port {config['services']['redis']['port']}")
                else:
                    print(f"Port {config['services']['redis']['port']} is already in use, cannot start Redis service")
            except ImportError as e:
                print(f"Failed to import Redis service module: {e}")
            except Exception as e:
                print(f"Failed to start Redis service: {e}")
                import traceback
                traceback.print_exc()

        if "elasticsearch" in services_to_enable:
            try:
                # Check if port is available
                if check_port_available(config["network"]["bind_ip"], config["services"]["elasticsearch"]["port"]):
                    from services.elasticsearch_service import ElasticsearchService

                    print(f"Starting Elasticsearch service on {config['network']['bind_ip']}:{config['services']['elasticsearch']['port']}")

                    elasticsearch_service = ElasticsearchService(
                        host=config["network"]["bind_ip"],
                        port=config["services"]["elasticsearch"]["port"],
                        config=config,
                        unified_logger=unified_logger
                    )
                    elasticsearch_thread = threading.Thread(target=elasticsearch_service.start)
                    elasticsearch_thread.daemon = True
                    elasticsearch_thread.start()
                    active_services.append(("Elasticsearch", elasticsearch_service, elasticsearch_thread))
                    started_services.append(("Elasticsearch", config["services"]["elasticsearch"]["port"]))
                    print(f"Elasticsearch honeypot started on port {config['services']['elasticsearch']['port']}")
                else:
                    print(f"Port {config['services']['elasticsearch']['port']} is already in use, cannot start Elasticsearch service")
            except ImportError as e:
                print(f"Failed to import Elasticsearch service module: {e}")
            except Exception as e:
                print(f"Failed to start Elasticsearch service: {e}")
                import traceback
                traceback.print_exc()

        if "docker" in services_to_enable:
            try:
                # Check if port is available
                if check_port_available(config["network"]["bind_ip"], config["services"]["docker"]["port"]):
                    from services.docker_service import DockerService

                    print(f"Starting Docker service on {config['network']['bind_ip']}:{config['services']['docker']['port']}")

                    docker_service = DockerService(
                        host=config["network"]["bind_ip"],
                        port=config["services"]["docker"]["port"],
                        config=config,
                        unified_logger=unified_logger
                    )
                    docker_thread = threading.Thread(target=docker_service.start)
                    docker_thread.daemon = True
                    docker_thread.start()
                    active_services.append(("Docker", docker_service, docker_thread))
                    started_services.append(("Docker", config["services"]["docker"]["port"]))
                    print(f"Docker API honeypot started on port {config['services']['docker']['port']}")
                else:
                    print(f"Port {config['services']['docker']['port']} is already in use, cannot start Docker service")
            except ImportError as e:
                print(f"Failed to import Docker service module: {e}")
            except Exception as e:
                print(f"Failed to start Docker service: {e}")
                import traceback
                traceback.print_exc()

    except Exception as e:
        print(f"Error starting services: {e}")
        import traceback
        traceback.print_exc()

    return started_services

def check_port_available(host, port):
    """Check if a port is available on the host"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            s.close()
            return True
        except OSError:
            return False

def print_status(started_services, dashboard_port=None, analytics_enabled=False):
    """Print the status of started services"""
    if not started_services and not dashboard_port and not analytics_enabled:
        print(f"\n{Fore.RED}No services were started.")
        return

    print(f"\n{Fore.GREEN}=== Honeypot Status ===")
    print(f"{Fore.CYAN}The following services are running:")

    for service, port in started_services:
        print(f"  {Fore.GREEN}✓ {service} on port {port}")

    if dashboard_port:
        print(f"  {Fore.GREEN}✓ Dashboard on port {dashboard_port} (http://localhost:{dashboard_port})")

    if analytics_enabled:
        print(f"  {Fore.GREEN}✓ Analytics engine is running")

    print(f"\n{Fore.YELLOW}Press Ctrl+C to stop the honeypot.")
    print(f"{Style.RESET_ALL}")

def main():
    global logger, running

    parser = argparse.ArgumentParser(description="Python Honeypot System")
    parser.add_argument("-c", "--config", help="Path to configuration file", default="config/honeypot.json")
    parser.add_argument("-v", "--verbose", help="Increase output verbosity", action="store_true")
    parser.add_argument("-n", "--no-prompt", help="Start with default services (no interactive prompt)", action="store_true")
    parser.add_argument("--interaction", choices=["low", "medium", "high"], help="Set global interaction level for all services")
    parser.add_argument("--services", help="Comma-separated list of services to enable or 'all'", type=str)
    parser.add_argument("--config-siem", action="store_true", help="Configure SIEM integration")
    parser.add_argument("-d", "--daemon", action="store_true", help="Run as background daemon")
    parser.add_argument("--stop", action="store_true", help="Stop the running daemon")

    args = parser.parse_args()

    # Handle stop request
    if args.stop:
        stop_daemon()
        return

    # Handle SIEM configuration standalone
    if args.config_siem:
        configure_siem(args.config)
        return

    # Daemonize early, before any output
    if args.daemon:
        daemonize()

    print_banner()

    config = load_config(args.config)

    if args.verbose:
        config["logging"]["level"] = "DEBUG"
        config["logging"]["console"] = True

    if args.interaction:
        config["global_interaction_level"] = args.interaction
        for svc in config.get("services", {}).values():
            svc["interaction_level"] = args.interaction

    logger = setup_logging(config)
    logger.info("Starting honeypot system...")

    unified_logger = UnifiedLogger(config)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Select services
    service_map = [
        "ssh", "http", "ftp", "telnet", "mysql", "mssql",
        "rdp", "vnc", "redis", "elasticsearch", "docker"
    ]

    if args.no_prompt or args.services:
        if args.services:
            cleaned = args.services.strip().lower()
            services_to_enable = service_map if cleaned == "all" else [s for s in cleaned.split(',') if s in service_map]
        else:
            services_to_enable = [s for s, scfg in config["services"].items() if scfg.get("enabled")]
    else:
        result = select_services(config, args)
        if not result:
            print(f"{Fore.YELLOW}Exiting...")
            return
        services_to_enable = result

    started_services = start_services(config, services_to_enable, unified_logger)

    if args.interaction:
        save_config(config, args.config)

    print_status(started_services)
    logger.info(f"Honeypot started with {len(started_services)} service(s)")

    try:
        while running:
            time.sleep(1)
    except KeyboardInterrupt:
        running = False
        logger.info("Shutting down honeypot...")

if __name__ == "__main__":
    main()
