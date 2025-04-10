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
import colorama
from colorama import Fore, Style, init

# Initialize colorama for colored terminal output
init(autoreset=True)

# Import service modules
#from services.ssh_service import SSHService
#from services.http_service import HTTPService
#from services.ftp_service import FTPService
#from services.telnet_service import TelnetService
#from services.mysql_service import MySQLService
#from services.mssql_service import MSSQLService

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

def check_port_available(host, port):
    """Check if a port is available on the host"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            s.close()
            return True
        except OSError:
            return False

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
    print(f"{Fore.CYAN}d. {Fore.WHITE}Enable dashboard")
    print(f"{Fore.CYAN}a. {Fore.WHITE}Enable analytics")
    print(f"{Fore.CYAN}q. {Fore.WHITE}Quit")

def main():
    global logger, running

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Python Honeypot System")
    parser.add_argument("-c", "--config", help="Path to configuration file", default="config/honeypot.json")
    parser.add_argument("-v", "--verbose", help="Increase output verbosity", action="store_true")
    parser.add_argument("-n", "--no-prompt", help="Start with default services (no interactive prompt)", action="store_true")
    args = parser.parse_args()

    # Print banner
    print_banner()

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

    services_to_enable = []
    enable_dashboard = False
    enable_analytics = False

    if args.no_prompt:
        # Use default enabled services from config
        for service_name, service_config in config["services"].items():
            if service_config.get("enabled", False):
                services_to_enable.append(service_name)

        enable_dashboard = config["dashboard"]["enabled"]
        enable_analytics = config["analytics"]["enabled"]
    else:
        # Interactive prompt
        result = select_services(config)
        if result is None:
            print(f"{Fore.YELLOW}Exiting...")
            return

        services_to_enable, enable_dashboard, enable_analytics = result

    # Initialize alert manager
    alert_manager = AlertManager(config)

    # Initialize analytics engine
    analytics_engine = None
    if enable_analytics:
        analytics_engine = AnalyticsEngine(config)

    # Start services
    started_services = start_services(config, services_to_enable)

    # Start analytics engine if enabled
    if enable_analytics and analytics_engine:
        analytics_thread = threading.Thread(target=analytics_engine.start)
        analytics_thread.daemon = True
        analytics_thread.start()
        logger.info("Analytics engine started")

    # Start dashboard server if enabled
    dashboard_port = None
    if enable_dashboard:
        from utils.dashboard import DashboardServer
        dashboard_port = config["dashboard"]["port"]

        # Check if dashboard port is available
        if not check_port_available(config["network"]["bind_ip"], dashboard_port):
            print(f"{Fore.RED}Dashboard port {dashboard_port} is already in use. Dashboard will not be started.")
            logger.error(f"Dashboard port {dashboard_port} is already in use.")
        else:
            dashboard = DashboardServer(config, analytics_engine)
            dashboard_thread = threading.Thread(target=dashboard.start)
            dashboard_thread.daemon = True
            dashboard_thread.start()
            logger.info(f"Dashboard server started on port {dashboard_port}")

    # Print status
    print_status(started_services, dashboard_port if enable_dashboard else None, enable_analytics)

    logger.info(f"Honeypot started with {len(started_services)} service(s)")

    # Keep the main thread alive
    try:
        while running:
            time.sleep(1)
    except KeyboardInterrupt:
        running = False
        logger.info("Shutting down honeypot...")

def select_services(config):
    """Prompt user to select services to enable"""
    print_service_menu(config)

    while True:
        try:
            choice = input(f"\n{Fore.GREEN}Enter your selection: {Style.RESET_ALL}").strip().lower()

            if choice == 'q':
                return None, False, False

            services_to_enable = []
            enable_dashboard = False
            enable_analytics = False

            if 'd' in choice:
                enable_dashboard = True
                choice = choice.replace('d', '')

            if 'a' in choice:
                enable_analytics = True
                choice = choice.replace('a', '')

            # Clean up the input
            choice = choice.replace(' ', '')

            # Available services
            service_map = ["ssh", "http", "ftp", "telnet", "mysql", "mssql", "rdp", "vnc", "redis", "elasticsearch", "docker"]

            if choice == 'all':
                services_to_enable = service_map
            else:
                # Handle comma-separated list and digit selection
                parts = choice.split(',')
                for part in parts:
                    if part.isdigit():
                        idx = int(part) - 1
                        if 0 <= idx < len(service_map):
                            services_to_enable.append(service_map[idx])
                    elif part in service_map:
                        services_to_enable.append(part)

            # Validate port availability and ensure services exist in config
            for service in services_to_enable[:]:  # Copy list to safely modify during iteration
                # Add service to config if it doesn't exist
                if service not in config["services"]:
                    print(f"{Fore.YELLOW}Adding {service.upper()} service to configuration...")
                    # Set default configuration based on service type
                    if service == "mysql":
                        config["services"][service] = {
                            "enabled": True,
                            "port": 3306,
                            "server_version": "5.7.34-log",
                            "auth_attempts": 3,
                            "credentials": [
                                {"username": "root", "password": ""},
                                {"username": "root", "password": "password"},
                                {"username": "admin", "password": "admin123"}
                            ],
                            "interaction_level": "medium"
                        }
                    elif service == "mssql":
                        config["services"][service] = {
                            "enabled": True,
                            "port": 1433,
                            "server_version": "Microsoft SQL Server 2019",
                            "server_name": "SQLSERVER",
                            "instance_name": "MSSQLSERVER",
                            "auth_attempts": 3,
                            "credentials": [
                                {"username": "sa", "password": "sa"},
                                {"username": "sa", "password": "password"},
                                {"username": "admin", "password": "admin123"}
                            ],
                            "interaction_level": "medium"
                        }

                # Check port availability
                port = config["services"][service]["port"]
                if not check_port_available(config["network"]["bind_ip"], port):
                    print(f"{Fore.RED}Warning: {service.upper()} port {port} is already in use.")
                    confirm = input(f"{Fore.YELLOW}Do you want to continue without {service.upper()}? (y/n): {Style.RESET_ALL}").lower()
                    if confirm == 'y':
                        services_to_enable.remove(service)
                    else:
                        print(f"{Fore.CYAN}Please select services again.")
                        return select_services(config)

            if services_to_enable or enable_dashboard or enable_analytics:
                return services_to_enable, enable_dashboard, enable_analytics
            else:
                print(f"{Fore.RED}No valid services selected. Please try again.")
        except Exception as e:
            print(f"{Fore.RED}Error: {e}. Please try again.")

def start_services(config, services_to_enable):
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
                        config=config
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
                        config=config
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
                        config=config
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
                        config=config
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
                        config=config
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
                        config=config
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
                        config=config
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
                        config=config
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
                        config=config
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
                        config=config
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
                        config=config
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

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Python Honeypot System")
    parser.add_argument("-c", "--config", help="Path to configuration file", default="config/honeypot.json")
    parser.add_argument("-v", "--verbose", help="Increase output verbosity", action="store_true")
    parser.add_argument("-n", "--no-prompt", help="Start with default services (no interactive prompt)", action="store_true")
    args = parser.parse_args()

    # Print banner
    print_banner()

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

    services_to_enable = []
    enable_dashboard = False
    enable_analytics = False

    if args.no_prompt:
        # Use default enabled services from config
        for service_name, service_config in config["services"].items():
            if service_config.get("enabled", False):
                services_to_enable.append(service_name)

        enable_dashboard = config["dashboard"]["enabled"]
        enable_analytics = config["analytics"]["enabled"]
    else:
        # Interactive prompt
        result = select_services(config)
        if not result:
            print(f"{Fore.YELLOW}Exiting...")
            return

        services_to_enable, enable_dashboard, enable_analytics = result

    # Initialize alert manager
    alert_manager = AlertManager(config)

    # Initialize analytics engine
    analytics_engine = None
    if enable_analytics:
        analytics_engine = AnalyticsEngine(config)

    # Start services
    started_services = start_services(config, services_to_enable)

    # Start analytics engine if enabled
    if enable_analytics and analytics_engine:
        analytics_thread = threading.Thread(target=analytics_engine.start)
        analytics_thread.daemon = True
        analytics_thread.start()
        logger.info("Analytics engine started")

    # Start dashboard server if enabled
    dashboard_port = None
    if enable_dashboard:
        from utils.dashboard import DashboardServer
        dashboard_port = config["dashboard"]["port"]

        # Check if dashboard port is available
        if not check_port_available(config["network"]["bind_ip"], dashboard_port):
            print(f"{Fore.RED}Dashboard port {dashboard_port} is already in use. Dashboard will not be started.")
            logger.error(f"Dashboard port {dashboard_port} is already in use.")
        else:
            dashboard = DashboardServer(config, analytics_engine)
            dashboard_thread = threading.Thread(target=dashboard.start)
            dashboard_thread.daemon = True
            dashboard_thread.start()
            logger.info(f"Dashboard server started on port {dashboard_port}")

    # Print status
    print_status(started_services, dashboard_port if enable_dashboard else None, enable_analytics)

    logger.info(f"Honeypot started with {len(started_services)} service(s)")

    # Keep the main thread alive
    try:
        while running:
            time.sleep(1)
    except KeyboardInterrupt:
        running = False
        logger.info("Shutting down honeypot...")

if __name__ == "__main__":
    main()
