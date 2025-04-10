#!/usr/bin/env python3
"""
Configuration manager for the honeypot system
"""

import json
import os
import logging
from typing import Dict, Any

# Default configuration
DEFAULT_CONFIG = {
    "network": {
        "bind_ip": "0.0.0.0",
        "max_connections": 100
    },
    "services": {
        "ssh": {
            "enabled": True,
            "port": 2222,  # Using non-standard ports to avoid conflicts
            "banner": "SSH-2.0-OpenSSH_7.4p1 Ubuntu-10",
            "auth_attempts": 3,
            "credentials": [
                {"username": "admin", "password": "password123"},
                {"username": "root", "password": "toor"},
                {"username": "user", "password": "123456"}
            ],
            "interaction_level": "medium"  # low, medium, high
        },
        "http": {
            "enabled": True,
            "port": 8080,
            "server_name": "Apache/2.4.41 (Ubuntu)",
            "webroot": "data/http",
            "vulnerable_pages": [
                "/admin",
                "/phpmyadmin",
                "/wordpress/wp-admin"
            ],
            "interaction_level": "medium"
        },
        "ftp": {
            "enabled": True,
            "port": 2121,
            "banner": "220 FTP Server Ready",
            "auth_attempts": 3,
            "credentials": [
                {"username": "anonymous", "password": ""},
                {"username": "admin", "password": "admin"},
                {"username": "ftpuser", "password": "ftppass"}
            ],
            "interaction_level": "medium"
        },
        "telnet": {
            "enabled": True,
            "port": 2323,
            "banner": "Ubuntu 18.04 LTS",
            "auth_attempts": 3,
            "credentials": [
                {"username": "admin", "password": "admin"},
                {"username": "root", "password": "root"},
                {"username": "user", "password": "password"}
            ],
            "interaction_level": "medium"
        },
        "mysql": {
            "enabled": True,
            "port": 3306,
            "server_version": "5.7.34-log",
            "auth_attempts": 3,
            "credentials": [
                {"username": "root", "password": ""},
                {"username": "root", "password": "password"},
                {"username": "admin", "password": "admin123"},
                {"username": "dbuser", "password": "dbpass"}
            ],
            "interaction_level": "medium"
        },
        "mssql": {
            "enabled": True,
            "port": 1433,
            "server_version": "Microsoft SQL Server 2019",
            "server_name": "SQLSERVER",
            "instance_name": "MSSQLSERVER",
            "auth_attempts": 3,
            "credentials": [
                {"username": "sa", "password": "sa"},
                {"username": "sa", "password": "password"},
                {"username": "admin", "password": "admin123"},
                {"username": "sqlserver", "password": "sqlserver"}
            ],
            "interaction_level": "medium"
        },
        "rdp": {
            "enabled": True,
            "port": 3389,
            "server_name": "WIN-SERVER2019",
            "os_version": "Windows Server 2019",
            "auth_attempts": 3,
            "credentials": [
                {"username": "Administrator", "password": "P@ssw0rd"},
                {"username": "admin", "password": "admin123"},
                {"username": "user", "password": "user123"}
            ],
            "interaction_level": "medium"
        },
        "vnc": {
            "enabled": True,
            "port": 5900,
            "server_version": "RFB 003.008",
            "auth_attempts": 3,
            "credentials": [
                {"username": "", "password": "password"},
                {"username": "", "password": "admin"},
                {"username": "", "password": "secret"}
            ],
            "interaction_level": "medium"
        },
        "redis": {
            "enabled": True,
            "port": 6379,
            "server_version": "5.0.7",
            "password": "redis123",
            "require_auth": True,
            "interaction_level": "medium"
        },
        "elasticsearch": {
            "enabled": True,
            "port": 9200,
            "server_version": "6.8.0",
            "cluster_name": "elasticsearch-cluster",
            "interaction_level": "medium"
        },
        "docker": {
            "enabled": True,
            "port": 2375,
            "api_version": "1.41",
            "docker_version": "20.10.7",
            "interaction_level": "medium"
        }
    },
    "logging": {
        "dir": "logs/",
        "level": "INFO",
        "console": True,
        "rotation": {
            "enabled": True,
            "max_size_mb": 10,
            "backup_count": 5
        }
    },
    "analytics": {
        "enabled": True,
        "database": {
            "type": "sqlite",  # sqlite, mysql, postgresql
            "path": "data/honeypot.db",
            "host": "",
            "port": 0,
            "user": "",
            "password": "",
            "name": ""
        },
        "analysis_interval": 300  # seconds
    },
    "alerts": {
        "email": {
            "enabled": False,
            "smtp_server": "",
            "smtp_port": 587,
            "use_tls": True,
            "username": "",
            "password": "",
            "from_address": "",
            "to_addresses": []
        },
        "webhook": {
            "enabled": False,
            "url": ""
        },
        "threshold": {
            "connection_count": 10,  # Alert after 10 connections from same IP
            "time_window": 60  # In seconds
        }
    },
    "dashboard": {
        "enabled": True,
        "port": 8000,
        "username": "admin",
        "password": "honeypot"
    },
    "deception": {
        "fake_filesystem": {
            "enabled": True,
            "path": "data/fake_fs"
        },
        "fake_processes": [
            {"name": "nginx", "pid": 1234},
            {"name": "mysql", "pid": 2345},
            {"name": "postgres", "pid": 3456}
        ],
        "breadcrumbs": True,  # Add fake sensitive info as breadcrumbs
        "system_info": {
            "hostname": "web-prod-01",
            "os": "Ubuntu 18.04.5 LTS",
            "kernel": "4.15.0-112-generic"
        }
    },
    "resource_limits": {
        "max_memory_mb": 1024,
        "max_cpu_percent": 50,
        "connection_timeout": 300  # seconds
    }
}

def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from a JSON file.
    If file doesn't exist, create it with default config.

    Args:
        config_path: Path to the configuration file

    Returns:
        Dict containing configuration
    """
    # Ensure directory exists
    os.makedirs(os.path.dirname(config_path), exist_ok=True)

    # If config file doesn't exist, create it with defaults
    if not os.path.exists(config_path):
        save_config(DEFAULT_CONFIG, config_path)
        logging.info(f"Created default configuration at {config_path}")
        return DEFAULT_CONFIG

    # Load existing config
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
            logging.info(f"Loaded configuration from {config_path}")

            # Ensure all default keys exist (for backwards compatibility)
            merged_config = DEFAULT_CONFIG.copy()
            _recursive_update(merged_config, config)

            return merged_config
    except Exception as e:
        logging.error(f"Error loading config from {config_path}: {e}")
        logging.info("Using default configuration")
        return DEFAULT_CONFIG

def save_config(config: Dict[str, Any], config_path: str) -> bool:
    """
    Save configuration to a JSON file

    Args:
        config: Configuration dictionary
        config_path: Path to save the configuration

    Returns:
        True if successful, False otherwise
    """
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(config_path), exist_ok=True)

        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)

        logging.info(f"Saved configuration to {config_path}")
        return True
    except Exception as e:
        logging.error(f"Error saving config to {config_path}: {e}")
        return False

def _recursive_update(d: Dict[str, Any], u: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively update a dictionary with another dictionary

    Args:
        d: Dictionary to update
        u: Dictionary with updates

    Returns:
        Updated dictionary
    """
    for k, v in u.items():
        if isinstance(v, dict) and k in d and isinstance(d[k], dict):
            _recursive_update(d[k], v)
        else:
            d[k] = v
    return d
