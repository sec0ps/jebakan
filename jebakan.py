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
import copy
import joblib
import requests
import geoip2.database
import subprocess
from packaging import version
from collections import defaultdict, Counter
from typing import Dict, List, Any, Tuple, Optional
from colorama import Fore, Style, init

####### ML Added libraries #######
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN

base_dir = "/opt/jebakan"

VERSION_FILE = os.path.join(base_dir, "version.txt")
REMOTE_VERSION_URL = "https://raw.githubusercontent.com/sec0ps/jebakan/main/version.txt"

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
    log_dir = config["logging"]["dir"]
    
    # Use absolute path for logging directory
    if not os.path.isabs(log_dir):
        log_dir = os.path.join(base_dir, log_dir)
        config["logging"]["dir"] = log_dir
    
    try:
        if not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
    except PermissionError:
        # Fallback to the base_dir/logs if permission denied
        fallback_dir = os.path.join(base_dir, "logs")
        if not os.path.exists(fallback_dir):
            os.makedirs(fallback_dir, exist_ok=True)
        config["logging"]["dir"] = fallback_dir
        log_dir = fallback_dir
        print(f"Permission denied for {log_dir}, using {fallback_dir} instead")

    logging.basicConfig(
        filename=f"{log_dir}/honeypot_{datetime.datetime.now().strftime('%Y%m%d')}.log",
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
    
    # Original service cleanup code
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
    
        # ML-specific attributes
        self.ml_enabled = config.get("analytics", {}).get("enabled", True)
        if self.ml_enabled:
            # Set up ML-specific logging
            self.ml_logger = logging.getLogger("ml_system")
            self.ml_logger.setLevel(logging.INFO)
            
            # Create file handler for ML logs
            ml_log_path = os.path.join(self.log_dir, "ml_system.log")
            ml_file_handler = logging.FileHandler(ml_log_path)
            ml_file_handler.setLevel(logging.INFO)
            
            # Create formatter
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            ml_file_handler.setFormatter(formatter)
            
            # Add the handler to the ML logger
            self.ml_logger.addHandler(ml_file_handler)
            
            # Make the ML logger propagate=False to prevent logs from going to root logger
            self.ml_logger.propagate = False
            
            self.ml_logger.info("ML logging system initialized")
            
            # Initialize ML resources
            self.ip_features_cache = {}
            self.attacker_profiles = {}
            
            # ML model storage
            self.models_dir = os.path.join(os.path.dirname(self.log_dir), "models")
            os.makedirs(self.models_dir, exist_ok=True)
            
            # Load or train initial models
            self.anomaly_model = self._load_model("anomaly_model.pkl") or self._train_anomaly_model()
            self.risk_model = self._load_model("risk_model.pkl") or self._train_risk_model()
            
            # Start background thread for model updates
            self.last_model_update = 0
            self.model_update_interval = 3600  # Update models every hour
            self.ml_update_thread = threading.Thread(target=self._ml_model_update_loop, daemon=True)
            self.ml_update_thread.start()
            
            self.ml_logger.info("ML capabilities initialized in self.ml_logger")

    def log_attack(self, service: str, attacker_ip: str, attacker_port: int, 
                   command: str, additional_data: Dict[str, Any] = None) -> None:
        """
        Log an attack to the unified log file with ML risk analysis
        
        Args:
            service: Service that was attacked
            attacker_ip: Attacker's IP address
            attacker_port: Attacker's port
            command: Command or action performed
            additional_data: Additional attack data
        """
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
        
        # Add ML processing code here
        if hasattr(self, 'ml_enabled') and self.ml_enabled:
            try:
                # Process with ML
                attack_data = {
                    "service": service,
                    "attacker_ip": attacker_ip,
                    "attacker_port": attacker_port,
                    "command": command,
                    "additional_data": additional_data or {},
                    "timestamp": datetime.datetime.now().isoformat()
                }
                
                # Extract features and calculate risk score
                features = self._extract_features(attack_data)
                risk_score = self._calculate_risk_score(features)
                
                # Check for anomalies
                is_anomaly, anomaly_score = self._detect_anomalies(features)
                
                # Add ML results to the log entry
                ml_entry = {
                    "timestamp": datetime.datetime.now().isoformat(),
                    "attack_data": attack_data,
                    "risk_score": float(risk_score),  # Ensure it's a float
                    "is_anomaly": int(is_anomaly),    # Convert bool to int
                    "anomaly_score": float(anomaly_score)  # Ensure it's a float
                }
                
                # Log high-risk or anomalous events
                if risk_score > 0.7 or is_anomaly:
                    self.ml_logger.warning(
                        f"High-risk attack detected from {attacker_ip} - "
                        f"Risk: {risk_score:.2f}, "
                        f"Anomaly: {is_anomaly}, Score: {anomaly_score:.2f}"
                    )
                    
                    # Write to a separate ML insights file
                    ml_log_file = os.path.join(self.log_dir, "ml_insights.json")
                    with open(ml_log_file, 'a') as f:
                        f.write(json.dumps(ml_entry) + "\n")
                    
            except Exception as e:
                self.ml_logger.error(f"Error in ML processing: {e}")
    
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

    def _extract_features(self, attack_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract features from attack data for ML processing"""
        features = {}
        
        # Source IP metadata
        attacker_ip = attack_data.get("attacker_ip", "")
        if attacker_ip in self.ip_features_cache:
            # Update cached features with new attack data
            cached = self.ip_features_cache[attacker_ip]
            cached["attack_count"] += 1
            cached["last_seen"] = time.time()
            
            # Calculate time since first seen
            time_active = cached["last_seen"] - cached["first_seen"]
            cached["attacks_per_hour"] = (cached["attack_count"] / time_active) * 3600 if time_active > 0 else 0
            
            # Record service attacked
            service = attack_data.get("service", "unknown")
            cached["services_attacked"].add(service)
            cached["service_count"] = len(cached["services_attacked"])
            
            # Record command if present
            command = attack_data.get("command", "")
            if command:
                cached["commands"].append(command)
            
            # Extract and store features from cache
            features["attack_count"] = cached["attack_count"]
            features["time_active_seconds"] = time_active
            features["attacks_per_hour"] = cached["attacks_per_hour"]
            features["service_count"] = cached["service_count"]
            features["unique_commands"] = len(set(cached["commands"]))
            features["command_count"] = len(cached["commands"])
        else:
            # Initialize cache for new IP
            self.ip_features_cache[attacker_ip] = {
                "attack_count": 1,
                "first_seen": time.time(),
                "last_seen": time.time(),
                "attacks_per_hour": 0,
                "services_attacked": {attack_data.get("service", "unknown")},
                "service_count": 1,
                "commands": [attack_data.get("command", "")]
            }
            
            # Set initial features
            features["attack_count"] = 1
            features["time_active_seconds"] = 0
            features["attacks_per_hour"] = 0
            features["service_count"] = 1
            features["unique_commands"] = 1 if attack_data.get("command") else 0
            features["command_count"] = 1 if attack_data.get("command") else 0
        
        # Service-specific features
        service = attack_data.get("service", "unknown")
        command = attack_data.get("command", "")
        
        # Common malicious indicators
        malicious_indicators = [
            "wget", "curl", "chmod", "base64", "eval", "bash", "sh ", 
            "nc ", "ncat", "reverse shell", "cat /etc/passwd", "cat /etc/shadow"
        ]
        
        # Check for malicious indicators in command
        features["malicious_indicator_count"] = sum(1 for ind in malicious_indicators if ind in command.lower())
        
        # Check for login attempts
        if "login_attempt" in command or command == "login_attempt":
            features["login_attempt"] = 1
            
            # Extract credentials if available
            additional_data = attack_data.get("additional_data", {})
            username = additional_data.get("username", "")
            password = additional_data.get("password", "")
            
            # Features based on username/password
            features["username_length"] = len(username) if username else 0
            features["password_length"] = len(password) if password else 0
            features["has_special_chars"] = 1 if any(c in r'!@#$%^&*()_+-=[]{};\:"|<>?,./' for c in password) else 0
        else:
            features["login_attempt"] = 0
            features["username_length"] = 0
            features["password_length"] = 0
            features["has_special_chars"] = 0
        
        # Service-specific features
        if service == "ssh":
            features["ssh_attack"] = 1
        else:
            features["ssh_attack"] = 0
            
        if service == "http":
            features["http_attack"] = 1
            
            # Extract HTTP-specific features
            additional_data = attack_data.get("additional_data", {})
            path = additional_data.get("path", "")
            
            # Check for common web attack patterns
            web_attack_patterns = [
                "wp-admin", "phpMyAdmin", "admin", "login.php", 
                "wp-login", ".git", "../", "passwd", "/etc/", "select",
                "union", "insert", "drop", "alert(", "<script"
            ]
            features["web_attack_pattern_count"] = sum(1 for patt in web_attack_patterns if patt in path)
        else:
            features["http_attack"] = 0
            features["web_attack_pattern_count"] = 0
        
        return features
    
    def _calculate_risk_score(self, features: Dict[str, float]) -> float:
        """Calculate a risk score based on extracted features"""
        # Base risk score
        risk_score = 0.0
        
        # Increment risk for high attack frequency
        if features["attacks_per_hour"] > 10:
            risk_score += 0.3
        elif features["attacks_per_hour"] > 5:
            risk_score += 0.2
        elif features["attacks_per_hour"] > 1:
            risk_score += 0.1
        
        # Increment risk for multi-service attacks
        if features["service_count"] > 3:
            risk_score += 0.3
        elif features["service_count"] > 1:
            risk_score += 0.2
        
        # Increment risk for command patterns
        risk_score += min(0.4, features["malicious_indicator_count"] * 0.1)
        
        # Increment risk for web attack patterns
        risk_score += min(0.3, features["web_attack_pattern_count"] * 0.05)
        
        # Clamp risk score between 0 and 1
        return max(0.0, min(1.0, risk_score))
    
    def _detect_anomalies(self, features: Dict[str, float]) -> Tuple[bool, float]:
        """Detect whether an attack is anomalous based on historical patterns"""
        if not hasattr(self, 'anomaly_model') or self.anomaly_model is None:
            return False, 0.0
            
        # Convert features to format expected by model
        feature_vector = self._features_to_vector(features)
        
        # Use IsolationForest to detect anomalies
        try:
            # Reshape for single sample prediction
            feature_vector = feature_vector.reshape(1, -1)
            
            # Get anomaly score (negative = more anomalous)
            anomaly_score = -self.anomaly_model.score_samples(feature_vector)[0]
            
            # Determine if it's an anomaly (decision_function < 0 means anomaly)
            is_anomaly = self.anomaly_model.decision_function(feature_vector)[0] < 0
            
            return is_anomaly, anomaly_score
        except Exception as e:
            self.logger.error(f"Error detecting anomalies: {e}")
            return False, 0.0
    
    def _features_to_vector(self, features: Dict[str, float]) -> np.ndarray:
        """Convert feature dictionary to numpy array for model input"""
        # Define the expected feature order for models
        feature_keys = [
            "attack_count", "time_active_seconds", "attacks_per_hour",
            "service_count", "unique_commands", "command_count",
            "malicious_indicator_count", "login_attempt",
            "username_length", "password_length", "has_special_chars",
            "ssh_attack", "http_attack", "web_attack_pattern_count"
        ]
        
        # Create feature vector with proper ordering
        vector = np.array([features.get(key, 0.0) for key in feature_keys])
        return vector
    
    def _load_model(self, model_name: str) -> Any:
        """Load a saved ML model if it exists"""
        model_path = os.path.join(self.models_dir, model_name)
        if os.path.exists(model_path):
            try:
                self.ml_logger.info(f"Loading model from {model_path}")
                return joblib.load(model_path)
            except Exception as e:
                self.logger.error(f"Error loading model {model_name}: {e}")
        return None
    
    def _save_model(self, model: Any, model_name: str) -> bool:
        """Save an ML model to disk"""
        model_path = os.path.join(self.models_dir, model_name)
        try:
            joblib.dump(model, model_path)
            self.ml_logger.info(f"Model saved to {model_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving model {model_name}: {e}")
            return False
    
    def _train_anomaly_model(self) -> Any:
        """Train the anomaly detection model using IsolationForest"""
        self.ml_logger.info("Training anomaly detection model")
        
        # Collect attack data from logs
        attack_data = self._collect_attack_data()
        
        if len(attack_data) < 10:
            self.logger.warning("Not enough data to train anomaly model (need at least 10 samples)")
            return None
        
        try:
            # Extract features from each attack
            features_list = [self._extract_features(attack) for attack in attack_data]
            
            # Convert to numpy array
            X = np.array([self._features_to_vector(features) for features in features_list])
            
            # Train IsolationForest model
            model = IsolationForest(
                n_estimators=100,
                max_samples='auto',
                contamination=0.1,  # Assume 10% of data is anomalous
                random_state=42
            )
            model.fit(X)
            
            # Save the model
            self._save_model(model, "anomaly_model.pkl")
            
            self.ml_logger.info(f"Anomaly model trained on {len(X)} samples")
            return model
            
        except Exception as e:
            self.logger.error(f"Error training anomaly model: {e}")
            return None
    
    def _train_risk_model(self) -> Any:
        """Train the risk scoring model using RandomForestClassifier"""
        self.ml_logger.info("Training risk scoring model")
        
        # Collect attack data from logs
        attack_data = self._collect_attack_data()
        
        if len(attack_data) < 10:
            self.logger.warning("Not enough data to train risk model (need at least 10 samples)")
            return None
        
        try:
            # Extract features from each attack
            features_list = [self._extract_features(attack) for attack in attack_data]
            
            # Create synthetic labels for training
            # (in real deployment this would use human-labeled data)
            y = np.array([
                1 if features["malicious_indicator_count"] > 0 or 
                     features["web_attack_pattern_count"] > 0 else 0
                for features in features_list
            ])
            
            # Convert to numpy array
            X = np.array([self._features_to_vector(features) for features in features_list])
            
            # Train RandomForestClassifier model
            model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
            model.fit(X, y)
            
            # Save the model
            self._save_model(model, "risk_model.pkl")
            
            self.ml_logger.info(f"Risk model trained on {len(X)} samples")
            return model
            
        except Exception as e:
            self.logger.error(f"Error training risk model: {e}")
            return None
    
    def _collect_attack_data(self) -> List[Dict[str, Any]]:
        """Collect attack data from logs for model training"""
        attack_data = []
        
        # Find attack log files
        if os.path.exists(self.unified_log_file):
            try:
                with open(self.unified_log_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                attack = json.loads(line)
                                attack_data.append(attack)
                            except json.JSONDecodeError:
                                continue
            except Exception as e:
                self.logger.error(f"Error reading attack log: {e}")
        
        return attack_data
    
    def _ml_model_update_loop(self) -> None:
        """Background thread to periodically update ML models"""
        while True:
            current_time = time.time()
            
            # Update models if enough time has passed
            if current_time - self.last_model_update > self.model_update_interval:
                try:
                    self.ml_logger.info("Starting periodic ML model update")
                    
                    # Update models
                    self.anomaly_model = self._train_anomaly_model()
                    self.risk_model = self._train_risk_model()
                    
                    self.last_model_update = current_time
                    self.ml_logger.info("Periodic ML model update completed")
                    
                except Exception as e:
                    self.logger.error(f"Error during periodic ML model update: {e}")
            
            # Sleep before next check
            time.sleep(60)  # Check every minute

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

    # Make sure config directory exists with proper permissions
    if not os.path.exists(os.path.join(base_dir, "config")):
        os.makedirs(os.path.join(base_dir, "config"), exist_ok=True)
        
    # Make sure logs directory exists with proper permissions before redirecting output
    logs_dir = os.path.join(base_dir, "logs")
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir, exist_ok=True)
    
    # Write logs to a file
    log_path = os.path.join(base_dir, "config", "jebakan.daemon.log")
    sys.stdout.flush()
    sys.stderr.flush()

    with open(log_path, 'a+') as out_log:
        os.dup2(out_log.fileno(), sys.stdout.fileno())
        os.dup2(out_log.fileno(), sys.stderr.fileno())

    # Save PID
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

    # Create necessary directories before daemonizing
    if not os.path.exists(os.path.join(base_dir, "logs")):
        try:
            os.makedirs(os.path.join(base_dir, "logs"), exist_ok=True)
        except PermissionError:
            print(f"Warning: Permission denied when creating logs directory at {os.path.join(base_dir, 'logs')}")
            
    if not os.path.exists(os.path.join(base_dir, "config")):
        try:
            os.makedirs(os.path.join(base_dir, "config"), exist_ok=True)
        except PermissionError:
            print(f"Warning: Permission denied when creating config directory at {os.path.join(base_dir, 'config')}")

    # Daemonize early, before any output
    if args.daemon:
        daemonize()

    print_banner()

    config = load_config(config_path)

    if args.verbose:
        config["logging"]["level"] = "DEBUG"
        config["logging"]["console"] = True

    if args.interaction:
        config["global_interaction_level"] = args.interaction
        for svc in config.get("services", {}).values():
            svc["interaction_level"] = args.interaction
            
    # Ensure log directory path is absolute
    if "logging" in config and "dir" in config["logging"]:
        if not os.path.isabs(config["logging"]["dir"]):
            config["logging"]["dir"] = os.path.join(base_dir, config["logging"]["dir"])

    logger = setup_logging(config)
    logger.info("Starting honeypot system...")

    unified_logger = self.logger(config)

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

################# CONFIG MANAGER ########################
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
            "interaction_level": "high"  # low, medium, high
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
            "interaction_level": "high"
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
            "interaction_level": "high"
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
            "interaction_level": "high"
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
            "interaction_level": "high"
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
            "interaction_level": "high"
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
            "interaction_level": "high"
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
            "interaction_level": "high"
        },
        "redis": {
            "enabled": True,
            "port": 6379,
            "server_version": "5.0.7",
            "password": "redis123",
            "require_auth": True,
            "interaction_level": "high"
        },
        "elasticsearch": {
            "enabled": True,
            "port": 9200,
            "server_version": "6.8.0",
            "cluster_name": "elasticsearch-cluster",
            "interaction_level": "high"
        },
        "docker": {
            "enabled": True,
            "port": 2375,
            "api_version": "1.41",
            "docker_version": "20.10.7",
            "interaction_level": "high"
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
        return copy.deepcopy(DEFAULT_CONFIG)

    # Load existing config
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
            logging.info(f"Loaded configuration from {config_path}")

            # Ensure all default keys exist (for backwards compatibility)
            merged_config = copy.deepcopy(DEFAULT_CONFIG)  # <-- Deep copy fixes overwriting issue
            _recursive_update(merged_config, config)

            return merged_config
    except Exception as e:
        logging.error(f"Error loading config from {config_path}: {e}")
        logging.info("Using default configuration")
        return copy.deepcopy(DEFAULT_CONFIG)

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

    for k, v in u.items():
        if isinstance(v, dict) and k in d and isinstance(d[k], dict):
            _recursive_update(d[k], v)
        else:
            d[k] = v
    return d

#########################################################

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

def check_for_updates():
    """Check if a newer version is available and force update if needed"""
    current_version_file = os.path.join(os.path.dirname(__file__), 'version.txt')
    if not os.path.isfile(current_version_file):
        print("Version file not found.")
        return

    with open(current_version_file, 'r') as f:
        current_version = f.read().strip()

    try:
        response = requests.get("https://raw.githubusercontent.com/sec0ps/jebakan/main/version.txt", timeout=5)
        if response.status_code == 200:
            latest_version = response.text.strip()
            if latest_version != current_version:
                print(f"Update available: {latest_version} (current: {current_version})")
                print("Pulling latest changes from GitHub...")

                try:
                    subprocess.run(["git", "reset", "--hard"], check=True)
                    subprocess.run(["git", "clean", "-fd"], check=True)
                    subprocess.run(["git", "pull"], check=True)

                    # Overwrite version.txt with the new version
                    with open(current_version_file, 'w') as f:
                        f.write(latest_version + "\n")

                    print("Update completed successfully.")
                except subprocess.CalledProcessError as e:
                    print(f"Git update failed: {e}")
            else:
                print("Jebakan is up to date.")
        else:
            print("Failed to check for updates.")
    except Exception as e:
        print(f"Update check error: {e}")

def force_git_update():
    try:
        subprocess.run(["git", "reset", "--hard"], check=True)
        subprocess.run(["git", "clean", "-fd"], check=True)
        subprocess.run(["git", "pull"], check=True)
        print("Forced update completed.")
    except subprocess.CalledProcessError as e:
        print(f"Update failed: {e}")

def main():
    global logger, running
    
    check_for_updates()

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

    config = load_config(config_path)

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
