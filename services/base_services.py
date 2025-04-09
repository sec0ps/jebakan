#!/usr/bin/env python3
"""
Base service class for honeypot services
"""

import socket
import threading
import logging
import datetime
import json
import os
import time
import random
import ipaddress
from typing import Dict, List, Any, Tuple, Optional

class BaseService:
    """Base class for all honeypot services"""
    
    def __init__(self, host: str, port: int, config: Dict[str, Any], service_name: str):
        """
        Initialize the base service
        
        Args:
            host: Host IP to bind to
            port: Port to listen on
            config: Global configuration dictionary
            service_name: Name of the service (ssh, http, etc.)
        """
        self.host = host
        self.port = port
        self.config = config
        self.service_name = service_name
        self.service_config = config["services"].get(service_name, {})
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = False
        self.connection_count = 0
        self.logger = logging.getLogger(f"honeypot.{service_name}")
        
        # Dictionary to track connection counts by IP
        self.connections_by_ip = {}
        self.connections_lock = threading.Lock()
        
        # Load credentials if available
        self.credentials = self.service_config.get("credentials", [])
        
    def start(self) -> None:
        """Start the service and listen for connections"""
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            self.running = True
            self.logger.info(f"{self.service_name.upper()} honeypot started on port {self.port}")
            
            while self.running:
                try:
                    client, addr = self.sock.accept()
                    
                    # Check if we've reached the maximum connections
                    if self.connection_count >= self.config["network"]["max_connections"]:
                        self.logger.warning(f"Maximum connections reached, dropping connection from {addr[0]}")
                        client.close()
                        continue
                    
                    # Increment connection counters
                    self.connection_count += 1
                    self._increment_ip_counter(addr[0])
                    
                    # Log the connection
                    self.logger.info(f"Connection from {addr[0]}:{addr[1]} to {self.service_name.upper()} service")
                    
                    # Start a new thread to handle the client
                    client_handler = threading.Thread(
                        target=self._handle_client_wrapper,
                        args=(client, addr)
                    )
                    client_handler.daemon = True
                    client_handler.start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    self.logger.error(f"Error accepting connection: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error starting {self.service_name} service: {e}")
        finally:
            if self.sock:
                self.sock.close()
    
    def stop(self) -> None:
        """Stop the service"""
        self.running = False
        if self.sock:
            self.sock.close()
        self.logger.info(f"{self.service_name.upper()} honeypot stopped")
    
    def _handle_client_wrapper(self, client_socket: socket.socket, address: Tuple[str, int]) -> None:
        """
        Wrapper around handle_client to ensure proper cleanup
        
        Args:
            client_socket: Client socket object
            address: Client address tuple (ip, port)
        """
        start_time = time.time()
        connection_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "source_ip": address[0],
            "source_port": address[1],
            "service": self.service_name,
            "data": {}
        }
        
        try:
            # Call the service-specific handler
            self.handle_client(client_socket, address, connection_data)
            
        except Exception as e:
            self.logger.error(f"Error handling client {address[0]}: {e}")
            connection_data["error"] = str(e)
        finally:
            # Calculate session duration
            duration = time.time() - start_time
            connection_data["duration"] = duration
            
            # Save connection data to log file
            self._log_connection(connection_data)
            
            # Check if we need to trigger an alert
            self._check_alert_threshold(address[0])
            
            # Close the client socket
            if client_socket:
                client_socket.close()
            
            # Decrement connection counter
            self.connection_count -= 1
    
    def handle_client(self, client_socket: socket.socket, address: Tuple[str, int], 
                     connection_data: Dict[str, Any]) -> None:
        """
        Handle a client connection - to be implemented by subclasses
        
        Args:
            client_socket: Client socket object
            address: Client address tuple (ip, port)
            connection_data: Dictionary to store connection data for logging
        """
        raise NotImplementedError("Subclasses must implement handle_client")
    
    def _log_connection(self, connection_data: Dict[str, Any]) -> None:
        """
        Log connection data to a file
        
        Args:
            connection_data: Dictionary with connection data
        """
        try:
            log_dir = self.config["logging"]["dir"]
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            log_file = f"{log_dir}/{self.service_name}_connections.json"
            
            with open(log_file, "a") as f:
                f.write(json.dumps(connection_data) + "\n")
                
        except Exception as e:
            self.logger.error(f"Error logging connection data: {e}")
    
    def _increment_ip_counter(self, ip: str) -> None:
        """
        Increment counter for an IP address
        
        Args:
            ip: IP address
        """
        with self.connections_lock:
            timestamp = time.time()
            
            # Clean up old entries
            cutoff = timestamp - self.config["alerts"]["threshold"]["time_window"]
            for ip_addr in list(self.connections_by_ip.keys()):
                self.connections_by_ip[ip_addr] = [t for t in self.connections_by_ip[ip_addr] if t > cutoff]
                if not self.connections_by_ip[ip_addr]:
                    del self.connections_by_ip[ip_addr]
            
            # Add new timestamp
            if ip not in self.connections_by_ip:
                self.connections_by_ip[ip] = []
            
            self.connections_by_ip[ip].append(timestamp)
    
    def _check_alert_threshold(self, ip: str) -> None:
        """
        Check if an IP has exceeded the alert threshold
        
        Args:
            ip: IP address to check
        """
        with self.connections_lock:
            if ip in self.connections_by_ip:
                # Count connections within the time window
                timestamp = time.time()
                cutoff = timestamp - self.config["alerts"]["threshold"]["time_window"]
                recent_connections = [t for t in self.connections_by_ip[ip] if t > cutoff]
                
                # Check if we've exceeded the threshold
                if len(recent_connections) >= self.config["alerts"]["threshold"]["connection_count"]:
                    self.logger.warning(f"Alert threshold exceeded for IP {ip} with {len(recent_connections)} connections")
                    
                    # Reset counter to avoid repeated alerts
                    self.connections_by_ip[ip] = []
                    
                    # Trigger alert - this would typically call the alert manager
                    # For now, just log it
                    alert_data = {
                        "timestamp": datetime.datetime.now().isoformat(),
                        "alert_type": "connection_threshold",
                        "source_ip": ip,
                        "service": self.service_name,
                        "connection_count": len(recent_connections),
                        "time_window": self.config["alerts"]["threshold"]["time_window"]
                    }
                    
                    # Log alert to file
                    try:
                        log_dir = self.config["logging"]["dir"]
                        alert_file = f"{log_dir}/alerts.json"
                        
                        with open(alert_file, "a") as f:
                            f.write(json.dumps(alert_data) + "\n")
                            
                    except Exception as e:
                        self.logger.error(f"Error logging alert: {e}")
    
    def simulate_command_response(self, command: str, context: Dict[str, Any] = None) -> str:
        """
        Simulate a response to a command based on interaction level
        
        Args:
            command: The command to respond to
            context: Optional context dictionary with additional information
            
        Returns:
            String response to the command
        """
        # Default implementation - can be overridden by subclasses
        interaction_level = self.service_config.get("interaction_level", "medium")
        
        if interaction_level == "low":
            # Low interaction - minimal responses
            return f"Command not found: {command}\n"
            
        elif interaction_level == "medium":
            # Medium interaction - more realistic but limited responses
            common_commands = {
                "ls": "file1.txt  file2.txt  folder1  folder2\n",
                "pwd": "/home/user\n",
                "whoami": "user\n",
                "id": "uid=1000(user) gid=1000(user) groups=1000(user)\n",
                "ps": " PID TTY          TIME CMD\n 1234 pts/0    00:00:00 bash\n 5678 pts/0    00:00:00 ps\n",
                "uname": "Linux honeypot 4.15.0-112-generic #113-Ubuntu SMP\n",
                "cat": "Permission denied\n",
                "ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n",
                "netstat": "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\ntcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
            }
            
            # Check if it's a known command
            for cmd, response in common_commands.items():
                if command.startswith(cmd):
                    return response
            
            # Default response for unknown commands
            return f"bash: {command.split()[0]}: command not found\n"
            
        else:  # high interaction
            # High interaction - more sophisticated responses
            # This would typically be implemented by subclasses
            return "Command execution not implemented in this honeypot level\n"
    
    def get_fake_credentials(self) -> Dict[str, str]:
        """
        Get a random set of fake credentials
        
        Returns:
            Dictionary with username and password
        """
        if not self.credentials:
            return {"username": "admin", "password": "password"}
        
        return random.choice(self.credentials)
    
    def is_valid_credentials(self, username: str, password: str) -> bool:
        """
        Check if credentials are valid
        
        Args:
            username: Username to check
            password: Password to check
            
        Returns:
            True if credentials match a known set, False otherwise
        """
        for creds in self.credentials:
            if creds["username"] == username and creds["password"] == password:
                return True
        
        return False
