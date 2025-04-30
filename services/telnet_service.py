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
Telnet service emulator for the honeypot system
"""

import socket
import threading
import logging
import datetime
import json
import os
import time
import re
from typing import Dict, List, Any, Tuple, Optional

from services.base_service import BaseService

class TelnetService(BaseService):
    """Telnet service emulator for the honeypot"""
    
    def __init__(self, host: str, port: int, config: Dict[str, Any], unified_logger=None):
        """
        Initialize the Telnet service
        
        Args:
            host: Host IP to bind to
            port: Port to listen on
            config: Global configuration dictionary
            unified_logger: Unified logger instance for centralized logging
        """
        super().__init__(host, port, config, "telnet")
        
        # Store unified logger instance
        self.unified_logger = unified_logger
        
        # Set up Telnet server
        self.banner = self.service_config.get("banner", "Ubuntu 18.04 LTS")
        
        # Track command history by session
        self.command_history = {}
        
    def _simulate_shell(self, client_socket: socket.socket, session_id: str, username: str, connection_data: Dict[str, Any], address: Tuple[str, int]) -> None:
        """
        Simulates a fake interactive shell after successful authentication.
    
        Args:
            client_socket: Client socket
            session_id: Unique session ID for tracking
            username: Authenticated username
            connection_data: Dictionary to store interaction data
            address: Client address tuple (ip, port)
        """
        try:
            client_socket.send(f"\r\nWelcome {username}! Type 'exit' to disconnect.\r\n\n$ ".encode())
    
            while True:
                # Receive command input
                command_data = client_socket.recv(1024)
                if not command_data:
                    break
    
                command = command_data.decode('utf-8', errors='ignore').strip()
                self.command_history[session_id].append(command)
                
                # Log command to unified logger
                if self.unified_logger:
                    self.unified_logger.log_attack(
                        service="telnet",
                        attacker_ip=address[0],
                        attacker_port=address[1],
                        command=command,
                        additional_data={
                            "session_id": session_id,
                            "username": username,
                            "timestamp": datetime.datetime.now().isoformat()
                        }
                    )
    
                # Fake command responses
                if command.lower() in ["exit", "logout", "quit"]:
                    client_socket.send(b"\r\nLogging out...\r\n")
                    break
                elif command.lower() in ["ls", "dir"]:
                    client_socket.send(b"fake_file.txt  secrets.doc  config.yaml\r\n")
                elif command.lower() == "whoami":
                    client_socket.send(f"{username}\r\n".encode())
                elif command.lower() == "pwd":
                    client_socket.send(b"/home/fakeuser\r\n")
                elif command.lower() == "uname -a":
                    client_socket.send(b"Linux honeypot 5.4.0-42-generic #46-Ubuntu SMP x86_64 GNU/Linux\r\n")
                else:
                    client_socket.send(f"bash: {command}: command not found\r\n".encode())
    
                client_socket.send(b"$ ")
    
        except Exception as e:
            self.logger.error(f"Telnet shell error for {session_id}: {e}")
            connection_data["shell_error"] = str(e)
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="telnet",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="error",
                    additional_data={
                        "error": str(e),
                        "session_id": session_id
                    }
                )
        finally:
            client_socket.close()

    def handle_client(self, client_socket: socket.socket, address: Tuple[str, int],
                        connection_data: Dict[str, Any]) -> None:
        """
        Handle a client connection to the Telnet service
    
        Args:
            client_socket: Client socket object
            address: Client address tuple (ip, port)
            connection_data: Dictionary to store connection data for logging
        """
        # Create a unique session ID for this connection
        session_id = f"{address[0]}:{address[1]}:{time.time()}"
    
        # Initialize command history for this session
        self.command_history[session_id] = []
        
        # Log connection attempt to unified logger
        if self.unified_logger:
            self.unified_logger.log_attack(
                service="telnet",
                attacker_ip=address[0],
                attacker_port=address[1],
                command="connection_attempt",
                additional_data={"timestamp": datetime.datetime.now().isoformat()}
            )
    
        try:
            # Send welcome banner
            client_socket.send(f"\r\n{self.banner}\r\n".encode())
            client_socket.send(b"\r\nlogin: ")
    
            # Authentication phase
            auth_attempts = 0
            max_auth_attempts = self.service_config.get("auth_attempts", 3)
            auth_successful = False
    
            while auth_attempts < max_auth_attempts and not auth_successful:
                # Get username
                username_data = client_socket.recv(1024)
                if not username_data:
                    break
    
                username = username_data.decode('utf-8', errors='ignore').strip()
    
                # Get password
                client_socket.send(b"Password: ")
                password_data = client_socket.recv(1024)
                if not password_data:
                    break
    
                password = password_data.decode('utf-8', errors='ignore').strip()
    
                # Log the authentication attempt
                auth_data = {
                    "username": username,
                    "password": password,
                    "attempt": auth_attempts + 1,
                    "timestamp": datetime.datetime.now().isoformat()
                }
    
                if "auth_attempts" not in connection_data["data"]:
                    connection_data["data"]["auth_attempts"] = []
    
                connection_data["data"]["auth_attempts"].append(auth_data)
                
                # Log authentication attempt to unified logger
                if self.unified_logger:
                    self.unified_logger.log_attack(
                        service="telnet",
                        attacker_ip=address[0],
                        attacker_port=address[1],
                        command="login_attempt",
                        additional_data={
                            "username": username,
                            "password": password,
                            "success": self.is_valid_credentials(username, password),
                            "attempt": auth_attempts + 1
                        }
                    )
    
                # Check credentials
                auth_successful = self.is_valid_credentials(username, password)
    
                if auth_successful:
                    # Authentication successful
                    connection_data["data"]["auth_result"] = "success"
                    client_socket.send(b"\r\nLast login: Mon Apr 7 12:34:56 2025 from 192.168.1.5\r\n")
                    self.logger.info(f"Successful telnet authentication from {address[0]} with username '{username}' and password '{password}'")
                    
                    # Log successful authentication to unified logger
                    if self.unified_logger:
                        self.unified_logger.log_attack(
                            service="telnet",
                            attacker_ip=address[0],
                            attacker_port=address[1],
                            command="login_success",
                            additional_data={
                                "username": username,
                                "password": password,
                                "session_id": session_id
                            }
                        )
                else:
                    # Authentication failed
                    auth_attempts += 1
                    connection_data["data"]["auth_result"] = "failure"
    
                    if auth_attempts < max_auth_attempts:
                        client_socket.send(b"\r\nLogin incorrect\r\n\r\nlogin: ")
                    else:
                        client_socket.send(b"\r\nLogin incorrect\r\nMaximum login attempts exceeded\r\n")
                        self.logger.info(f"Failed telnet authentication from {address[0]} after {auth_attempts} attempts")
                        break
    
            # If authentication was successful, proceed to shell emulation
            if auth_successful:
                self._simulate_shell(client_socket, session_id, username, connection_data, address)
    
        except Exception as e:
            self.logger.error(f"Error handling telnet client: {e}")
            connection_data["error"] = str(e)
            
            # Log error to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="telnet",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="error",
                    additional_data={"error": str(e)}
                )
        finally:
            # Clean up session data
            if session_id in self.command_history:
                connection_data["data"]["command_history"] = self.command_history[session_id]
                del self.command_history[session_id]

    def start(self) -> None:
        """Start the Telnet service properly by listening on a socket"""
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            self.running = True
            
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="telnet",
                    attacker_ip="system",
                    attacker_port=0,
                    command="service_start",
                    additional_data={"port": self.port}
                )
            
            self.logger.info(f"Telnet honeypot started on port {self.port}")
            
            while self.running:
                try:
                    client, addr = self.sock.accept()
                    
                    # Set a timeout for the client socket
                    client.settimeout(self.config["resource_limits"]["connection_timeout"])
                    
                    # Check if we've reached the maximum connections
                    if self.connection_count >= self.config["network"]["max_connections"]:
                        self.logger.warning(f"Maximum connections reached, dropping connection from {addr[0]}")
                        client.close()
                        continue
                    
                    # Increment connection counters
                    self.connection_count += 1
                    self._increment_ip_counter(addr[0])
                    
                    # Log the connection
                    self.logger.info(f"Connection from {addr[0]}:{addr[1]} to Telnet service")
                    
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
                    if self.unified_logger:
                        self.unified_logger.log_attack(
                            service="telnet",
                            attacker_ip="error",
                            attacker_port=0,
                            command="error",
                            additional_data={"error": str(e)}
                        )
                    self.logger.error(f"Error accepting connection: {e}")
                    
        except Exception as e:
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="telnet",
                    attacker_ip="error",
                    attacker_port=0,
                    command="service_error",
                    additional_data={"error": str(e)}
                )
            self.logger.error(f"Error starting Telnet service: {e}")
        finally:
            if self.sock:
                self.sock.close()
