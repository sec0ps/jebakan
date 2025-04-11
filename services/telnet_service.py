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
    
    def __init__(self, host: str, port: int, config: Dict[str, Any]):
        """
        Initialize the Telnet service
        
        Args:
            host: Host IP to bind to
            port: Port to listen on
            config: Global configuration dictionary
        """
        super().__init__(host, port, config, "telnet")
        
        # Set up Telnet server
        self.banner = self.service_config.get("banner", "Ubuntu 18.04 LTS")
        
        # Track command history by session
        self.command_history = {}
    
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

                # Check credentials
                auth_successful = self.is_valid_credentials(username, password)

                if auth_successful:
                    # Authentication successful
                    connection_data["data"]["auth_result"] = "success"
                    client_socket.send(b"\r\nLast login: Mon Apr 7 12:34:56 2025 from 192.168.1.5\r\n")
                    self.logger.info(f"Successful telnet authentication from {address[0]} with username '{username}' and password '{password}'")
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
                self._simulate_shell(client_socket, session_id, username, connection_data)

        except Exception as e:
            self.logger.error(f"Error handling telnet client: {e}")
            connection_data["error"] = str(e)
        finally:
            # Clean up session data
            if session_id in self.command_history:
                connection_data["data"]["command_history"] = self.command_history[session_id]
                del self.command_history[session_id]
