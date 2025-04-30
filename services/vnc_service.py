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
VNC service emulator for the honeypot system
"""

import socket
import threading
import logging
import datetime
import json
import os
import time
import struct
import hashlib
import random
from typing import Dict, List, Any, Tuple, Optional

from services.base_service import BaseService

class VNCService(BaseService):
    """VNC service emulator for the honeypot"""

    def __init__(self, host: str, port: int, config: Dict[str, Any], unified_logger=None):
        """
        Initialize the VNC service
    
        Args:
            host: Host IP to bind to
            port: Port to listen on
            config: Global configuration dictionary
            unified_logger: Unified logger instance for centralized logging
        """
        super().__init__(host, port, config, "vnc")
        
        # Store unified logger instance
        self.unified_logger = unified_logger
    
        # VNC specific configurations
        self.server_version = self.service_config.get("server_version", "RFB 003.008")
        self.auth_methods = [2]  # VNC Authentication
        self.challenge = os.urandom(16)  # Random 16-byte challenge

    def handle_client(self, client_socket: socket.socket, address: Tuple[str, int],
                     connection_data: Dict[str, Any]) -> None:
        """
        Handle a client connection to the VNC service
    
        Args:
            client_socket: Client socket object
            address: Client address tuple (ip, port)
            connection_data: Dictionary to store connection data for logging
        """
        connection_data["data"]["connection_time"] = datetime.datetime.now().isoformat()
        
        # Log connection attempt to unified logger
        if self.unified_logger:
            self.unified_logger.log_attack(
                service="vnc",
                attacker_ip=address[0],
                attacker_port=address[1],
                command="connection_attempt",
                additional_data={"timestamp": datetime.datetime.now().isoformat()}
            )
    
        try:
            self.logger.info(f"VNC connection attempt from {address[0]}:{address[1]}")
    
            # Send VNC Protocol Version
            self._send_protocol_version(client_socket)
    
            # Receive client protocol version
            client_version = client_socket.recv(12).decode('ascii', errors='ignore')
            if not client_version:
                return
    
            connection_data["data"]["client_version"] = client_version
            self.logger.debug(f"Client protocol version: {client_version}")
            
            # Log client version to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="vnc",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="protocol_negotiation",
                    additional_data={"client_version": client_version}
                )
    
            # Send supported authentication types
            self._send_auth_types(client_socket)
    
            # Receive chosen auth type
            auth_type = client_socket.recv(1)
            if not auth_type or len(auth_type) == 0:
                return
    
            auth_type_num = auth_type[0]
            connection_data["data"]["auth_type"] = auth_type_num
    
            if auth_type_num == 2:  # VNC Authentication
                # Send challenge
                client_socket.send(self.challenge)
    
                # Receive encrypted challenge (16 bytes)
                response = client_socket.recv(16)
                if not response or len(response) != 16:
                    return
    
                # Attempt to extract password from response
                password = self._extract_password_from_response(response)
    
                # Log the authentication attempt
                auth_data = {
                    "password": password,
                    "timestamp": datetime.datetime.now().isoformat()
                }
    
                if "auth_attempts" not in connection_data["data"]:
                    connection_data["data"]["auth_attempts"] = []
    
                connection_data["data"]["auth_attempts"].append(auth_data)
    
                self.logger.info(f"VNC authentication attempt from {address[0]} with password '{password}'")
                
                # Log authentication attempt to unified logger
                if self.unified_logger:
                    self.unified_logger.log_attack(
                        service="vnc",
                        attacker_ip=address[0],
                        attacker_port=address[1],
                        command="login_attempt",
                        additional_data={
                            "password": password,
                            "timestamp": datetime.datetime.now().isoformat()
                        }
                    )
    
                # Check if the password matches any in the credentials list
                credentials = self.service_config.get("credentials", [])
                auth_success = False
                
                for cred in credentials:
                    if cred.get("password") == password:
                        auth_success = True
                        break
                
                if auth_success:
                    # Send authentication successful
                    self._send_auth_success(client_socket)
                    self.logger.info(f"VNC authentication successful from {address[0]} with password '{password}'")
                    
                    # Log successful authentication to unified logger
                    if self.unified_logger:
                        self.unified_logger.log_attack(
                            service="vnc",
                            attacker_ip=address[0],
                            attacker_port=address[1],
                            command="login_success",
                            additional_data={
                                "password": password,
                                "timestamp": datetime.datetime.now().isoformat()
                            }
                        )
                    
                    # Handle post-authentication interaction
                    self._handle_post_auth(client_socket, connection_data, address)
                else:
                    # Send authentication failed
                    self._send_auth_failed(client_socket)
                    self.logger.info(f"VNC authentication failed from {address[0]} with password '{password}'")
                    
                    # Log failed authentication to unified logger
                    if self.unified_logger:
                        self.unified_logger.log_attack(
                            service="vnc",
                            attacker_ip=address[0],
                            attacker_port=address[1],
                            command="login_failure",
                            additional_data={
                                "password": password,
                                "timestamp": datetime.datetime.now().isoformat()
                            }
                        )
            else:
                # Unsupported auth type
                self.logger.warning(f"Unsupported auth type: {auth_type_num}")
                # Send failure
                client_socket.send(struct.pack(">I", 1))  # Authentication failed
                
                # Log unsupported auth type to unified logger
                if self.unified_logger:
                    self.unified_logger.log_attack(
                        service="vnc",
                        attacker_ip=address[0],
                        attacker_port=address[1],
                        command="unsupported_auth_type",
                        additional_data={"auth_type": auth_type_num}
                    )
    
        except Exception as e:
            self.logger.error(f"Error handling VNC client: {e}")
            connection_data["error"] = str(e)
            
            # Log error to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="vnc",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="error",
                    additional_data={"error": str(e)}
                )
        finally:
            client_socket.close()

    def _send_protocol_version(self, client_socket: socket.socket) -> None:
        """Send VNC protocol version string"""
        version_string = f"{self.server_version}\n"
        client_socket.send(version_string.encode('ascii'))

    def _send_auth_types(self, client_socket: socket.socket) -> None:
        """Send supported authentication types"""
        # First byte is number of auth types
        data = bytearray([len(self.auth_methods)])
        # Add each auth type
        for auth_type in self.auth_methods:
            data.append(auth_type)

        client_socket.send(data)

    def _extract_password_from_response(self, response: bytes) -> str:
        """
        Extract password from VNC authentication response

        In a real VNC server, this would involve decrypting the response.
        For the honeypot, we'll simulate the process.

        Args:
            response: VNC authentication response

        Returns:
            Extracted password or placeholder
        """
        # For the honeypot, we'll log the response but return a placeholder
        # In a real VNC authentication, we'd need to compare against known passwords
        credentials = self.get_fake_credentials()

        # Log the raw response for potential later analysis
        self.logger.debug(f"Auth response (hex): {response.hex()}")

        return credentials["password"]

    def _send_auth_failed(self, client_socket: socket.socket) -> None:
        """Send authentication failed message"""
        # Send auth result (4 bytes): 1 = failed
        client_socket.send(struct.pack(">I", 1))

        # Send error message (VNC 3.8+)
        error_msg = "Authentication failed"

        # First 4 bytes: length of message
        client_socket.send(struct.pack(">I", len(error_msg)))

        # Then the message itself
        client_socket.send(error_msg.encode('utf-8'))
        
    def _send_auth_success(self, client_socket: socket.socket) -> None:
        """Send authentication success message"""
        # Send auth result (4 bytes): 0 = success
        client_socket.send(struct.pack(">I", 0))
        
    def _handle_post_auth(self, client_socket: socket.socket, connection_data: Dict[str, Any], address: Tuple[str, int]) -> None:
        """
        Handle post-authentication interaction
        
        Args:
            client_socket: Client socket object
            connection_data: Dictionary to store connection data for logging
            address: Client address tuple (ip, port)
        """
        try:
            # For a honeypot, we'll just receive client message and send minimal responses
            # In a real VNC server, we would handle actual screen sharing
            
            # First, client will send ClientInit message (1 byte)
            client_init = client_socket.recv(1)
            if not client_init:
                return
                
            shared_flag = client_init[0]
            connection_data["data"]["shared_flag"] = shared_flag
            
            # Log client init to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="vnc",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="client_init",
                    additional_data={"shared_flag": shared_flag}
                )
            
            # Send ServerInit message (basic server info)
            self._send_server_init(client_socket)
            
            # In a real implementation, we would continue with frame buffer updates
            # For the honeypot, we'll just keep the connection open and log any received data
            
            # Set a timeout for idle connections
            client_socket.settimeout(60)  # 60 seconds timeout
            
            while True:
                try:
                    # Wait for client messages
                    message_type = client_socket.recv(1)
                    if not message_type or len(message_type) == 0:
                        break
                        
                    # Log the message type
                    msg_type_num = message_type[0]
                    self.logger.debug(f"Received message type: {msg_type_num}")
                    
                    # Read the rest of the message based on the type
                    # This would be implemented based on RFB protocol
                    # For honeypot, we'll just read some data and log it
                    
                    # Different message types have different lengths
                    if msg_type_num == 0:  # FramebufferUpdateRequest
                        data = client_socket.recv(9)  # Additional 9 bytes
                        msg_type_name = "FramebufferUpdateRequest"
                    elif msg_type_num == 2:  # KeyEvent
                        data = client_socket.recv(7)  # Additional 7 bytes
                        msg_type_name = "KeyEvent"
                    elif msg_type_num == 3:  # PointerEvent
                        data = client_socket.recv(5)  # Additional 5 bytes
                        msg_type_name = "PointerEvent"
                    elif msg_type_num == 4:  # ClientCutText
                        # First 3 bytes are padding, then 4 bytes length
                        header = client_socket.recv(7)
                        msg_type_name = "ClientCutText"
                        if len(header) == 7:
                            length = struct.unpack(">I", header[3:7])[0]
                            data = client_socket.recv(length)
                    else:
                        # Unknown message type, read a small amount to prevent blocking
                        data = client_socket.recv(8)
                        msg_type_name = f"Unknown({msg_type_num})"
                    
                    # Log interactions for analysis
                    if "interactions" not in connection_data["data"]:
                        connection_data["data"]["interactions"] = []
                        
                    connection_data["data"]["interactions"].append({
                        "timestamp": datetime.datetime.now().isoformat(),
                        "message_type": msg_type_num,
                        "data_hex": data.hex() if data else ""
                    })
                    
                    # Log client message to unified logger
                    if self.unified_logger:
                        self.unified_logger.log_attack(
                            service="vnc",
                            attacker_ip=address[0],
                            attacker_port=address[1],
                            command=f"vnc_message_{msg_type_name}",
                            additional_data={
                                "message_type": msg_type_num,
                                "message_type_name": msg_type_name,
                                "data_hex": data.hex() if data else ""
                            }
                        )
                    
                except socket.timeout:
                    # Connection idle, break the loop
                    break
                except Exception as e:
                    self.logger.error(f"Error in post-auth handling: {e}")
                    
                    # Log error to unified logger
                    if self.unified_logger:
                        self.unified_logger.log_attack(
                            service="vnc",
                            attacker_ip=address[0],
                            attacker_port=address[1],
                            command="error",
                            additional_data={"error": str(e), "context": "post_auth_handling"}
                        )
                    break
                    
        except Exception as e:
            self.logger.error(f"Error in post-authentication handling: {e}")
            
            # Log error to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="vnc",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="error",
                    additional_data={"error": str(e), "context": "post_auth_setup"}
                )
            
    def _send_server_init(self, client_socket: socket.socket) -> None:
        """
        Send ServerInit message with fake display information
        
        Args:
            client_socket: Client socket object
        """
        # Create a minimal ServerInit message
        # Format: width (2 bytes), height (2 bytes), pixel format (16 bytes), name length (4 bytes), name (variable)
        
        # Set fake screen resolution (800x600)
        width = 800
        height = 600
        
        # Pixel format (16 bytes)
        # bits-per-pixel (1), depth (1), big-endian-flag (1), true-color-flag (1)
        # red-max (2), green-max (2), blue-max (2)
        # red-shift (1), green-shift (1), blue-shift (1), padding (3)
        pixel_format = bytearray([
            32,  # bits-per-pixel
            24,  # depth
            0,   # big-endian-flag (0 = little endian)
            1,   # true-color-flag
            0, 255,  # red-max (255)
            0, 255,  # green-max (255)
            0, 255,  # blue-max (255)
            16,  # red-shift
            8,   # green-shift
            0,   # blue-shift
            0, 0, 0  # padding
        ])
        
        # Server name
        server_name = "Honeypot VNC Server"
        name_bytes = server_name.encode('ascii')
        
        # Construct the message
        message = struct.pack(">HH", width, height)  # Screen resolution
        message += pixel_format  # Pixel format
        message += struct.pack(">I", len(name_bytes))  # Name length
        message += name_bytes  # Server name
        
        # Send the message
        client_socket.send(message)
        
    def start(self) -> None:
        """Start the VNC service"""
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            self.running = True
            
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="vnc",
                    attacker_ip="system",
                    attacker_port=0,
                    command="service_start",
                    additional_data={"port": self.port}
                )
            
            self.logger.info(f"VNC honeypot started on port {self.port}")
            
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
                    self.logger.info(f"Connection from {addr[0]}:{addr[1]} to VNC service")
                    
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
                            service="vnc",
                            attacker_ip="error",
                            attacker_port=0,
                            command="error",
                            additional_data={"error": str(e)}
                        )
                    self.logger.error(f"Error accepting connection: {e}")
                    
        except Exception as e:
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="vnc",
                    attacker_ip="error",
                    attacker_port=0,
                    command="service_error",
                    additional_data={"error": str(e)}
                )
            self.logger.error(f"Error starting VNC service: {e}")
        finally:
            if self.sock:
                self.sock.close()
