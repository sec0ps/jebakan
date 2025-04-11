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

    def __init__(self, host: str, port: int, config: Dict[str, Any]):
        """
        Initialize the VNC service

        Args:
            host: Host IP to bind to
            port: Port to listen on
            config: Global configuration dictionary
        """
        super().__init__(host, port, config, "vnc")

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
                    
                    # Handle post-authentication interaction
                    self._handle_post_auth(client_socket, connection_data)
                else:
                    # Send authentication failed
                    self._send_auth_failed(client_socket)
                    self.logger.info(f"VNC authentication failed from {address[0]} with password '{password}'")
            else:
                # Unsupported auth type
                self.logger.warning(f"Unsupported auth type: {auth_type_num}")
                # Send failure
                client_socket.send(struct.pack(">I", 1))  # Authentication failed

        except Exception as e:
            self.logger.error(f"Error handling VNC client: {e}")
            connection_data["error"] = str(e)
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
        
    def _handle_post_auth(self, client_socket: socket.socket, connection_data: Dict[str, Any]) -> None:
        """
        Handle post-authentication interaction
        
        Args:
            client_socket: Client socket object
            connection_data: Dictionary to store connection data for logging
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
                    elif msg_type_num == 2:  # KeyEvent
                        data = client_socket.recv(7)  # Additional 7 bytes
                    elif msg_type_num == 3:  # PointerEvent
                        data = client_socket.recv(5)  # Additional 5 bytes
                    elif msg_type_num == 4:  # ClientCutText
                        # First 3 bytes are padding, then 4 bytes length
                        header = client_socket.recv(7)
                        if len(header) == 7:
                            length = struct.unpack(">I", header[3:7])[0]
                            data = client_socket.recv(length)
                    else:
                        # Unknown message type, read a small amount to prevent blocking
                        data = client_socket.recv(8)
                    
                    # Log interactions for analysis
                    if "interactions" not in connection_data["data"]:
                        connection_data["data"]["interactions"] = []
                        
                    connection_data["data"]["interactions"].append({
                        "timestamp": datetime.datetime.now().isoformat(),
                        "message_type": msg_type_num,
                        "data_hex": data.hex() if data else ""
                    })
                    
                except socket.timeout:
                    # Connection idle, break the loop
                    break
                except Exception as e:
                    self.logger.error(f"Error in post-auth handling: {e}")
                    break
                    
        except Exception as e:
            self.logger.error(f"Error in post-authentication handling: {e}")
            
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
