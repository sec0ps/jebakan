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

                # Attempt to extract password (in real VNC this would involve decrypting the challenge response)
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

                # Send authentication failed
                self._send_auth_failed(client_socket)

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
