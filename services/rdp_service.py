#!/usr/bin/env python3
"""
RDP (Remote Desktop Protocol) service emulator for the honeypot system
"""

import socket
import threading
import logging
import datetime
import json
import os
import time
import struct
import random
from typing import Dict, List, Any, Tuple, Optional

from services.base_service import BaseService

class RDPService(BaseService):
    """RDP service emulator for the honeypot"""

    def __init__(self, host: str, port: int, config: Dict[str, Any]):
        """
        Initialize the RDP service

        Args:
            host: Host IP to bind to
            port: Port to listen on
            config: Global configuration dictionary
        """
        super().__init__(host, port, config, "rdp")

        # RDP specific configurations
        self.server_name = self.service_config.get("server_name", "WIN-SERVER2019")
        self.os_version = self.service_config.get("os_version", "Windows Server 2019")

    def handle_client(self, client_socket: socket.socket, address: Tuple[str, int],
                     connection_data: Dict[str, Any]) -> None:
        """
        Handle a client connection to the RDP service

        Args:
            client_socket: Client socket object
            address: Client address tuple (ip, port)
            connection_data: Dictionary to store connection data for logging
        """
        connection_data["data"]["connection_time"] = datetime.datetime.now().isoformat()

        try:
            # Log connection attempt
            self.logger.info(f"RDP connection attempt from {address[0]}:{address[1]}")

            # Receive initial X.224 connection request
            x224_data = self._receive_with_timeout(client_socket, 1024)
            if not x224_data:
                return

            connection_data["data"]["x224_connection_request"] = x224_data.hex()

            # Send X.224 connection confirm
            self._send_x224_connection_confirm(client_socket)

            # Wait for MCS connect initial
            mcs_data = self._receive_with_timeout(client_socket, 1024)
            if not mcs_data:
                return

            connection_data["data"]["mcs_connect_initial"] = mcs_data.hex()

            # Send MCS connect response - indication server is ready
            self._send_mcs_connect_response(client_socket)

            # Simulate secure channel establishment and capability exchange
            # In a real implementation, this would involve a more complex exchange
            time.sleep(0.5)

            # Simulate sending login screen
            self._send_login_screen(client_socket)

            # Wait for credentials
            cred_data = self._receive_with_timeout(client_socket, 1024)
            if not cred_data:
                return

            # Extract username/password (very simplified - in a real scenario this would be encrypted)
            username, password = self._extract_credentials(cred_data)

            # Log the authentication attempt
            auth_data = {
                "username": username,
                "password": password,
                "timestamp": datetime.datetime.now().isoformat()
            }

            if "auth_attempts" not in connection_data["data"]:
                connection_data["data"]["auth_attempts"] = []

            connection_data["data"]["auth_attempts"].append(auth_data)

            self.logger.info(f"RDP authentication attempt from {address[0]} with username '{username}' and password '{password}'")

            # Always deny access (it's a honeypot)
            self._send_login_failed(client_socket)

            # Keep connection open for a bit to simulate a real server
            time.sleep(2)

        except Exception as e:
            self.logger.error(f"Error handling RDP client: {e}")
            connection_data["error"] = str(e)
        finally:
            client_socket.close()

    def _receive_with_timeout(self, client_socket: socket.socket, buffer_size: int, timeout: int = 10) -> bytes:
        """Receive data with timeout"""
        client_socket.settimeout(timeout)
        try:
            return client_socket.recv(buffer_size)
        except socket.timeout:
            self.logger.warning("Socket receive timed out")
            return b""

    def _send_x224_connection_confirm(self, client_socket: socket.socket) -> None:
        """Send X.224 Connection Confirm - simplified version"""
        # Create a simplified X.224 Connection Confirm PDU
        data = bytearray([
            0x03,  # Length indicator
            0x00, 0x00, 0x0D,  # Length
            0x0E,  # X.224 Connection Confirm
            0x00, 0x00, 0x00,  # Unused
            0x00, 0x00,  # Source reference
            0x00, 0x00,  # Destination reference
            0x00   # Class options
        ])

        client_socket.send(data)

    def _send_mcs_connect_response(self, client_socket: socket.socket) -> None:
        """Send MCS Connect Response - simplified version"""
        # Create a very simplified MCS Connect Response
        # Real RDP implementations would have a more complex structure
        data = bytearray([
            0x03, 0x00, 0x00, 0x0B,  # TPKT header
            0x02, 0xF0, 0x80,  # X.224 Data Header
            0x7F, 0x66, 0x5A, 0x01  # MCS Connect Response simplified
        ])

        client_socket.send(data)

    def _send_login_screen(self, client_socket: socket.socket) -> None:
        """Send simulated login screen - in real RDP this would be image data"""
        # In a real implementation, this would send graphical data for the login screen
        # For our honeypot, we'll just send a marker to indicate this is where the login screen would appear
        data = bytearray([
            0x03, 0x00, 0x00, 0x0F,  # TPKT header
            0x02, 0xF0, 0x80,  # X.224 Data Header
            # Dummy data representing login screen command
            0x68, 0x00, 0x01, 0x03, 0xEB, 0x70, 0x12
        ])

        client_socket.send(data)

    def _extract_credentials(self, data: bytes) -> Tuple[str, str]:
        """
        Extract credentials from login data - simplified method

        In a real RDP connection, credentials would be encrypted and properly parsed.
        For the honeypot, we'll simulate credential extraction.

        Args:
            data: Raw data containing RDP login information

        Returns:
            Tuple of (username, password)
        """
        # For demo purposes, use fake credentials from our configuration
        # In a real honeypot, we might try to parse what was actually sent
        credentials = self.get_fake_credentials()

        # Log the raw data for potential later analysis
        self.logger.debug(f"Raw login data (hex): {data.hex()}")

        return credentials["username"], credentials["password"]

    def _send_login_failed(self, client_socket: socket.socket) -> None:
        """Send login failure message"""
        # In a real implementation, this would involve returning error data in proper RDP format
        data = bytearray([
            0x03, 0x00, 0x00, 0x0E,  # TPKT header
            0x02, 0xF0, 0x80,  # X.224 Data Header
            # Dummy data representing login failure
            0x68, 0x00, 0x01, 0x03, 0xEA, 0xFF
        ])

        client_socket.send(data)
