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
MySQL service emulator for the honeypot system
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

class MySQLService(BaseService):
    """MySQL service emulator for the honeypot"""

    def __init__(self, host: str, port: int, config: Dict[str, Any]):
        """
        Initialize the MySQL service

        Args:
            host: Host IP to bind to
            port: Port to listen on
            config: Global configuration dictionary
        """
        super().__init__(host, port, config, "mysql")

        # MySQL specific configurations
        self.server_version = self.service_config.get("server_version", "5.7.34-log")
        self.protocol_version = 10
        self.connection_id = 0
        self.auth_plugin = "mysql_native_password"

        # Random salt for authentication
        self.salt = os.urandom(20)

    def handle_client(self, client_socket: socket.socket, address: Tuple[str, int],
                     connection_data: Dict[str, Any]) -> None:
        """
        Handle a client connection to the MySQL service

        Args:
            client_socket: Client socket object
            address: Client address tuple (ip, port)
            connection_data: Dictionary to store connection data for logging
        """
        # Increment connection ID
        self.connection_id += 1
        connection_id = self.connection_id

        # Record initial connection timestamp
        connection_data["data"]["connection_time"] = datetime.datetime.now().isoformat()

        try:
            # Send server greeting
            self._send_server_greeting(client_socket)

            # Receive authentication response
            auth_response = self._receive_packet(client_socket)
            if not auth_response:
                return

            # Parse authentication data
            username, password = self._parse_auth_packet(auth_response)

            # Log the authentication attempt
            auth_data = {
                "username": username,
                "password_hash": self._get_password_hash(password) if password else None,
                "timestamp": datetime.datetime.now().isoformat()
            }

            if "auth_attempts" not in connection_data["data"]:
                connection_data["data"]["auth_attempts"] = []

            connection_data["data"]["auth_attempts"].append(auth_data)

            # Check credentials (always reject in honeypot)
            self.logger.info(f"MySQL authentication attempt from {address[0]} with username '{username}'")

            # Send authentication result (intentionally deny access)
            self._send_auth_result(client_socket, False, "Access denied for user '{}'@'{}' (using password: YES)".format(
                username, address[0]))

            # Additional command interactions would go here if we were allowing successful auth

        except Exception as e:
            self.logger.error(f"Error handling MySQL client: {e}")
            connection_data["error"] = str(e)
        finally:
            client_socket.close()

    def _send_server_greeting(self, client_socket: socket.socket) -> None:
        """
        Send MySQL server greeting packet

        Args:
            client_socket: Client socket object
        """
        # https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html
        data = bytearray()

        # Protocol version
        data.append(self.protocol_version)

        # Server version (null-terminated)
        data.extend(self.server_version.encode())
        data.append(0)

        # Connection ID (4 bytes)
        data.extend(struct.pack("<I", self.connection_id))

        # Auth plugin data part 1 (8 bytes)
        data.extend(self.salt[:8])

        # Filler byte
        data.append(0)

        # Capability flags (4 bytes)
        # Only include the basic capabilities
        capabilities = (
            0x00000001 |  # CLIENT_LONG_PASSWORD
            0x00000200 |  # CLIENT_PROTOCOL_41
            0x00008000 |  # CLIENT_SECURE_CONNECTION
            0x00010000    # CLIENT_PLUGIN_AUTH
        )
        data.extend(struct.pack("<I", capabilities))

        # Character set
        data.append(33)  # utf8_general_ci

        # Status flags (2 bytes)
        data.extend(struct.pack("<H", 2))  # SERVER_STATUS_AUTOCOMMIT

        # Capability flags upper 2 bytes
        data.extend(struct.pack("<H", capabilities >> 16))

        # Length of auth plugin data (should be 21 for mysql_native_password)
        data.append(21)

        # Reserved (10 bytes of 0)
        data.extend(bytes(10))

        # Auth plugin data part 2 (at least 12 bytes)
        # Ensure the salt is 20 bytes or more for part 1 + part 2
        data.extend(self.salt[8:])
        data.append(0)  # Null terminator

        # Auth plugin name (null-terminated)
        data.extend(self.auth_plugin.encode())
        data.append(0)

        # Send packet
        self._send_packet(client_socket, data, 0)  # Sequence ID 0

    def _parse_auth_packet(self, packet: bytes) -> Tuple[str, Optional[bytes]]:
        """
        Parse authentication packet from client

        Args:
            packet: Raw packet data

        Returns:
            Tuple of (username, password) where password may be None
        """
        try:
            # Skip capability flags (4 bytes), max packet size (4 bytes), and character set (1 byte)
            pos = 9

            # Skip reserved bytes (23 bytes)
            pos += 23

            # Extract username (null-terminated string)
            username_end = packet.find(b'\0', pos)
            username = packet[pos:username_end].decode('utf-8', errors='ignore')
            pos = username_end + 1

            # Extract password hash if present
            password = None
            if pos < len(packet):
                # Get length of password hash
                auth_len = packet[pos]
                pos += 1

                if auth_len > 0 and pos + auth_len <= len(packet):
                    password = packet[pos:pos + auth_len]

            return username, password

        except Exception as e:
            self.logger.error(f"Error parsing auth packet: {e}")
            return "", None

    def _send_auth_result(self, client_socket: socket.socket, success: bool, message: str = "") -> None:
        """
        Send authentication result packet

        Args:
            client_socket: Client socket object
            success: True if authentication was successful, False otherwise
            message: Error message (only for failed auth)
        """
        if success:
            # Send OK packet
            data = bytearray()
            data.append(0x00)  # OK packet header
            data.append(0x00)  # Affected rows (0)
            data.append(0x00)  # Last insert ID (0)
            data.extend(struct.pack("<H", 2))  # Server status (autocommit)
            data.extend(struct.pack("<H", 0))  # Warnings (0)

            self._send_packet(client_socket, data, 2)  # Sequence ID 2
        else:
            # Send error packet
            data = bytearray()
            data.append(0xFF)  # Error packet header
            data.extend(struct.pack("<H", 1045))  # Error code (1045 = access denied)
            data.append(0x23)  # SQL state marker
            data.extend(b'28000')  # SQL state
            data.extend(message.encode())  # Error message

            self._send_packet(client_socket, data, 2)  # Sequence ID 2

    def _send_packet(self, client_socket: socket.socket, data: bytes, sequence_id: int) -> None:
        """
        Send a MySQL packet

        Args:
            client_socket: Client socket object
            data: Packet data
            sequence_id: Sequence ID
        """
        # Calculate packet length
        length = len(data)

        # Create packet header (4 bytes: 3 for length, 1 for sequence ID)
        header = bytearray()
        header.extend(struct.pack("<I", length)[:3])  # Length (3 bytes)
        header.append(sequence_id)  # Sequence ID (1 byte)

        # Send packet header and data
        client_socket.sendall(header + data)

    def _receive_packet(self, client_socket: socket.socket) -> bytes:
        """
        Receive a MySQL packet

        Args:
            client_socket: Client socket object

        Returns:
            Packet data (without header)
        """
        # Receive packet header (4 bytes)
        header = client_socket.recv(4)
        if len(header) < 4:
            return b""

        # Parse packet length (first 3 bytes)
        length = struct.unpack("<I", header[:3] + b'\x00')[0]

        # Receive packet data
        data = b""
        while len(data) < length:
            chunk = client_socket.recv(length - len(data))
            if not chunk:
                break
            data += chunk

        return data

    def _get_password_hash(self, password: bytes) -> str:
        """
        Convert password hash to hex string for logging

        Args:
            password: Raw password hash

        Returns:
            Hex representation of password hash
        """
        return password.hex() if password else ""
