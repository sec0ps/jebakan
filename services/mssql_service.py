#!/usr/bin/env python3
"""
Microsoft SQL Server (MSSQL) service emulator for the honeypot system
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

class MSSQLService(BaseService):
    """Microsoft SQL Server service emulator for the honeypot"""

    def __init__(self, host: str, port: int, config: Dict[str, Any]):
        """
        Initialize the MSSQL service

        Args:
            host: Host IP to bind to
            port: Port to listen on
            config: Global configuration dictionary
        """
        super().__init__(host, port, config, "mssql")

        # MSSQL specific configurations
        self.server_version = self.service_config.get("server_version", "Microsoft SQL Server 2019")
        self.server_name = self.service_config.get("server_name", "SQLSERVER")
        self.instance_name = self.service_config.get("instance_name", "MSSQLSERVER")

    def handle_client(self, client_socket: socket.socket, address: Tuple[str, int],
                     connection_data: Dict[str, Any]) -> None:
        """
        Handle a client connection to the MSSQL service

        Args:
            client_socket: Client socket object
            address: Client address tuple (ip, port)
            connection_data: Dictionary to store connection data for logging
        """
        # Record initial connection timestamp
        connection_data["data"]["connection_time"] = datetime.datetime.now().isoformat()

        try:
            # Send pre-login response
            self._handle_prelogin(client_socket)

            # Receive login packet
            login_packet = self._receive_tds_packet(client_socket)
            if not login_packet:
                return

            # Parse login packet to extract credentials
            username, password = self._parse_login_packet(login_packet)

            # Log the authentication attempt
            auth_data = {
                "username": username,
                "password_hash": hashlib.md5(password.encode()).hexdigest() if password else None,
                "timestamp": datetime.datetime.now().isoformat()
            }

            if "auth_attempts" not in connection_data["data"]:
                connection_data["data"]["auth_attempts"] = []

            connection_data["data"]["auth_attempts"].append(auth_data)

            # Log the authentication attempt
            self.logger.info(f"MSSQL authentication attempt from {address[0]} with username '{username}' and password '{password}'")

            # Send authentication error (honeypot always rejects)
            self._send_login_error(client_socket)

        except Exception as e:
            self.logger.error(f"Error handling MSSQL client: {e}")
            connection_data["error"] = str(e)
        finally:
            client_socket.close()

    def _handle_prelogin(self, client_socket: socket.socket) -> None:
        """
        Handle MSSQL pre-login negotiation

        Args:
            client_socket: Client socket object
        """
        # Receive pre-login packet
        prelogin_packet = self._receive_tds_packet(client_socket)
        if not prelogin_packet:
            return

        # Build pre-login response
        response = bytearray()

        # Add VERSION token
        response.extend(b'\x00')  # TOKEN = VERSION
        response.extend(b'\x00\x08')  # OFFSET
        response.extend(b'\x00\x06')  # LENGTH

        # Add ENCRYPTION token
        response.extend(b'\x01')  # TOKEN = ENCRYPTION
        response.extend(b'\x00\x0E')  # OFFSET
        response.extend(b'\x00\x01')  # LENGTH

        # Add INSTOPT token
        response.extend(b'\x02')  # TOKEN = INSTOPT
        response.extend(b'\x00\x0F')  # OFFSET
        response.extend(b'\x00\x01')  # LENGTH

        # Add THREADID token
        response.extend(b'\x03')  # TOKEN = THREADID
        response.extend(b'\x00\x10')  # OFFSET
        response.extend(b'\x00\x04')  # LENGTH

        # Add MARS token
        response.extend(b'\x04')  # TOKEN = MARS
        response.extend(b'\x00\x14')  # OFFSET
        response.extend(b'\x00\x01')  # LENGTH

        # Add TERMINATOR token
        response.extend(b'\xFF')

        # Add VERSION value: Major (4 bytes), Minor (4 bytes), BuildNumber (2 bytes)
        response.extend(b'\x0C\x00\x0A\x00')  # Version 12.0.10.0
        response.extend(b'\x00\x00')  # Build number

        # Add ENCRYPTION value: 2 = Encrypt login only
        response.extend(b'\x02')

        # Add INSTOPT value: 0 = No instance name
        response.extend(b'\x00')

        # Add THREADID value
        response.extend(struct.pack("<I", random.randint(1, 0xFFFFFFFF)))

        # Add MARS value: 0 = MARS disabled
        response.extend(b'\x00')

        # Send the packet
        self._send_tds_packet(client_socket, response, 0x04)  # 0x04 = TDS response

    def _parse_login_packet(self, packet: bytes) -> Tuple[str, str]:
        """
        Parse TDS login packet to extract credentials

        Args:
            packet: Login packet data

        Returns:
            Tuple of (username, password)
        """
        try:
            # Login7 packet format is very complex
            # Simplified parsing to extract only username and password

            # Skip fixed-length part of the header (36 bytes)
            pos = 36

            # Get variable length positions
            # Offset to hostname (2 bytes)
            pos += 2
            # Hostname length (2 bytes)
            pos += 2

            # Offset to username (2 bytes)
            username_offset = struct.unpack("<H", packet[pos:pos+2])[0]
            pos += 2
            # Username length (2 bytes)
            username_len = struct.unpack("<H", packet[pos:pos+2])[0]
            pos += 2

            # Offset to password (2 bytes)
            password_offset = struct.unpack("<H", packet[pos:pos+2])[0]
            pos += 2
            # Password length (2 bytes)
            password_len = struct.unpack("<H", packet[pos:pos+2])[0]
            pos += 2

            # Extract username
            username_bytes = packet[username_offset:username_offset+username_len*2]
            username = username_bytes.decode('utf-16-le')

            # Extract password - in actual TDS it's obfuscated, but for simplicity we'll assume plaintext
            if password_len > 0:
                password_bytes = packet[password_offset:password_offset+password_len*2]
                # In real TDS protocol, password would be obfuscated
                # For the honeypot, we don't implement full obfuscation
                password = "********"  # Placeholder for extracted password
            else:
                password = ""

            return username, password

        except Exception as e:
            self.logger.error(f"Error parsing login packet: {e}")
            return "", ""

    def _send_login_error(self, client_socket: socket.socket) -> None:
        """
        Send MSSQL login error response

        Args:
            client_socket: Client socket object
        """
        # Build an error message packet
        error_message = "Login failed for user. The user is not associated with a trusted SQL Server connection."

        # TDS token for error message
        token = 0xAA  # ERROR token

        # Create the error message packet
        packet = bytearray()
        packet.append(token)  # Token type

        # Error number (4 bytes) - 18456 is "Login failed"
        packet.extend(struct.pack("<I", 18456))

        # State (1 byte)
        packet.append(1)

        # Class (1 byte) - 14 is login error
        packet.append(14)

        # Message length (2 bytes, in Unicode characters)
        packet.extend(struct.pack("<H", len(error_message)))

        # Message (Unicode)
        packet.extend(error_message.encode('utf-16-le'))

        # Server name length (1 byte)
        packet.append(len(self.server_name))

        # Server name
        packet.extend(self.server_name.encode('utf-8'))

        # Procedure name length (1 byte)
        packet.append(0)

        # Line number (4 bytes)
        packet.extend(struct.pack("<I", 1))

        # Send the error packet
        self._send_tds_packet(client_socket, packet, 0x04)  # 0x04 = TDS response

    def _receive_tds_packet(self, client_socket: socket.socket) -> bytes:
        """
        Receive a TDS packet

        Args:
            client_socket: Client socket object

        Returns:
            Packet data (without header)
        """
        try:
            # Receive TDS packet header (8 bytes)
            header = client_socket.recv(8)
            if len(header) < 8:
                return b""

            # Parse packet length (2 bytes at offset 2)
            length = struct.unpack(">H", header[2:4])[0]

            # Receive packet data
            data = b""
            remaining = length - 8  # Subtract header size

            while remaining > 0:
                chunk = client_socket.recv(remaining)
                if not chunk:
                    break
                data += chunk
                remaining -= len(chunk)

            return data

        except Exception as e:
            self.logger.error(f"Error receiving TDS packet: {e}")
            return b""

    def _send_tds_packet(self, client_socket: socket.socket, data: bytes, packet_type: int) -> None:
        """
        Send a TDS packet

        Args:
            client_socket: Client socket object
            data: Packet data
            packet_type: TDS packet type
        """
        try:
            # Calculate total packet length
            length = len(data) + 8  # Data + header

            # Create TDS packet header (8 bytes)
            header = bytearray()
            header.append(packet_type)  # Packet type
            header.append(0x01)  # Status: EOM (End Of Message)
            header.extend(struct.pack(">H", length))  # Length (big-endian)
            header.extend(b'\x00\x00')  # SPID (Server Process ID)
            header.append(0x00)  # Packet ID
            header.append(0x00)  # Window

            # Send packet header and data
            client_socket.sendall(header + data)

        except Exception as e:
            self.logger.error(f"Error sending TDS packet: {e}")
