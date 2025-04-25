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
        connection_data["data"]["connection_time"] = datetime.datetime.now().isoformat()
    
        try:
            self._handle_prelogin(client_socket)
            login_packet = self._receive_tds_packet(client_socket)
            if not login_packet:
                return
    
            username, password = self._parse_login_packet(login_packet)
    
            auth_data = {
                "username": username,
                "password": password,
                "timestamp": datetime.datetime.now().isoformat()
            }
    
            connection_data["data"].setdefault("auth_attempts", []).append(auth_data)
    
            self.logger.info(f"MSSQL authentication attempt from {address[0]} with username '{username}' and password '{password}'")
    
            valid_creds = self.service_config.get("credentials", [])
            if any(c["username"] == username and c["password"] == password for c in valid_creds):
                self._send_login_success(client_socket)
                self._sql_interaction_loop(client_socket, address, connection_data)
            else:
                self._send_login_error(client_socket)
    
        except Exception as e:
            self.logger.error(f"Error handling MSSQL client: {e}")
            connection_data["error"] = str(e)
        finally:
            client_socket.close()

    def _handle_prelogin(self, client_socket: socket.socket) -> None:
        prelogin_packet = self._receive_tds_packet(client_socket)
        if not prelogin_packet:
            return
    
        response = bytearray()
    
        # Version
        response.extend(b'\x00')            # VERSION token
        response.extend(b'\x00\x08')        # Offset
        response.extend(b'\x00\x06')        # Length
    
        # Encryption
        response.extend(b'\x01')            # ENCRYPTION token
        response.extend(b'\x00\x0E')
        response.extend(b'\x00\x01')
    
        # Terminator
        response.extend(b'\xFF')
    
        # Data section
        # Fake server version: 15.0.2000.5 (SQL Server 2019)
        response.extend(struct.pack(">I", 0x0F000000))  # Major.Minor
        response.extend(struct.pack(">H", 2000))        # Build
        response.extend(b'\x05')                        # Sub-build or patch
        response.extend(b'\x02')                        # ENCRYPT login only
    
        self._send_tds_packet(client_socket, response, 0x04)

    def _parse_login_packet(self, packet: bytes) -> Tuple[str, str]:
        try:
            pos = 36
            pos += 4  # Skip hostname offset
    
            def safe_unpack(offset):
                if offset + 2 > len(packet):
                    raise ValueError(f"Packet too short to unpack at offset {offset}")
                return struct.unpack("<H", packet[offset:offset + 2])[0]
    
            username_offset = safe_unpack(pos)
            pos += 2
            username_len = safe_unpack(pos)
            pos += 2
    
            password_offset = safe_unpack(pos)
            pos += 2
            password_len = safe_unpack(pos)
            pos += 2
    
            username_bytes = packet[username_offset:username_offset + username_len * 2]
            password_bytes = packet[password_offset:password_offset + password_len * 2]
    
            username = username_bytes.decode("utf-16-le", errors="ignore")
            password = self._decode_tds_password(password_bytes)
    
            self.logger.debug(f"Extracted username: {username}")
            self.logger.debug(f"Decoded password: {password}")
            return username, password
    
        except Exception as e:
            self.logger.error(f"Exception in _parse_login_packet: {e}")
            return "", ""
    
    def _decode_tds_password(self, data: bytes) -> str:
        result = bytearray()
        for b in data:
            xored = b ^ 0xA5
            swapped = ((xored & 0x0F) << 4) | ((xored & 0xF0) >> 4)
            result.append(swapped)
        try:
            return result.decode('utf-16-le')
        except UnicodeDecodeError:
            return "<decode error>"

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
            #self.logger.debug(f"Sending TDS packet (type {packet_type}): {header.hex()} {data.hex()}")
            self.logger.debug(f"TDS SEND: type={packet_type}, len={len(data)} | "f"header={header.hex()} | data={data.hex()}")
            client_socket.sendall(header + data)

        except Exception as e:
            self.logger.error(f"Error sending TDS packet: {e}")

    def _send_login_success(self, client_socket: socket.socket) -> None:
        """Simulate a successful MSSQL login."""
        token = 0xAD  # Hypothetical success token
        packet = bytearray()
        packet.append(token)
        packet.extend(b'\x00\x00\x00\x00')  # Dummy data
        self._send_tds_packet(client_socket, packet, 0x04)

    def _sql_interaction_loop(self, client_socket: socket.socket, address: Tuple[str, int],
                              connection_data: Dict[str, Any]) -> None:
        try:
            self.logger.info(f"Sending SQL login banner to {address[0]}")
            headers, rows = self._generate_fake_sql_response("welcome")
            self._send_fake_result(client_socket, headers, rows)
    
            while True:
                command = self._receive_sql_command(client_socket)
                if not command:
                    break
    
                connection_data["data"].setdefault("sql_commands", []).append({
                    "timestamp": datetime.datetime.now().isoformat(),
                    "command": command
                })
    
                self.logger.info(f"SQL command from {address[0]}: {command}")
    
                headers, rows = self._generate_fake_sql_response(command)
                self._send_fake_result(client_socket, headers, rows)
    
        except Exception as e:
            self.logger.error(f"Error in SQL interaction: {e}")

    def _receive_sql_command(self, client_socket: socket.socket) -> str:
        data = self._receive_tds_packet(client_socket)
        return data.decode('utf-8', errors='ignore').strip() if data else ""
    
    def _send_fake_result(self, client_socket: socket.socket, headers: List[str], rows: List[List[str]]) -> None:
        try:
            packet = bytearray()
    
            # --- COLMETADATA ---
            packet.append(0x81)  # COLMETADATA token
            packet.extend(struct.pack("<H", 1))  # 1 column
    
            # Column metadata for NVARCHAR
            col_name = headers[0]
            col_name_encoded = col_name.encode('utf-8')
    
            packet.extend(b'\x00\x00')       # user type + flags
            packet.append(0xA7)              # NVARCHAR type
            packet.append(100)               # max length
    
            # Dummy 5-byte collation (LCID + flags) — tools expect 5 bytes
            packet.extend(b'\x09\x04\xD0\x00\x34')
    
            packet.append(len(col_name_encoded))
            packet.extend(col_name_encoded)
    
            # --- ROW(s) ---
            for row in rows:
                packet.append(0xD1)  # ROW token
    
                # Encode string as UTF-16LE
                value_utf16 = row[0].encode('utf-16le')
                packet.append(len(value_utf16))  # length in bytes
                packet.extend(value_utf16)
    
            # --- DONE ---
            packet.append(0xFD)
            packet.extend(struct.pack("<H", 0))   # status
            packet.extend(struct.pack("<H", 0))   # curcmd
            packet.extend(struct.pack("<Q", len(rows)))  # row count
    
            self._send_tds_packet(client_socket, packet, 0x04)
    
        except Exception as e:
            self.logger.error(f"Error sending hardened result: {e}")

    def _generate_fake_sql_response(self, command: str) -> Tuple[List[str], List[List[str]]]:
        command_lower = command.lower().strip()
    
        if "@@version" in command_lower:
            return (
                ["version"],
                [["Microsoft SQL Server 2019 (RTM-CU21) - 15.0.4198.2 (X64)"]]
            )
    
        elif "@@servername" in command_lower:
            return (
                ["name"],
                [[self.server_name]]
            )
    
        elif "is_srvrolemember" in command_lower and "sysadmin" in command_lower:
            return (
                ["IsSysAdmin"],
                [["1"]]
            )
    
        elif "select name from sys.databases" in command_lower:
            return (
                ["name", "database_id", "create_date"],
                [
                    ["master", "1", "2022-01-01 12:00:00"],
                    ["tempdb", "2", "2022-01-01 12:00:00"],
                    ["model", "3", "2022-01-01 12:00:00"],
                    ["finance", "4", "2023-03-11 09:15:22"],
                    ["research", "5", "2023-06-01 10:44:08"]
                ]
            )
    
        elif "from sys.tables" in command_lower:
            return (
                ["name", "object_id", "schema_id", "create_date"],
                [
                    ["users", "1001", "1", "2023-03-20 14:12:00"],
                    ["accounts", "1002", "1", "2023-03-22 11:09:00"],
                    ["invoices", "1003", "1", "2023-04-01 09:45:00"],
                    ["logs", "1004", "1", "2023-04-07 15:28:00"]
                ]
            )
    
        elif "information_schema.columns" in command_lower:
            return (
                ["table_name", "column_name", "data_type"],
                [
                    ["users", "id", "int"],
                    ["users", "username", "nvarchar"],
                    ["users", "password", "nvarchar"],
                    ["accounts", "account_id", "int"],
                    ["accounts", "balance", "decimal"]
                ]
            )
    
        elif "from users" in command_lower:
            return (
                ["id", "username", "password", "role"],
                [
                    ["1", "alice", "P@ssw0rd!", "admin"],
                    ["2", "bob", "hunter2", "user"],
                    ["3", "charlie", "letmein", "analyst"],
                    ["4", "eve", "123qwe", "guest"]
                ]
            )
    
        elif "xp_cmdshell" in command_lower:
            return (
                ["msg"],
                [["Access denied. xp_cmdshell is disabled by administrator policy."]]
            )
    
        elif "select" in command_lower and "from" in command_lower:
            return (
                ["result"],
                [["Query executed. 1 row returned."]]
            )
    
        return (
            ["msg"],
            [["Command completed successfully."]]
        )
