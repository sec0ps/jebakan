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

    def __init__(self, host: str, port: int, config: Dict[str, Any], unified_logger=None):
        """
        Initialize the MySQL service
    
        Args:
            host: Host IP to bind to
            port: Port to listen on
            config: Global configuration dictionary
            unified_logger: Unified logger instance for centralized logging
        """
        super().__init__(host, port, config, "mysql")
    
        # Store unified logger instance
        self.unified_logger = unified_logger
    
        # MySQL specific configurations
        self.server_version = self.service_config.get("server_version", "5.7.34-log")
        self.protocol_version = 10
        self.connection_id = 0
        self.auth_plugin = "mysql_native_password"
    
        # Generate proper length salt for authentication (20 bytes total: 8 + 12)
        self.salt = os.urandom(8) + os.urandom(12)

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
        
        # Log connection attempt to unified logger
        if self.unified_logger:
            self.unified_logger.log_attack(
                service="mysql",
                attacker_ip=address[0],
                attacker_port=address[1],
                command="connection_attempt",
                additional_data={
                    "connection_id": connection_id,
                    "timestamp": datetime.datetime.now().isoformat()
                }
            )
    
        try:
            # Send server greeting
            self._send_server_greeting(client_socket)
            
            # Log server greeting to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="mysql",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="mysql_greeting_sent",
                    additional_data={
                        "connection_id": connection_id,
                        "server_version": self.server_version
                    }
                )
    
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
    
            self.logger.info(f"MySQL authentication attempt from {address[0]} with username '{username}'")
            
            # Log authentication attempt to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="mysql",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="login_attempt",
                    additional_data={
                        "username": username,
                        "password_hash": self._get_password_hash(password) if password else None,
                        "connection_id": connection_id
                    }
                )
    
            # Always allow authentication for honeypot purposes
            self._send_auth_result(client_socket, True)
            self.logger.info(f"MySQL authentication successful for user '{username}' from {address[0]}")
            
            # Log successful authentication to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="mysql",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="login_success",
                    additional_data={
                        "username": username,
                        "connection_id": connection_id
                    }
                )
            
            # Handle MySQL commands after successful auth
            self._handle_mysql_commands(client_socket, address, connection_data)
    
        except Exception as e:
            self.logger.error(f"Error handling MySQL client: {e}")
            connection_data["error"] = str(e)
            
            # Log error to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="mysql",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="error",
                    additional_data={
                        "error": str(e),
                        "connection_id": connection_id
                    }
                )
        finally:
            client_socket.close()

    def _send_server_greeting(self, client_socket: socket.socket) -> None:
        """
        Send MySQL server greeting packet
    
        Args:
            client_socket: Client socket object
        """
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
    
        # Capability flags - lower 2 bytes
        capabilities = (
            0x00000001 |  # CLIENT_LONG_PASSWORD
            0x00000200 |  # CLIENT_PROTOCOL_41
            0x00008000 |  # CLIENT_SECURE_CONNECTION
            0x00080000    # CLIENT_PLUGIN_AUTH
        )
        data.extend(struct.pack("<H", capabilities & 0xFFFF))
    
        # Character set
        data.append(33)  # utf8_general_ci
    
        # Status flags (2 bytes)
        data.extend(struct.pack("<H", 2))  # SERVER_STATUS_AUTOCOMMIT
    
        # Capability flags upper 2 bytes
        data.extend(struct.pack("<H", (capabilities >> 16) & 0xFFFF))
    
        # Length of auth plugin data (must be 21 for mysql_native_password)
        data.append(21)
    
        # Reserved (10 bytes of 0)
        data.extend(bytes(10))
    
        # Auth plugin data part 2 (remaining 12 bytes + null terminator)
        data.extend(self.salt[8:20])
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
            data.extend(struct.pack("<H", 0x0002))  # Server status (autocommit)
            data.extend(struct.pack("<H", 0))  # Warnings (0)
            
            # MySQL 5.7+ expects additional data in the OK packet
            data.extend(b'')  # Info string (empty)
    
            self._send_packet(client_socket, data, 2)  # Sequence ID 2
        else:
            # Send error packet
            data = bytearray()
            data.append(0xFF)  # Error packet header
            data.extend(struct.pack("<H", 1045))  # Error code (1045 = access denied)
            data.append(0x23)  # SQL state marker '#'
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
    
    def _send_query_result(self, client_socket: socket.socket, rows: List[List[str]], columns: List[str]) -> None:
        """
        Send a query result set to the client
        """
        # Column count packet
        col_count = bytearray()
        col_count.append(len(columns))
        self._send_packet(client_socket, col_count, 1)
        
        # Column definitions
        for i, col_name in enumerate(columns):
            col_def = bytearray()
            # Catalog (lenenc string)
            col_def.append(3)
            col_def.extend(b'def')
            # Schema (lenenc string)
            col_def.append(0)
            # Table (lenenc string)
            col_def.append(0)
            # Original table (lenenc string)
            col_def.append(0)
            # Name (lenenc string)
            col_def.append(len(col_name))
            col_def.extend(col_name.encode())
            # Original name (lenenc string)
            col_def.append(len(col_name))
            col_def.extend(col_name.encode())
            # Next length (always 0x0c)
            col_def.append(0x0c)
            # Character set (utf8)
            col_def.extend(struct.pack("<H", 33))
            # Column length
            col_def.extend(struct.pack("<I", 255))
            # Column type (VARCHAR)
            col_def.append(253)
            # Flags
            col_def.extend(struct.pack("<H", 0))
            # Decimals
            col_def.append(0)
            # Filler
            col_def.extend(b'\x00\x00')
            
            self._send_packet(client_socket, col_def, i+2)
        
        # EOF packet
        eof = bytearray()
        eof.append(0xFE)  # EOF header
        eof.extend(struct.pack("<H", 0))  # Warnings
        eof.extend(struct.pack("<H", 0x0002))  # Server status
        self._send_packet(client_socket, eof, len(columns)+2)
        
        # Row data
        for i, row in enumerate(rows):
            row_data = bytearray()
            for value in row:
                if value is None:
                    row_data.append(0xFB)  # NULL
                else:
                    value_bytes = str(value).encode()
                    if len(value_bytes) < 251:
                        row_data.append(len(value_bytes))
                    else:
                        row_data.append(0xFC)
                        row_data.extend(struct.pack("<H", len(value_bytes)))
                    row_data.extend(value_bytes)
            self._send_packet(client_socket, row_data, len(columns)+3+i)
        
        # EOF packet
        eof = bytearray()
        eof.append(0xFE)  # EOF header
        eof.extend(struct.pack("<H", 0))  # Warnings
        eof.extend(struct.pack("<H", 0x0002))  # Server status
        self._send_packet(client_socket, eof, len(columns)+3+len(rows))

    def _handle_mysql_commands(self, client_socket: socket.socket, address: Tuple[str, int],
                              connection_data: Dict[str, Any]) -> None:
        """
        Handle MySQL commands after successful authentication
        
        Args:
            client_socket: Client socket object
            address: Client address tuple (ip, port)
            connection_data: Dictionary to store connection data for logging
        """
        while True:
            try:
                cmd_packet = self._receive_packet(client_socket)
                if not cmd_packet:
                    break
                    
                # Parse command type
                cmd_type = cmd_packet[0]
                
                if cmd_type == 0x03:  # COM_QUERY
                    query = cmd_packet[1:].decode('utf-8', errors='ignore')
                    self.logger.info(f"MySQL query from {address[0]}: {query}")
                    
                    # Store query in connection data
                    if "queries" not in connection_data["data"]:
                        connection_data["data"]["queries"] = []
                    connection_data["data"]["queries"].append({
                        "timestamp": datetime.datetime.now().isoformat(),
                        "query": query
                    })
                    
                    # Log query to unified logger
                    if self.unified_logger:
                        self.unified_logger.log_attack(
                            service="mysql",
                            attacker_ip=address[0],
                            attacker_port=address[1],
                            command="mysql_query",
                            additional_data={
                                "query": query,
                                "timestamp": datetime.datetime.now().isoformat()
                            }
                        )
                    
                    # Check for sensitive queries and log them specially
                    lower_query = query.lower()
                    if "password" in lower_query or "authentication_string" in lower_query or "user" in lower_query:
                        if self.unified_logger:
                            self.unified_logger.log_attack(
                                service="mysql",
                                attacker_ip=address[0],
                                attacker_port=address[1],
                                command="sensitive_query",
                                additional_data={
                                    "query": query,
                                    "sensitivity": "high",
                                    "reason": "password_access"
                                }
                            )
                    
                    # Handle specific queries for hashdump
                    if "@@version" in query.lower():
                        self._send_query_result(client_socket, [["5.7.34-log"]], ["@@version"])
                    elif "select user,authentication_string from mysql.user" in query.lower():
                        # Modern MySQL (5.7+) uses authentication_string
                        columns = ["user", "authentication_string"]
                        rows = [
                            ["root", "*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"],  # hash for 'root'
                            ["admin", "*4ACFE3202A5FF5CF467898FC58AAB1D615029441"],  # hash for 'admin'
                            ["backup", "*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9"],  # hash for '123456'
                            ["developer", "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"],  # hash for 'password'
                            ["web", "*97E7471D816A37E38510728AEA47440F9C6E2585"],  # hash for 'web123'
                            ["dbadmin", "*E6CC90B878B948C35E92B003C792C46C58C4AF40"],  # hash for 'qwerty'
                            ["finance", "*2AC9CB7DC02B3C0083EB70898E549B63"],  # hash for 'money'
                        ]
                        self._send_query_result(client_socket, rows, columns)
                        
                        # Log password hash dump to unified logger
                        if self.unified_logger:
                            self.unified_logger.log_attack(
                                service="mysql",
                                attacker_ip=address[0],
                                attacker_port=address[1],
                                command="password_hash_dump",
                                additional_data={
                                    "query": query,
                                    "users_count": len(rows)
                                }
                            )
                    elif "select user,password from mysql.user" in query.lower():
                        # Legacy MySQL uses password column
                        columns = ["user", "password"]
                        rows = [
                            ["root", "*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"],  # hash for 'root'
                            ["admin", "*4ACFE3202A5FF5CF467898FC58AAB1D615029441"],  # hash for 'admin'
                            ["backup", "*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9"],  # hash for '123456'
                            ["developer", "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"],  # hash for 'password'
                            ["web", "*97E7471D816A37E38510728AEA47440F9C6E2585"],  # hash for 'web123'
                        ]
                        self._send_query_result(client_socket, rows, columns)
                        
                        # Log password hash dump to unified logger
                        if self.unified_logger:
                            self.unified_logger.log_attack(
                                service="mysql",
                                attacker_ip=address[0],
                                attacker_port=address[1],
                                command="password_hash_dump",
                                additional_data={
                                    "query": query,
                                    "users_count": len(rows)
                                }
                            )
                    elif "show databases" in query.lower():
                        databases = [
                            ["information_schema"], 
                            ["mysql"], 
                            ["performance_schema"], 
                            ["sys"],
                            ["production"], 
                            ["wordpress"],
                            ["customers"],
                            ["finance"],
                            ["hr"]
                        ]
                        self._send_query_result(client_socket, databases, ["Database"])
                        
                        # Log database enumeration to unified logger
                        if self.unified_logger:
                            self.unified_logger.log_attack(
                                service="mysql",
                                attacker_ip=address[0],
                                attacker_port=address[1],
                                command="database_enumeration",
                                additional_data={
                                    "databases": [db[0] for db in databases]
                                }
                            )
                    elif "show tables" in query.lower():
                        tables = [
                            ["users"], 
                            ["credentials"], 
                            ["payments"], 
                            ["accounts"],
                            ["sensitive_data"]
                        ]
                        self._send_query_result(client_socket, tables, ["Tables_in_mysql"])
                        
                        # Log table enumeration to unified logger
                        if self.unified_logger:
                            self.unified_logger.log_attack(
                                service="mysql",
                                attacker_ip=address[0],
                                attacker_port=address[1],
                                command="table_enumeration",
                                additional_data={
                                    "tables": [table[0] for table in tables]
                                }
                            )
                    elif "select" in query.lower() and "from" in query.lower():
                        # Generic select query - send empty result
                        self._send_query_result(client_socket, [], ["column1"])
                    else:
                        # Send OK packet for other queries
                        self._send_ok_packet(client_socket)
                        
                elif cmd_type == 0x01:  # COM_QUIT
                    # Log quit command to unified logger
                    if self.unified_logger:
                        self.unified_logger.log_attack(
                            service="mysql",
                            attacker_ip=address[0],
                            attacker_port=address[1],
                            command="mysql_quit",
                            additional_data={
                                "timestamp": datetime.datetime.now().isoformat()
                            }
                        )
                    break
                elif cmd_type == 0x02:  # COM_INIT_DB
                    db_name = cmd_packet[1:].decode('utf-8', errors='ignore')
                    # Log database initialization to unified logger
                    if self.unified_logger:
                        self.unified_logger.log_attack(
                            service="mysql",
                            attacker_ip=address[0],
                            attacker_port=address[1],
                            command="mysql_init_db",
                            additional_data={
                                "database": db_name
                            }
                        )
                    self._send_ok_packet(client_socket)
                else:
                    # Log unknown command to unified logger
                    if self.unified_logger:
                        self.unified_logger.log_attack(
                            service="mysql",
                            attacker_ip=address[0],
                            attacker_port=address[1],
                            command="mysql_unknown_command",
                            additional_data={
                                "command_type": cmd_type,
                                "raw_data": cmd_packet.hex()[:100]  # First 100 chars to avoid bloat
                            }
                        )
                    # Send OK packet for unknown commands
                    self._send_ok_packet(client_socket)
                    
            except Exception as e:
                self.logger.error(f"Error handling MySQL command: {e}")
                # Log error to unified logger
                if self.unified_logger:
                    self.unified_logger.log_attack(
                        service="mysql",
                        attacker_ip=address[0],
                        attacker_port=address[1],
                        command="error",
                        additional_data={
                            "error": str(e),
                            "context": "command_handling"
                        }
                    )
                break
    
    def _send_ok_packet(self, client_socket: socket.socket, sequence_id: int = 1) -> None:
        """
        Send an OK packet to the client
        """
        data = bytearray()
        data.append(0x00)  # OK packet header
        data.append(0x00)  # Affected rows
        data.append(0x00)  # Last insert ID
        data.extend(struct.pack("<H", 0x0002))  # Server status
        data.extend(struct.pack("<H", 0))  # Warnings
        self._send_packet(client_socket, data, sequence_id)

    def start(self) -> None:
        """Start the MySQL service"""
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            self.running = True
            
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="mysql",
                    attacker_ip="system",
                    attacker_port=0,
                    command="service_start",
                    additional_data={"port": self.port}
                )
            
            self.logger.info(f"MySQL honeypot started on port {self.port}")
            
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
                    self.logger.info(f"Connection from {addr[0]}:{addr[1]} to MySQL service")
                    
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
                            service="mysql",
                            attacker_ip="error",
                            attacker_port=0,
                            command="error",
                            additional_data={"error": str(e)}
                        )
                    self.logger.error(f"Error accepting connection: {e}")
                    
        except Exception as e:
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="mysql",
                    attacker_ip="error",
                    attacker_port=0,
                    command="service_error",
                    additional_data={"error": str(e)}
                )
            self.logger.error(f"Error starting MySQL service: {e}")
        finally:
            if self.sock:
                self.sock.close()
