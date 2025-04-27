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
        
            # Add extra validation to prevent index errors
            if (username_offset + username_len * 2 > len(packet) or 
                password_offset + password_len * 2 > len(packet)):
                self.logger.warning("Invalid offsets in login packet")
                return "", ""
                
            username_bytes = packet[username_offset:username_offset + username_len * 2]
            password_bytes = packet[password_offset:password_offset + password_len * 2]
        
            username = username_bytes.decode("utf-16-le", errors="ignore")
            password = self._decode_tds_password(password_bytes)
        
            self.logger.debug(f"Extracted username: {username}")
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
        try:
            # Set a reasonable timeout
            client_socket.settimeout(5.0)
            
            # Receive TDS packet header (8 bytes)
            header = b""
            bytes_received = 0
            while bytes_received < 8:
                chunk = client_socket.recv(8 - bytes_received)
                if not chunk:
                    self.logger.warning("Connection closed while receiving header")
                    return b""
                header += chunk
                bytes_received += len(chunk)
            
            if len(header) < 8:
                self.logger.warning(f"Incomplete TDS header received: {len(header)} bytes")
                return b""
            
            # Parse packet length (2 bytes at offset 2)
            # Keep the original format that was working
            length = struct.unpack(">H", header[2:4])[0]
            
            # Sanity check for length
            if length < 8 or length > 32768:
                self.logger.warning(f"Invalid TDS packet length: {length}")
                return b""
            
            # Receive packet data
            data = b""
            remaining = length - 8  # Subtract header size
            
            while remaining > 0:
                chunk = client_socket.recv(min(remaining, 4096))  # Read in chunks
                if not chunk:
                    self.logger.warning(f"Connection closed while receiving data")
                    break
                data += chunk
                remaining -= len(chunk)
            
            return data
                
        except socket.timeout:
            self.logger.warning("Socket timeout while receiving TDS packet")
            return b""
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
            header.extend(struct.pack(">H", length))  # Keep original format
            header.extend(b'\x00\x00')  # SPID (Server Process ID)
            header.append(0x00)  # Packet ID
            header.append(0x00)  # Window
    
            # Send packet header and data
            self.logger.debug(f"TDS SEND: type={packet_type}, len={len(data)}")
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
        """
        Receive SQL command from client
        
        Args:
            client_socket: Client socket object
            
        Returns:
            SQL command string
        """
        try:
            data = self._receive_tds_packet(client_socket)
            if not data:
                return ""
            
            # SQL commands in TDS format typically start with a command token
            # Skip the first byte (token) and return the actual SQL command
            if len(data) > 1:
                # Look for string-like data (typically after token byte)
                for i in range(len(data)):
                    if 32 <= data[i] < 127:  # Printable ASCII range
                        sql = data[i:].decode('utf-8', errors='ignore').strip()
                        # Clean up any null terminators or control characters
                        sql = ''.join(char for char in sql if 32 <= ord(char) < 127 or char in '\r\n\t')
                        return sql
            
            return data.decode('utf-8', errors='ignore').strip()
            
        except Exception as e:
            self.logger.error(f"Error receiving SQL command: {e}")
            return ""
    
    def _send_fake_result(self, client_socket: socket.socket, headers: List[str], rows: List[List[str]]) -> None:
        try:
            packet = bytearray()
            
            # --- COLMETADATA ---
            packet.append(0x81)  # COLMETADATA token
            
            # Column count - must match exact format expected by Metasploit
            num_columns = len(headers)
            packet.extend(struct.pack("<H", num_columns))
            
            # Column definitions
            for col_name in headers:
                # UserType (2 bytes) and Flags (2 bytes)
                packet.extend(b'\x00\x00\x00\x00')
                
                # Data type - use NVARCHAR (0xE7) for compatibility
                packet.append(0xE7)
                
                # Max length (2 bytes)
                packet.extend(struct.pack("<H", 4000))
                
                # Collation (5 bytes)
                packet.extend(b'\x09\x04\xD0\x00\x34')
                
                # Column name length and value
                col_name_bytes = col_name.encode('utf-16-le')
                name_len = len(col_name)
                if name_len > 255:  # Ensure valid length byte
                    name_len = 255
                packet.append(name_len)
                packet.extend(col_name_bytes)
            
            # --- ROW(s) ---
            for row_data in rows:
                packet.append(0xD1)  # ROW token
                
                # For each column in the row
                for i, value in enumerate(row_data):
                    if i >= num_columns:  # Safety check
                        break
                        
                    # For NVARCHAR, encode as UTF-16LE
                    value_bytes = value.encode('utf-16-le')
                    value_len = len(value_bytes)
                    
                    # Length prefix (2 bytes for NVARCHAR)
                    packet.extend(struct.pack("<H", value_len))
                    
                    # Value
                    packet.extend(value_bytes)
            
            # --- DONE ---
            packet.append(0xFD)  # DONE token
            packet.extend(struct.pack("<H", 0))   # Status - DONE_FINAL
            packet.extend(struct.pack("<H", 0))   # CurCmd
            packet.extend(struct.pack("<I", len(rows)))  # Row count (4 bytes)
            
            # Send the packet
            self._send_tds_packet(client_socket, packet, 0x04)
            
        except Exception as e:
            self.logger.error(f"Error sending fake result: {e}")

    def _generate_fake_sql_response(self, command: str) -> Tuple[List[str], List[List[str]]]:
        """
        Generate appropriate responses for SQL commands based on common attack patterns
        
        Args:
            command: SQL command string
            
        Returns:
            Tuple of (headers, rows)
        """
        command_lower = command.lower().strip()
        self.logger.debug(f"Processing SQL command: {command_lower}")
        
        # --- SERVER INFORMATION QUERIES ---
        
        # Version information
        if "@@version" in command_lower:
            return (
                ["version"],
                [["Microsoft SQL Server 2019 (RTM-CU21) - 15.0.4198.2 (X64) Enterprise Edition on Windows Server 2019 Standard 10.0 (Build 17763: ) (Hypervisor)"]]
            )
        
        # Server name - exact match for Metasploit
        elif command_lower == "select @@servername":
            return (
                ["@@SERVERNAME"],
                [[self.server_name]]
            )
        
        # Database listing - exact match for Metasploit format
        elif command_lower == "select name from master..sysdatabases":
            return (
                ["name"],
                [
                    ["master"],
                    ["tempdb"],
                    ["model"],
                    ["msdb"],
                    ["finance"]
                ]
            )
        
        # Table listing - exact match for Metasploit format
        elif "select name,id from " in command_lower and "..sysobjects where xtype = 'u'" in command_lower:
            db_name = command_lower.split("select name,id from ")[1].split("..")[0]
            return (
                ["name", "id"],
                [
                    ["users", "1001"],
                    ["accounts", "1002"],
                    ["customers", "1003"],
                    ["orders", "1004"],
                    ["payments", "1005"]
                ]
            )
        
        # Column information - exact match for Metasploit format
        elif "select syscolumns.name,systypes.name,syscolumns.length from " in command_lower and "syscolumns join " in command_lower:
            # Extract table ID from the query
            table_id = "1001"  # Default
            if "where syscolumns.id=" in command_lower:
                table_id = command_lower.split("where syscolumns.id=")[1].strip()
            
            if table_id == "1001":  # users table
                return (
                    ["name", "name", "length"],
                    [
                        ["id", "int", "4"],
                        ["username", "varchar", "50"],
                        ["password", "varchar", "100"],
                        ["email", "varchar", "100"]
                    ]
                )
            elif table_id == "1002":  # accounts table
                return (
                    ["name", "name", "length"],
                    [
                        ["account_id", "int", "4"],
                        ["user_id", "int", "4"],
                        ["balance", "decimal", "10"],
                        ["account_type", "varchar", "20"]
                    ]
                )
            else:
                return (
                    ["name", "name", "length"],
                    [
                        ["id", "int", "4"],
                        ["name", "varchar", "50"],
                        ["description", "varchar", "200"]
                    ]
                )
        
        # SQL Server instance info
        elif "select serverproperty" in command_lower:
            if "productversion" in command_lower:
                return (["ProductVersion"], [["15.0.4198.2"]])
            elif "edition" in command_lower:
                return (["Edition"], [["Enterprise Edition"]])
            elif "productlevel" in command_lower:
                return (["ProductLevel"], [["RTM"]])
            elif "servername" in command_lower:
                return (["ServerName"], [[self.server_name]])
            else:
                return (["Value"], [["1"]])
        
        # Host information
        elif "xp_msver" in command_lower:
            return (
                ["Index", "Name", "Internal_Value", "Character_Value"],
                [
                    ["1", "ProductName", "0", "Microsoft SQL Server"],
                    ["2", "ProductVersion", "0", "15.0.4198.2"],
                    ["3", "Language", "1033", "English (United States)"],
                    ["4", "Platform", "0", "NT x64"],
                    ["5", "Comments", "0", "Enterprise Edition"]
                ]
            )
        
        # Host system info
        elif "host_name()" in command_lower or "@@hostname" in command_lower:
            return (["host_name"], [["SQL-PROD-01"]])
                
        # Current user info
        elif "current_user" in command_lower or "system_user" in command_lower or "user_name()" in command_lower:
            return (["CurrentUser"], [["dbo"]])
        
        # Language settings
        elif "@@language" in command_lower:
            return (["Language"], [["us_english"]])
        
        # --- PRIVILEGE AND ROLE CHECKING ---
        
        # Admin role check
        elif "is_srvrolemember" in command_lower and "sysadmin" in command_lower:
            return (
                ["IsSysAdmin"],
                [["0"]]  # Return 0 to indicate non-admin (makes attacker work harder)
            )
        
        # Permissions check
        elif "has_perms_by_name" in command_lower or "has_dbaccess" in command_lower:
            return (["Permission"], [["1"]])  # Indicate some permissions to keep attacker interested
        
        # User role enumeration
        elif "select" in command_lower and "sys.server_role_members" in command_lower:
            return (
                ["role_principal_id", "member_principal_id"],
                [
                    ["3", "5"],
                    ["3", "7"],
                    ["4", "6"]
                ]
            )
        
        # User list
        elif ("select" in command_lower and "sys.server_principals" in command_lower) or "sp_helplogins" in command_lower:
            return (
                ["name", "principal_id", "type", "type_desc", "create_date"],
                [
                    ["sa", "1", "S", "SQL_LOGIN", "2022-01-01"],
                    ["NT AUTHORITY\\SYSTEM", "2", "U", "WINDOWS_LOGIN", "2022-01-01"],
                    ["NT SERVICE\\SQLSERVERAGENT", "3", "U", "WINDOWS_LOGIN", "2022-01-01"],
                    ["domain\\sqladmin", "4", "U", "WINDOWS_LOGIN", "2022-01-01"],
                    ["app_user", "5", "S", "SQL_LOGIN", "2022-05-15"]
                ]
            )
        
        # Authentication mode
        elif "select" in command_lower and "serverproperty" in command_lower and "isintegratedsecurityonly" in command_lower:
            return (["IsIntegratedSecurityOnly"], [["0"]])  # Mixed mode auth
        
        # --- DATABASE ENUMERATION ---
        
        # More comprehensive database listing
        elif "sys.databases" in command_lower:
            return (
                ["name", "database_id", "create_date", "compatibility_level", "state"],
                [
                    ["master", "1", "2022-01-01", "150", "0"],
                    ["tempdb", "2", "2022-01-01", "150", "0"],
                    ["model", "3", "2022-01-01", "150", "0"], 
                    ["msdb", "4", "2022-01-01", "150", "0"],
                    ["finance", "5", "2023-03-11", "150", "0"],
                    ["hr", "6", "2023-04-22", "150", "0"],
                    ["customer", "7", "2023-06-10", "150", "0"]
                ]
            )
        
        # Default database for the current connection
        elif "db_name()" in command_lower:
            return (["db_name"], [["master"]])
        
        # Database files
        elif "sys.database_files" in command_lower or "sysfiles" in command_lower:
            return (
                ["name", "file_id", "type", "physical_name"],
                [
                    ["master", "1", "0", "C:\\Program Files\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\MSSQL\\DATA\\master.mdf"],
                    ["mastlog", "2", "1", "C:\\Program Files\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\MSSQL\\DATA\\mastlog.ldf"]
                ]
            )
        
        # --- TABLE ENUMERATION ---
        
        # General sysobjects query - used in many attack scripts
        elif "sysobjects" in command_lower:
            return (
                ["name", "id", "xtype", "uid"],
                [
                    ["users", "1001", "U", "1"],
                    ["accounts", "1002", "U", "1"],
                    ["customers", "1003", "U", "1"],
                    ["orders", "1004", "U", "1"],
                    ["payments", "1005", "U", "1"],
                    ["employees", "1006", "U", "1"],
                    ["audit_log", "1007", "U", "1"],
                    ["config", "1008", "U", "1"],
                    ["dt_addtabletocontents", "2001", "P", "1"],  # Adding stored procedures
                    ["sp_configure", "2002", "P", "1"]
                ]
            )
        
        # Column information - critical for schema dump and data exfiltration
        elif "information_schema.columns" in command_lower or "syscolumns" in command_lower:
            # Provide realistic schema information to track attacker's interest
            return (
                ["TABLE_CATALOG", "TABLE_SCHEMA", "TABLE_NAME", "COLUMN_NAME", "DATA_TYPE", "CHARACTER_MAXIMUM_LENGTH"],
                [
                    ["master", "dbo", "users", "id", "int", "4"],
                    ["master", "dbo", "users", "username", "nvarchar", "50"],
                    ["master", "dbo", "users", "password", "nvarchar", "100"],
                    ["master", "dbo", "users", "email", "nvarchar", "100"],
                    ["master", "dbo", "users", "created_date", "datetime", "8"],
                    ["master", "dbo", "accounts", "account_id", "int", "4"],
                    ["master", "dbo", "accounts", "user_id", "int", "4"],
                    ["master", "dbo", "accounts", "balance", "decimal", "10"],
                    ["master", "dbo", "accounts", "account_type", "nvarchar", "20"],
                    ["master", "dbo", "employees", "employee_id", "int", "4"],
                    ["master", "dbo", "employees", "first_name", "nvarchar", "50"],
                    ["master", "dbo", "employees", "last_name", "nvarchar", "50"],
                    ["master", "dbo", "employees", "salary", "decimal", "10"],
                    ["master", "dbo", "employees", "ssn", "nvarchar", "20"]
                ]
            )
        
        # --- SYSTEM COMMANDS AND EXTENDED PROCEDURES ---
        
        # xp_cmdshell - commonly used for command execution
        elif "xp_cmdshell" in command_lower:
            if "dir" in command_lower or "ls" in command_lower:
                return (
                    ["output"],
                    [
                        [" Volume in drive C has no label."],
                        [" Volume Serial Number is 1234-5678"],
                        [""],
                        [" Directory of C:\\Program Files\\Microsoft SQL Server\\MSSQL15.MSSQLSERVER\\MSSQL"],
                        [""],
                        ["01/01/2022  08:00 AM    <DIR>          DATA"],
                        ["01/01/2022  08:00 AM    <DIR>          Backup"],
                        ["01/01/2022  08:00 AM    <DIR>          Log"],
                        ["               0 File(s)              0 bytes"],
                        ["               3 Dir(s)  50,123,294,720 bytes free"]
                    ]
                )
            elif "whoami" in command_lower:
                return (["output"], [["nt service\\mssqlserver"]])
            elif "ipconfig" in command_lower:
                return (
                    ["output"],
                    [
                        ["Windows IP Configuration"],
                        [""],
                        ["Ethernet adapter Ethernet:"],
                        [""],
                        ["   Connection-specific DNS Suffix  . : domain.local"],
                        ["   IPv4 Address. . . . . . . . . . . : 10.0.0.25"],
                        ["   Subnet Mask . . . . . . . . . . . : 255.255.255.0"],
                        ["   Default Gateway . . . . . . . . . : 10.0.0.1"]
                    ]
                )
            else:
                return (
                    ["output"],
                    [["Access denied. The xp_cmdshell procedure is disabled on this server."]]
                )
        
        # xp_dirtree - used for UNC path injection and SMB hash capture
        elif "xp_dirtree" in command_lower:
            if "\\\\evil" in command_lower or "\\\\10." in command_lower or "\\\\192." in command_lower:
                # Track potential UNC path injection attempts
                self.logger.warning(f"Possible UNC path injection attempt: {command}")
                return (["subdirectory", "depth", "is_file"], [])  # Empty result
            else:
                return (
                    ["subdirectory", "depth", "is_file"],
                    [
                        ["Program Files", "1", "0"],
                        ["Windows", "1", "0"],
                        ["Users", "1", "0"],
                        ["temp", "1", "0"]
                    ]
                )
        
        # Other common extended procedures
        elif "xp_regread" in command_lower:
            return (["Value"], [["0"]])
        elif "sp_oacreate" in command_lower:
            return (["Return Value"], [["0"]])
        elif "sp_configure" in command_lower:
            if "show advanced" in command_lower:
                return (
                    ["name", "minimum", "maximum", "config_value", "run_value"],
                    [
                        ["xp_cmdshell", "0", "1", "0", "0"],
                        ["remote access", "0", "1", "1", "1"],
                        ["allow updates", "0", "1", "0", "0"],
                        ["max text repl size", "0", "2147483647", "65536", "65536"]
                    ]
                )
            else:
                return (["Value"], [["0"]])
        
        # --- DATA QUERIES ---
        
        # Common table queries - simulate sensitive data to log attackers' intent
        elif "from users" in command_lower:
            return (
                ["id", "username", "password", "email", "created_date"],
                [
                    ["1", "admin", "hashed_password_1", "admin@example.com", "2022-01-01"],
                    ["2", "jsmith", "hashed_password_2", "jsmith@example.com", "2022-02-15"],
                    ["3", "mjones", "hashed_password_3", "mjones@example.com", "2022-03-22"],
                    ["4", "dkim", "hashed_password_4", "dkim@example.com", "2022-05-10"]
                ]
            )
        elif "from employees" in command_lower:
            return (
                ["employee_id", "first_name", "last_name", "hire_date", "salary"],
                [
                    ["1", "John", "Smith", "2020-06-15", "75000.00"],
                    ["2", "Mary", "Jones", "2019-03-22", "82000.00"],
                    ["3", "David", "Kim", "2021-11-10", "65000.00"],
                    ["4", "Sarah", "Lee", "2018-08-05", "92000.00"]
                ]
            )
        elif "from accounts" in command_lower:
            return (
                ["account_id", "user_id", "balance", "account_type", "created_date"],
                [
                    ["1001", "1", "25000.00", "checking", "2022-01-05"],
                    ["1002", "1", "100000.00", "savings", "2022-01-05"],
                    ["1003", "2", "5250.75", "checking", "2022-02-20"],
                    ["1004", "3", "12750.25", "checking", "2022-04-01"]
                ]
            )
        
        # --- SQLMAP AND INJECTION TESTING ---
        
        # SQLMap detection and information queries
        elif any(marker in command_lower for marker in ["@@payload", "sqlmap", "waitfor delay", "sleep(", "benchmark("]):
            self.logger.warning(f"Possible SQL injection attack detected: {command}")
            return (["result"], [["Query processed. No results to display."]])
        
        # Error-based injection test
        elif any(marker in command_lower for marker in ["convert(", "cast(", "db_name(", "concat(", "error"]):
            return (["Error"], [["Incorrect syntax near the keyword."]])
        
        # Union-based injection fingerprinting
        elif "union" in command_lower and "select" in command_lower:
            self.logger.warning(f"Possible UNION-based SQL injection attempt: {command}")
            return (["Error"], [["All queries in a SQL statement containing a UNION operator must have an equal number of expressions."]])
        
        # Login failed count - specifically for Metasploit login scanners
        elif "select" in command_lower and "count" in command_lower and "login failed" in command_lower:
            return (["count"], [["15"]])
        
        # --- DEFAULT FALLBACKS ---
        
        # Generic SELECT query response
        elif "select" in command_lower:
            return (
                ["result"],
                [["Query processed. 0 rows affected."]]
            )
        
        # Generic UPDATE/INSERT/DELETE response
        elif any(op in command_lower for op in ["update ", "insert ", "delete "]):
            return (
                ["result"],
                [["Command completed. 0 rows affected."]]
            )
        
        # Generic error for invalid commands
        else:
            return (
                ["result"],
                [["Command executed successfully."]]
            )
        
