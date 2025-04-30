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
Redis service emulator for the honeypot system
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

class RedisService(BaseService):
    """Redis service emulator for the honeypot"""

    def __init__(self, host: str, port: int, config: Dict[str, Any], unified_logger=None):
        """
        Initialize the Redis service
    
        Args:
            host: Host IP to bind to
            port: Port to listen on
            config: Global configuration dictionary
            unified_logger: Unified logger instance for centralized logging
        """
        super().__init__(host, port, config, "redis")
        
        # Store unified logger instance
        self.unified_logger = unified_logger
    
        # Redis specific configurations
        self.server_version = self.service_config.get("server_version", "5.0.7")
        self.password = self.service_config.get("password", "")
        self.require_auth = self.service_config.get("require_auth", True)
        self.authenticated = {}  # Track authenticated clients by their session ID
    
        # Fake data for GET commands
        self.fake_data = {
            "user:1": '{"username":"admin","email":"admin@example.com"}',
            "api_key": "c5a8ae582c7ee96a6a4bae6e4f476f2e",
            "config:database": '{"host":"localhost","username":"dbuser","password":"dbpass123"}',
            "session:123456": '{"user_id": 1, "admin": true}',
            "server:info": '{"hostname": "prod-db-1", "environment": "production"}'
        }
    
    def handle_client(self, client_socket: socket.socket, address: Tuple[str, int],
                     connection_data: Dict[str, Any]) -> None:
        """
        Handle a client connection to the Redis service
    
        Args:
            client_socket: Client socket object
            address: Client address tuple (ip, port)
            connection_data: Dictionary to store connection data for logging
        """
        session_id = f"{address[0]}:{address[1]}:{time.time()}"
        self.authenticated[session_id] = False
        connection_data["data"]["connection_time"] = datetime.datetime.now().isoformat()
        
        # Log connection attempt to unified logger
        if self.unified_logger:
            self.unified_logger.log_attack(
                service="redis",
                attacker_ip=address[0],
                attacker_port=address[1],
                command="connection_attempt",
                additional_data={
                    "session_id": session_id,
                    "timestamp": datetime.datetime.now().isoformat()
                }
            )
    
        # Track commands for this session
        commands = []
    
        try:
            # Send Redis banner
            self._send_response(client_socket, f"-NOAUTH REDIS {self.server_version} not authenticated\r\n")
            
            # Log banner sent to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="redis",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="redis_banner_sent",
                    additional_data={
                        "session_id": session_id,
                        "version": self.server_version
                    }
                )
    
            while True:
                # Receive command
                data = client_socket.recv(4096)
                if not data:
                    break
    
                # Process Redis command
                response, command_info = self._process_command(data.decode('utf-8', errors='ignore'), session_id, address)
    
                # Log command
                if command_info:
                    commands.append(command_info)
                    connection_data["data"]["commands"] = commands
                    
                    # Log command to unified logger
                    if self.unified_logger:
                        self.unified_logger.log_attack(
                            service="redis",
                            attacker_ip=address[0],
                            attacker_port=address[1],
                            command=f"redis_command_{command_info.get('command', 'unknown')}",
                            additional_data={
                                "session_id": session_id,
                                "command": command_info.get("command", ""),
                                "args": command_info.get("args", []),
                                "timestamp": command_info.get("timestamp", "")
                            }
                        )
    
                # Send response
                self._send_response(client_socket, response)
    
        except Exception as e:
            self.logger.error(f"Error handling Redis client: {e}")
            connection_data["error"] = str(e)
            
            # Log error to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="redis",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="error",
                    additional_data={
                        "session_id": session_id,
                        "error": str(e)
                    }
                )
        finally:
            # Clean up session
            if session_id in self.authenticated:
                del self.authenticated[session_id]
            client_socket.close()

    def _send_response(self, client_socket: socket.socket, response: str) -> None:
        """Send a response to the client"""
        try:
            client_socket.send(response.encode())
        except Exception as e:
            self.logger.error(f"Error sending response: {e}")

    def _process_command(self, data: str, session_id: str, address: Tuple[str, int]) -> Tuple[str, Optional[Dict[str, Any]]]:
        """
        Process a Redis command
    
        Args:
            data: Raw command data
            session_id: Session identifier
            address: Client address tuple (ip, port)
    
        Returns:
            Tuple of (response string, command info dict or None)
        """
        # Basic parsing of Redis RESP protocol
        # This is simplified - a real implementation would handle nested arrays, etc.
        lines = data.strip().split('\r\n')
    
        if not lines or len(lines) < 2:
            # Log protocol error to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="redis",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="redis_protocol_error",
                    additional_data={
                        "session_id": session_id,
                        "raw_data": data
                    }
                )
            return "-ERR Protocol error\r\n", None
    
        # RESP arrays start with *<number of elements>
        if not lines[0].startswith('*'):
            # Log protocol error to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="redis",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="redis_protocol_error",
                    additional_data={
                        "session_id": session_id,
                        "raw_data": data
                    }
                )
            return "-ERR Protocol error\r\n", None
    
        # Extract command parts
        command_parts = []
        i = 1
        while i < len(lines):
            if lines[i].startswith('$'):
                # String length indicator
                if i + 1 < len(lines):
                    command_parts.append(lines[i + 1])
                i += 2
            else:
                i += 1
    
        if not command_parts:
            # Log protocol error to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="redis",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="redis_protocol_error",
                    additional_data={
                        "session_id": session_id,
                        "raw_data": data
                    }
                )
            return "-ERR Protocol error\r\n", None
    
        # Process command
        command = command_parts[0].upper()
        args = command_parts[1:] if len(command_parts) > 1 else []
    
        # Log the command
        command_info = {
            "command": command,
            "args": args,
            "timestamp": datetime.datetime.now().isoformat()
        }
    
        self.logger.info(f"Redis command: {command} {' '.join(args)}")
    
        # Handle authentication
        if self.require_auth and not self.authenticated.get(session_id, False) and command != "AUTH":
            # Log auth required to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="redis",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="redis_auth_required",
                    additional_data={
                        "session_id": session_id,
                        "attempted_command": command
                    }
                )
            return "-NOAUTH Authentication required.\r\n", command_info
    
        # Command handlers
        if command == "PING":
            return "+PONG\r\n", command_info
    
        elif command == "AUTH":
            if len(args) < 1:
                return "-ERR wrong number of arguments for 'auth' command\r\n", command_info
    
            password = args[0]
            # Log authentication attempt
            self.logger.info(f"Redis AUTH attempt with password: {password}")
            
            # Log auth attempt to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="redis",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="login_attempt",
                    additional_data={
                        "session_id": session_id,
                        "password": password,
                        "success": False
                    }
                )
    
            # Always fail auth in honeypot
            self.authenticated[session_id] = False
            return "-ERR invalid password\r\n", command_info
    
        elif command == "INFO":
            # Simplified INFO response
            info = f"""$251
    # Server
    redis_version:{self.server_version}
    redis_mode:standalone
    os:Linux 4.15.0-54-generic x86_64
    # Clients
    connected_clients:1
    # Memory
    used_memory:1016824
    used_memory_human:993.97K
    # Stats
    total_connections_received:1
    total_commands_processed:1
    """
            return info, command_info
    
        elif command == "GET":
            if len(args) < 1:
                return "-ERR wrong number of arguments for 'get' command\r\n", command_info
    
            key = args[0]
            value = self.fake_data.get(key)
            
            # Log data access to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="redis",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="redis_get",
                    additional_data={
                        "session_id": session_id,
                        "key": key,
                        "found": value is not None
                    }
                )
    
            if value:
                # String response format: $<length>\r\n<data>\r\n
                return f"${len(value)}\r\n{value}\r\n", command_info
            else:
                return "$-1\r\n", command_info  # Redis nil response
    
        elif command == "SET":
            if len(args) < 2:
                return "-ERR wrong number of arguments for 'set' command\r\n", command_info
    
            key = args[0]
            value = args[1]
            
            # Log data write to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="redis",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="redis_set",
                    additional_data={
                        "session_id": session_id,
                        "key": key,
                        "value_length": len(value),
                        "value_preview": value[:20] if len(value) > 20 else value
                    }
                )
    
            # In a honeypot, we don't actually store the data
            # Just acknowledge the command
            return "+OK\r\n", command_info
    
        elif command == "CONFIG":
            if len(args) < 1:
                return "-ERR wrong number of arguments for 'config' command\r\n", command_info
    
            subcommand = args[0].upper()
            
            # Log CONFIG command to unified logger (potentially dangerous)
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="redis",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="redis_config",
                    additional_data={
                        "session_id": session_id,
                        "subcommand": subcommand,
                        "args": args[1:] if len(args) > 1 else []
                    }
                )
    
            if subcommand == "GET":
                if len(args) < 2:
                    return "-ERR wrong number of arguments for 'config get' command\r\n", command_info
    
                # Return fake config
                param = args[1]
                if param == "dir":
                    return "*2\r\n$3\r\ndir\r\n$9\r\n/var/lib/redis\r\n", command_info
                elif param == "dbfilename":
                    return "*2\r\n$10\r\ndbfilename\r\n$9\r\ndump.rdb\r\n", command_info
                else:
                    return "*0\r\n", command_info
    
            elif subcommand == "SET":
                if len(args) < 3:
                    return "-ERR wrong number of arguments for 'config set' command\r\n", command_info
    
                # Log what config they're trying to set - could indicate attack
                self.logger.warning(f"Attempt to set config {args[1]} to {args[2]}")
                
                # Log dangerous CONFIG SET to unified logger
                if self.unified_logger:
                    self.unified_logger.log_attack(
                        service="redis",
                        attacker_ip=address[0],
                        attacker_port=address[1],
                        command="redis_config_set",
                        additional_data={
                            "session_id": session_id,
                            "parameter": args[1],
                            "value": args[2]
                        }
                    )
    
                # Pretend to succeed
                return "+OK\r\n", command_info
    
            else:
                return "-ERR unknown subcommand for 'config' command\r\n", command_info
    
        elif command == "KEYS":
            if len(args) < 1:
                return "-ERR wrong number of arguments for 'keys' command\r\n", command_info
    
            # Return list of fake keys
            pattern = args[0]
            keys = []
            
            # Log KEYS command to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="redis",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="redis_keys",
                    additional_data={
                        "session_id": session_id,
                        "pattern": pattern
                    }
                )
    
            # Very basic pattern matching (not full Redis glob)
            if pattern == "*":
                keys = list(self.fake_data.keys())
            else:
                for key in self.fake_data.keys():
                    if pattern in key:
                        keys.append(key)
    
            # Format response
            response = f"*{len(keys)}\r\n"
            for key in keys:
                response += f"${len(key)}\r\n{key}\r\n"
    
            return response, command_info
    
        elif command == "QUIT":
            return "+OK\r\n", command_info
    
        else:
            # Unknown command - in a honeypot, we might want to pretend to support it
            # Log unknown command to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="redis",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="redis_unknown_command",
                    additional_data={
                        "session_id": session_id,
                        "command": command,
                        "args": args
                    }
                )
            return "-ERR unknown command\r\n", command_info

    def start(self) -> None:
        """Start the Redis service"""
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            self.running = True
            
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="redis",
                    attacker_ip="system",
                    attacker_port=0,
                    command="service_start",
                    additional_data={"port": self.port}
                )
            
            self.logger.info(f"Redis honeypot started on port {self.port}")
            
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
                    self.logger.info(f"Connection from {addr[0]}:{addr[1]} to Redis service")
                    
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
                            service="redis",
                            attacker_ip="error",
                            attacker_port=0,
                            command="error",
                            additional_data={"error": str(e)}
                        )
                    self.logger.error(f"Error accepting connection: {e}")
                    
        except Exception as e:
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="redis",
                    attacker_ip="error",
                    attacker_port=0,
                    command="service_error",
                    additional_data={"error": str(e)}
                )
            self.logger.error(f"Error starting Redis service: {e}")
        finally:
            if self.sock:
                self.sock.close()
