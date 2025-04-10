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

    def __init__(self, host: str, port: int, config: Dict[str, Any]):
        """
        Initialize the Redis service

        Args:
            host: Host IP to bind to
            port: Port to listen on
            config: Global configuration dictionary
        """
        super().__init__(host, port, config, "redis")

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

        # Track commands for this session
        commands = []

        try:
            # Send Redis banner
            self._send_response(client_socket, f"-NOAUTH REDIS {self.server_version} not authenticated\r\n")

            while True:
                # Receive command
                data = client_socket.recv(4096)
                if not data:
                    break

                # Process Redis command
                response, command_info = self._process_command(data.decode('utf-8', errors='ignore'), session_id)

                # Log command
                if command_info:
                    commands.append(command_info)
                    connection_data["data"]["commands"] = commands

                # Send response
                self._send_response(client_socket, response)

        except Exception as e:
            self.logger.error(f"Error handling Redis client: {e}")
            connection_data["error"] = str(e)
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

    def _process_command(self, data: str, session_id: str) -> Tuple[str, Optional[Dict[str, Any]]]:
        """
        Process a Redis command

        Args:
            data: Raw command data
            session_id: Session identifier

        Returns:
            Tuple of (response string, command info dict or None)
        """
        # Basic parsing of Redis RESP protocol
        # This is simplified - a real implementation would handle nested arrays, etc.
        lines = data.strip().split('\r\n')

        if not lines or len(lines) < 2:
            return "-ERR Protocol error\r\n", None

        # RESP arrays start with *<number of elements>
        if not lines[0].startswith('*'):
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

            # In a honeypot, we don't actually store the data
            # Just acknowledge the command
            return "+OK\r\n", command_info

        elif command == "CONFIG":
            if len(args) < 1:
                return "-ERR wrong number of arguments for 'config' command\r\n", command_info

            subcommand = args[0].upper()

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
            return "-ERR unknown command\r\n", command_info
