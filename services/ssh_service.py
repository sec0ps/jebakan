#!/usr/bin/env python3
"""
SSH service emulator for the honeypot system
"""

import socket
import threading
import logging
import datetime
import json
import os
import time
import re
import paramiko
from typing import Dict, List, Any, Tuple, Optional

from services.base_service import BaseService

class SSHService(BaseService):
    """SSH service emulator for the honeypot"""
    
    def __init__(self, host: str, port: int, config: Dict[str, Any]):
        super().__init__(host, port, config, "ssh")
        
        # Generate SSH server key if needed
        self.key_file = os.path.join("data", "ssh_host_rsa_key")
        self._ensure_server_key()
        
        # Set banner if specified
        if "banner" in self.service_config:
            self.banner = self.service_config["banner"]
        else:
            self.banner = "SSH-2.0-OpenSSH_7.4p1 Ubuntu-10"
            
        # Track command history by session
        self.command_history = {}

    def _ensure_server_key(self) -> None:
        """Ensure SSH server key exists, generate if it doesn't"""
        os.makedirs(os.path.dirname(self.key_file), exist_ok=True)
        
        if not os.path.exists(self.key_file):
            self.logger.info("Generating SSH host key...")
            key = paramiko.RSAKey.generate(2048)
            key.write_private_key_file(self.key_file)
            self.logger.info(f"SSH host key generated and saved to {self.key_file}")
    
    def start(self) -> None:
        """Start the SSH service properly by listening on a socket"""
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            self.running = True
            self.logger.info(f"SSH honeypot started on port {self.port}")
            
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
                    self.logger.info(f"Connection from {addr[0]}:{addr[1]} to SSH service")
                    
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
                    self.logger.error(f"Error accepting connection: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error starting SSH service: {e}")
        finally:
            if self.sock:
                self.sock.close()

    def handle_client(self, client_socket: socket.socket, address: Tuple[str, int], 
                     connection_data: Dict[str, Any]) -> None:
        """
        Handle a client connection to the SSH service
        
        Args:
            client_socket: Client socket object
            address: Client address tuple (ip, port)
            connection_data: Dictionary to store connection data for logging
        """
        session_id = f"{address[0]}:{address[1]}:{time.time()}"
        
        # Initialize command history for this session
        self.command_history[session_id] = []
        
        # Wrap the client socket with Paramiko's Transport correctly
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(paramiko.RSAKey(filename=self.key_file))

        server_interface = CustomSSHServerInterface(self)

        try:
            transport.start_server(server=server_interface)

            chan = transport.accept(20)
            if chan is None:
                self.logger.error(f"No channel for {address}")
                return

            # Send welcome message and prompt
            hostname = self.config["deception"]["system_info"]["hostname"]
            username = server_interface.username
            chan.send(f"Welcome to Ubuntu 18.04.5 LTS ({hostname})\r\n".encode())
            chan.send(f"{username}@{hostname}:~$ ".encode())

            # Interactive command loop
            while True:
                command = ''
                while not command.endswith('\n'):
                    data = chan.recv(1024)
                    if not data:
                        break
                    command += data.decode('utf-8')

                command = command.strip()
                if not command or command.lower() in ['exit', 'logout', 'quit']:
                    chan.send("logout\r\n".encode())
                    break

                # Log the command
                self.command_history[session_id].append({
                    "command": command,
                    "timestamp": datetime.datetime.now().isoformat()
                })

                response = self.simulate_command_response(command)
                chan.send(response.encode())
                chan.send(f"{username}@{hostname}:~$ ".encode())

        except Exception as e:
            self.logger.error(f"Error handling SSH client: {e}")
            connection_data["error"] = str(e)
        finally:
            transport.close()
            client_socket.close()
            connection_data["data"]["command_history"] = self.command_history.pop(session_id, [])

    def simulate_command_response(self, command: str, context: Dict[str, Any] = None) -> str:
        """
        Simulate a response to an SSH command
        
        (Original function preserved exactly as provided—no changes)
        """
        interaction_level = self.service_config.get("interaction_level", "medium")

        # Handle common system commands
        if command.startswith("cd "):
            return ""  # Just acknowledge cd commands silently

        elif command == "pwd":
            return "/home/user\r\n"

        elif command == "whoami":
            return "user\r\n"

        elif command == "id":
            return "uid=1000(user) gid=1000(user) groups=1000(user)\r\n"

        elif command == "uname -a":
            return f"Linux {self.config['deception']['system_info']['hostname']} {self.config['deception']['system_info']['kernel']} GNU/Linux\r\n"

        elif command == "hostname":
            return f"{self.config['deception']['system_info']['hostname']}\r\n"

        elif command.startswith("ls"):
            # Simulate different directories
            if " /etc" in command:
                return "apache2  cron.d  hosts  motd  passwd  shadow  ssh\r\n"
            elif " /var" in command:
                return "backups  cache  lib  log  mail  spool  www\r\n"
            else:
                return ".bash_history  .bashrc  .profile  .ssh  documents  secret.txt\r\n"

        elif command == "cat secret.txt":
            if interaction_level == "high":
                if self.config["deception"]["breadcrumbs"]:
                    return "Database credentials:\nUser: dbadmin\nPassword: Str0ngP@$w0rd\nServer: 192.168.1.10\r\n"
                else:
                    return "Permission denied\r\n"
            else:
                return "Permission denied\r\n"

        elif command.startswith("ps"):
            return " PID TTY          TIME CMD\n 1234 pts/0    00:00:00 bash\n 5678 pts/0    00:00:00 ps\n"

        elif command.startswith("netstat") or command.startswith("ss"):
            return ("tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
                    "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
                    "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\n")

        elif command.startswith("ifconfig") or command.startswith("ip a"):
            return ("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                    "        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n")

        elif command.startswith("wget") or command.startswith("curl"):
            if any(x in command for x in [".sh", ".pl", ".py", ".bin", ".elf", ".malware"]):
                self.logger.warning(f"Possible malware download attempt: {command}")
            return "Connecting...\nHTTP request sent, awaiting response... 404 Not Found\r\n"

        elif "passwd" in command:
            return "Changing password for user.\nCurrent password: \r\n"

        elif command.startswith("sudo"):
            return "[sudo] password for user: Sorry, try again.\r\n"

        return super().simulate_command_response(command, context)

class CustomSSHServerInterface(paramiko.ServerInterface):
    def __init__(self, service: SSHService):
        self.event = threading.Event()
        self.service = service
        self.username = ""

    def check_auth_password(self, username, password):
        self.username = username
        if self.service.is_valid_credentials(username, password):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
