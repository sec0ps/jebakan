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
        """
        Initialize the SSH service
        
        Args:
            host: Host IP to bind to
            port: Port to listen on
            config: Global configuration dictionary
        """
        super().__init__(host, port, config, "ssh")
        
        # Generate SSH server key if needed
        self.key_file = os.path.join("data", "ssh_host_rsa_key")
        self._ensure_server_key()
        
        # Set up SSH server
        self.server = paramiko.Transport((host, port))
        self.server.add_server_key(paramiko.RSAKey(filename=self.key_file))
        
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
        """Start the SSH service"""
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            self.running = True
            self.logger.info(f"SSH honeypot started on port {self.port}")
            
            # Custom SSH server implementation
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
        # Create a unique session ID for this connection
        session_id = f"{address[0]}:{address[1]}:{time.time()}"
        
        # Initialize command history for this session
        self.command_history[session_id] = []
        
        # Send SSH banner
        client_socket.send(f"{self.banner}\r\n".encode())
        
        try:
            # Receive client banner
            banner_data = client_socket.recv(1024)
            if not banner_data:
                return
                
            client_banner = banner_data.decode('utf-8', errors='ignore').strip()
            connection_data["data"]["client_banner"] = client_banner
            self.logger.debug(f"Client banner: {client_banner}")
            
            # Extract client version if possible
            match = re.search(r"SSH-\d+\.\d+-([^\s]+)", client_banner)
            if match:
                client_version = match.group(1)
                connection_data["data"]["client_version"] = client_version
                self.logger.debug(f"Client version: {client_version}")
            
            # Perform key exchange (simplified)
            # In a real implementation, this would be a proper SSH key exchange
            time.sleep(0.5)  # Simulate processing time
            
            # Authentication phase
            auth_attempts = 0
            max_auth_attempts = self.service_config.get("auth_attempts", 3)
            auth_successful = False
            
            while auth_attempts < max_auth_attempts and not auth_successful:
                # Send username prompt
                client_socket.send(b"login as: ")
                username_data = client_socket.recv(1024)
                if not username_data:
                    break
                    
                username = username_data.decode('utf-8', errors='ignore').strip()
                
                # Send password prompt
                client_socket.send(f"{username}@{self.config['deception']['system_info']['hostname']}'s password: ".encode())
                password_data = client_socket.recv(1024)
                if not password_data:
                    break
                    
                password = password_data.decode('utf-8', errors='ignore').strip()
                
                # Log the authentication attempt
                auth_data = {
                    "username": username,
                    "password": password,
                    "attempt": auth_attempts + 1,
                    "timestamp": datetime.datetime.now().isoformat()
                }
                
                if "auth_attempts" not in connection_data["data"]:
                    connection_data["data"]["auth_attempts"] = []
                    
                connection_data["data"]["auth_attempts"].append(auth_data)
                
                # Check credentials
                auth_successful = self.is_valid_credentials(username, password)
                
                if auth_successful:
                    # Authentication successful
                    client_socket.send(b"\r\nWelcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-112-generic x86_64)\r\n\r\n")
                    client_socket.send(b"Last login: Mon Apr 07 14:23:16 2025 from 192.168.1.5\r\n")
                    connection_data["data"]["auth_result"] = "success"
                    self.logger.info(f"Successful authentication from {address[0]} with username '{username}' and password '{password}'")
                else:
                    # Authentication failed
                    auth_attempts += 1
                    if auth_attempts < max_auth_attempts:
                        client_socket.send(b"Access denied\r\n")
                    else:
                        client_socket.send(b"Too many authentication failures\r\n")
                        connection_data["data"]["auth_result"] = "failure"
                        self.logger.info(f"Failed authentication from {address[0]} after {auth_attempts} attempts")
                        break
            
            # If authentication was successful, proceed to shell emulation
            if auth_successful:
                self._simulate_shell(client_socket, session_id, connection_data)
                
        except Exception as e:
            self.logger.error(f"Error handling SSH client: {e}")
            connection_data["error"] = str(e)
        finally:
            # Clean up session data
            if session_id in self.command_history:
                connection_data["data"]["command_history"] = self.command_history[session_id]
                del self.command_history[session_id]
    
    def _simulate_shell(self, client_socket: socket.socket, session_id: str, 
                        connection_data: Dict[str, Any]) -> None:
        """
        Simulate an SSH shell
        
        Args:
            client_socket: Client socket object
            session_id: Unique session identifier
            connection_data: Dictionary to store connection data for logging
        """
        # Send initial prompt
        hostname = self.config["deception"]["system_info"]["hostname"]
        prompt = f"{connection_data['data']['auth_attempts'][0]['username']}@{hostname}:~$ "
        client_socket.send(prompt.encode())
        
        # Interactive shell loop
        while True:
            try:
                # Receive command
                command_data = client_socket.recv(1024)
                if not command_data:
                    break
                    
                command = command_data.decode('utf-8', errors='ignore').strip()
                
                # Check for exit command
                if command.lower() in ["exit", "logout", "quit"]:
                    client_socket.send(b"logout\r\n")
                    break
                
                # Log the command
                command_info = {
                    "command": command,
                    "timestamp": datetime.datetime.now().isoformat()
                }
                self.command_history[session_id].append(command_info)
                
                # Generate response based on interaction level
                response = self.simulate_command_response(command)
                
                # Send response and new prompt
                client_socket.send(response.encode())
                client_socket.send(prompt.encode())
                
            except socket.timeout:
                break
            except Exception as e:
                self.logger.error(f"Error in SSH shell simulation: {e}")
                break
    
    def simulate_command_response(self, command: str, context: Dict[str, Any] = None) -> str:
        """
        Simulate a response to an SSH command
        
        Args:
            command: The command to respond to
            context: Optional context dictionary with additional information
            
        Returns:
            String response to the command
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
                # Add breadcrumbs if enabled
                if self.config["deception"]["breadcrumbs"]:
                    return "Database credentials:\nUser: dbadmin\nPassword: Str0ngP@$w0rd\nServer: 192.168.1.10\r\n"
                else:
                    return "Permission denied\r\n"
            else:
                return "Permission denied\r\n"
                
        elif command.startswith("ps"):
            return " PID TTY          TIME CMD\n 1234 pts/0    00:00:00 bash\n 5678 pts/0    00:00:00 ps\n"
            
        elif command.startswith("netstat") or command.startswith("ss"):
            return "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n" + \
                   "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n" + \
                   "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\n"
                   
        elif command.startswith("ifconfig") or command.startswith("ip a"):
            return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n" + \
                   "        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n"
                   
        elif command.startswith("wget") or command.startswith("curl"):
            # Log attempts to download malware
            if any(x in command for x in [".sh", ".pl", ".py", ".bin", ".elf", ".malware"]):
                self.logger.warning(f"Possible malware download attempt: {command}")
                
            return "Connecting...\nHTTP request sent, awaiting response... 404 Not Found\r\n"
            
        elif "passwd" in command:
            return "Changing password for user.\nCurrent password: \r\n"
            
        elif command.startswith("sudo"):
            return "[sudo] password for user: Sorry, try again.\r\n"
            
        # Fall back to basic command handling
        return super().simulate_command_response(command, context)
