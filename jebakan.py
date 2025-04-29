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
import sys
from typing import Dict, List, Any, Tuple, Optional

from services.base_service import BaseService

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)  # <-- ensures console output
    ]
)

class SSHService(BaseService):
    """SSH service emulator for the honeypot"""
    
    def __init__(self, host: str, port: int, config: Dict[str, Any], unified_logger=None):
        super().__init__(host, port, config, "ssh")
        self.unified_logger = unified_logger
        
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
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="ssh",
                    attacker_ip="system",
                    attacker_port=0,
                    command="system_event",
                    additional_data={"message": "Generating SSH host key"}
                )
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
            
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="ssh",
                    attacker_ip="system",
                    attacker_port=0,
                    command="service_start",
                    additional_data={"port": self.port}
                )
            
            self.logger.info(f"SSH honeypot started on port {self.port}")
            
            while self.running:
                try:
                    client, addr = self.sock.accept()
                    
                    # Log connection attempt
                    if self.unified_logger:
                        self.unified_logger.log_attack(
                            service="ssh",
                            attacker_ip=addr[0],
                            attacker_port=addr[1],
                            command="connection_attempt",
                            additional_data={"timestamp": datetime.datetime.now().isoformat()}
                        )
                    
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
                    if self.unified_logger:
                        self.unified_logger.log_attack(
                            service="ssh",
                            attacker_ip="error",
                            attacker_port=0,
                            command="error",
                            additional_data={"error": str(e)}
                        )
                    self.logger.error(f"Error accepting connection: {e}")
                    
        except Exception as e:
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="ssh",
                    attacker_ip="error",
                    attacker_port=0,
                    command="service_error",
                    additional_data={"error": str(e)}
                )
            self.logger.error(f"Error starting SSH service: {e}")
        finally:
            if self.sock:
                self.sock.close()

    def handle_client(self, client_socket: socket.socket, address: Tuple[str, int],
                      connection_data: Dict[str, Any]) -> None:
        """
        Handle an SSH client connection
        
        Args:
            client_socket: Client socket object
            address: Client address tuple (ip, port)
            connection_data: Dictionary to store connection data for logging
        """
        session_id = f"{address[0]}:{address[1]}:{time.time()}"
        self.command_history[session_id] = []
    
        # Create the transport first
        transport = paramiko.Transport(client_socket)
        
        # Then set the banner
        try:
            transport.local_version = self.banner
        except Exception as e:
            self.logger.error(f"Error setting banner: {e}")
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="ssh",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="error",
                    additional_data={"error": f"Banner set error: {str(e)}"}
                )
            return
        
        transport.add_server_key(paramiko.RSAKey(filename=self.key_file))
        server_interface = CustomSSHServerInterface(self)
    
        try:
            self.logger.info(f"[{address}] Starting SSH session")
            transport.start_server(server=server_interface)
    
            chan = transport.accept(10)
            if chan is None:
                self.logger.error(f"[{address}] No channel opened")
                return
    
            self.logger.info(f"[{address}] Channel accepted")
    
            if not server_interface.event.wait(5):
                self.logger.error(f"[{address}] Shell not requested in time")
                chan.close()
                return
    
            if not chan.send_ready():
                self.logger.warning(f"[{address}] Channel not ready for send()")
                chan.close()
                return
    
            chan.settimeout(15.0)
            hostname = self.config["deception"]["system_info"]["hostname"]
            username = server_interface.username or "user"
    
            # Log the authentication to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="ssh",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="login_success",
                    additional_data={
                        "username": server_interface.username,
                        "password": server_interface.password if hasattr(server_interface, "password") else "unknown",
                        "session_id": session_id
                    }
                )
    
            chan.send(b"DEBUG: shell started\r\n")
            chan.send(f"Welcome to Ubuntu 18.04.5 LTS ({hostname})\r\n".encode())
            chan.send(f"{username}@{hostname}:~$ ".encode())
    
            buffer = ''
    
            while True:
                try:
                    data = chan.recv(1024)
                    if not data:
                        self.logger.info(f"[{address}] Channel closed")
                        break
    
                    decoded = data.decode('utf-8', errors='ignore')
                    self.logger.info(f"[{address}] RAW input: {repr(decoded)}")
                    buffer += decoded
                    chan.send(decoded.encode())  # echo each character back as typed
    
                    if '\n' in buffer or '\r' in buffer:
                        command = buffer.strip().replace('\r', '').replace('\n', '')
                        buffer = ''
    
                        if not command:
                            chan.send(f"{username}@{hostname}:~$ ".encode())
                            continue
    
                        self.logger.info(f"[{address}] Command received: {command}")
                        
                        # Log command to unified logger
                        if self.unified_logger:
                            self.unified_logger.log_attack(
                                service="ssh",
                                attacker_ip=address[0],
                                attacker_port=address[1],
                                command=command,
                                additional_data={
                                    "session_id": session_id,
                                    "timestamp": datetime.datetime.now().isoformat()
                                }
                            )
                        
                        self.command_history[session_id].append({
                            "command": command,
                            "timestamp": datetime.datetime.now().isoformat()
                        })
    
                        if command.lower() in ['exit', 'logout', 'quit']:
                            chan.send(b"logout\r\n")
                            break
    
                        chan.send((command + '\r\n').encode())
                        response = self.simulate_command_response(command, address=address)
                        if not response.endswith('\n'):
                            response += '\r\n'
                        chan.send(response.encode())
                        chan.send(f"{username}@{hostname}:~$ ".encode())
    
                except socket.timeout:
                    continue
                except Exception as e:
                    self.logger.error(f"[{address}] Error: {e}")
                    if self.unified_logger:
                        self.unified_logger.log_attack(
                            service="ssh",
                            attacker_ip=address[0],
                            attacker_port=address[1],
                            command="error",
                            additional_data={"error": str(e)}
                        )
                    break
    
        except Exception as e:
            self.logger.error(f"[{address}] SSH session error: {e}")
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="ssh",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="session_error",
                    additional_data={"error": str(e)}
                )
            connection_data["error"] = str(e)
        finally:
            try:
                if 'chan' in locals() and chan:
                    chan.close()
                transport.close()
                client_socket.close()
            except Exception:
                pass
            connection_data["data"]["command_history"] = self.command_history.pop(session_id, [])
    
    def simulate_command_response(self, command: str, context: Dict[str, Any] = None, address: Tuple[str, int] = None) -> str:
            """
            Simulate a response to an SSH command
            """
            interaction_level = self.service_config.get("interaction_level", "medium")
            hostname = self.config["deception"]["system_info"]["hostname"]
    
            if command.startswith("cd "):
                return ""
    
            elif command == "pwd":
                return "/home/user\r\n"
    
            elif command == "whoami":
                return "user\r\n"
    
            elif command == "id":
                return "uid=1000(user) gid=1000(user) groups=1000(user)\r\n"
    
            elif command == "uname -a":
                return f"Linux {hostname} {self.config['deception']['system_info']['kernel']} GNU/Linux\r\n"
    
            elif command == "hostname":
                return f"{hostname}\r\n"
    
            elif command.startswith("ls"):
                if " /etc" in command:
                    return "apache2  cron.d  hosts  motd  passwd  shadow  ssh\r\n"
                elif " /var" in command:
                    return "backups  cache  lib  log  mail  spool  www\r\n"
                else:
                    return ".bash_history  .bashrc  .profile  .ssh  documents  secret.txt\r\n"
    
            elif command == "cat secret.txt":
                if interaction_level == "high":
                    if self.config["deception"]["breadcrumbs"]:
                        # Log sensitive file access to unified logger
                        if self.unified_logger and address:
                            self.unified_logger.log_attack(
                                service="ssh",
                                attacker_ip=address[0],
                                attacker_port=address[1],
                                command="sensitive_file_access",
                                additional_data={
                                    "file": "secret.txt",
                                    "timestamp": datetime.datetime.now().isoformat()
                                }
                            )
                        return (
                            "Database credentials:\r\n"
                            "User: dbadmin\r\n"
                            "Password: Str0ngP@$w0rd\r\n"
                            "Server: 192.168.1.10\r\n"
                        )
                    else:
                        return "Permission denied\r\n"
                else:
                    return "Permission denied\r\n"
    
            elif command.startswith("ps"):
                return (
                    " PID TTY          TIME CMD\r\n"
                    " 1234 pts/0    00:00:00 bash\r\n"
                    " 5678 pts/0    00:00:00 ps\r\n"
                )
    
            elif command.startswith("netstat") or command.startswith("ss"):
                return (
                    "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n"
                    "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\r\n"
                    "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\r\n"
                )
    
            elif command.startswith("ifconfig") or command.startswith("ip a"):
                return (
                    "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
                    "        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\r\n"
                )
    
            elif command.startswith("wget") or command.startswith("curl"):
                if any(x in command for x in [".sh", ".pl", ".py", ".bin", ".elf", ".malware"]):
                    self.logger.warning(f"Possible malware download attempt: {command}")
                    
                    # Log malware download attempt to unified logger
                    if self.unified_logger and address:
                        self.unified_logger.log_attack(
                            service="ssh",
                            attacker_ip=address[0],
                            attacker_port=address[1],
                            command="malware_download_attempt",
                            additional_data={
                                "url": command.split()[-1] if len(command.split()) > 1 else "unknown",
                                "timestamp": datetime.datetime.now().isoformat()
                            }
                        )
                        
                return "Connecting...\r\nHTTP request sent, awaiting response... 404 Not Found\r\n"
    
            elif "passwd" in command:
                return "Changing password for user.\r\nCurrent password: \r\n"
    
            elif command.startswith("sudo"):
                return "[sudo] password for user: Sorry, try again.\r\n"
    
            return f"Command not found: {command}\r\n"

    def is_valid_credentials(self, username: str, password: str) -> bool:
        """
        Check if username/password combination is valid based on the configuration
    
        Args:
            username: Username to check
            password: Password to check
    
        Returns:
            True if credentials are valid, False otherwise
        """
        # Get credentials from the configuration
        valid_credentials = self.service_config.get("credentials", [])
        
        # Check if the credentials match any in the configuration
        for cred in valid_credentials:
            if cred.get("username") == username and cred.get("password") == password:
                return True
        
        return False

class CustomSSHServerInterface(paramiko.ServerInterface):
    def __init__(self, service: SSHService):
        self.event = threading.Event()
        self.service = service
        self.username = ""
        self.password = ""

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        
        # Log authentication attempt to unified logger
        if self.service.unified_logger:
            self.service.unified_logger.log_attack(
                service="ssh",
                attacker_ip="unknown",  # We don't have access to the IP here directly
                attacker_port=0,
                command="login_attempt",
                additional_data={
                    "username": username,
                    "password": password,
                    "success": self.service.is_valid_credentials(username, password)
                }
            )
            
        return paramiko.AUTH_SUCCESSFUL if self.service.is_valid_credentials(username, password) else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
