#!/usr/bin/env python3
"""
FTP service emulator for the honeypot system
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

class FTPService(BaseService):
    """FTP service emulator for the honeypot"""
    
    def __init__(self, host: str, port: int, config: Dict[str, Any]):
        """
        Initialize the FTP service
        
        Args:
            host: Host IP to bind to
            port: Port to listen on
            config: Global configuration dictionary
        """
        super().__init__(host, port, config, "ftp")
        
        # Set up FTP server
        self.banner = self.service_config.get("banner", "220 FTP Server Ready")
        
        # Create fake filesystem structure
        self.ftproot = os.path.join("data", "ftp")
        os.makedirs(self.ftproot, exist_ok=True)
        
        # Ensure some default files exist
        self._ensure_default_files()
        
        # Track active FTP sessions
        self.sessions = {}
    
    def _ensure_default_files(self) -> None:
        """Ensure default FTP files exist"""
        # Create a README file
        readme_path = os.path.join(self.ftproot, "README.txt")
        if not os.path.exists(readme_path):
            with open(readme_path, "w") as f:
                f.write("This is the FTP server root directory.\n")
        
        # Create a sample data directory
        data_dir = os.path.join(self.ftproot, "data")
        os.makedirs(data_dir, exist_ok=True)
        
        # Create a sample file in the data directory
        sample_path = os.path.join(data_dir, "sample.txt")
        if not os.path.exists(sample_path):
            with open(sample_path, "w") as f:
                f.write("This is a sample file in the data directory.\n")
        
        # Create an upload directory
        upload_dir = os.path.join(self.ftproot, "upload")
        os.makedirs(upload_dir, exist_ok=True)
        
        # Create a private directory
        private_dir = os.path.join(self.ftproot, "private")
        os.makedirs(private_dir, exist_ok=True)
        
        # Create a configuration file with fake sensitive data
        if self.config["deception"]["breadcrumbs"]:
            config_path = os.path.join(private_dir, "config.ini")
            if not os.path.exists(config_path):
                with open(config_path, "w") as f:
                    f.write("""[database]
host = 192.168.1.10
port = 3306
user = dbadmin
password = Str0ngP@$$w0rd
database = production

[api]
key = f8a7c6b5e4d3c2b1a0
secret = 9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2

[server]
hostname = web-prod-01
environment = production
""")
    
    def handle_client(self, client_socket: socket.socket, address: Tuple[str, int], 
                     connection_data: Dict[str, Any]) -> None:
        """
        Handle a client connection to the FTP service
        
        Args:
            client_socket: Client socket object
            address: Client address tuple (ip, port)
            connection_data: Dictionary to store connection data for logging
        """
        # Create a unique session ID for this connection
        session_id = f"{address[0]}:{address[1]}:{time.time()}"
        
        # Initialize session state
        self.sessions[session_id] = {
            "authenticated": False,
            "username": None,
            "current_dir": "/",
            "binary_mode": False,
            "passive_mode": False,
            "data_port": None,
            "data_ip": None,
            "commands": []
        }
        
        # Send welcome banner
        self._send_response(client_socket, self.banner)
        
        try:
            authenticated = False
            quit_command_received = False
            
            while not quit_command_received:
                # Receive command
                cmd_line = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
                if not cmd_line:
                    break
                
                # Parse command and arguments
                if " " in cmd_line:
                    cmd, arg = cmd_line.split(" ", 1)
                else:
                    cmd, arg = cmd_line, ""
                
                cmd = cmd.upper()
                
                # Log the command
                cmd_info = {
                    "command": cmd,
                    "argument": arg,
                    "timestamp": datetime.datetime.now().isoformat()
                }
                self.sessions[session_id]["commands"].append(cmd_info)
                
                # Add command to connection data
                if "commands" not in connection_data["data"]:
                    connection_data["data"]["commands"] = []
                connection_data["data"]["commands"].append(cmd_info)
                
                self.logger.debug(f"FTP command from {address[0]}: {cmd} {arg}")
                
                # Process commands
                if cmd == "USER":
                    # Store the username for later authentication
                    self.sessions[session_id]["username"] = arg
                    self._send_response(client_socket, "331 User name okay, need password.")
                
                elif cmd == "PASS":
                    # Check if username was provided
                    username = self.sessions[session_id]["username"]
                    if not username:
                        self._send_response(client_socket, "503 Login with USER first.")
                        continue
                    
                    # Log the authentication attempt
                    auth_data = {
                        "username": username,
                        "password": arg,
                        "timestamp": datetime.datetime.now().isoformat()
                    }
                    
                    if "auth_attempts" not in connection_data["data"]:
                        connection_data["data"]["auth_attempts"] = []
                        
                    connection_data["data"]["auth_attempts"].append(auth_data)
                    
                    # Check credentials
                    if self.is_valid_credentials(username, arg):
                        # Authentication successful
                        self.sessions[session_id]["authenticated"] = True
                        authenticated = True
                        connection_data["data"]["auth_result"] = "success"
                        self._send_response(client_socket, "230 User logged in, proceed.")
                        self.logger.info(f"Successful FTP authentication from {address[0]} with username '{username}' and password '{arg}'")
                    else:
                        # Authentication failed
                        connection_data["data"]["auth_result"] = "failure"
                        self._send_response(client_socket, "530 Login incorrect.")
                        self.logger.info(f"Failed FTP authentication from {address[0]} with username '{username}' and password '{arg}'")
                
                elif cmd == "QUIT":
                    self._send_response(client_socket, "221 Goodbye.")
                    quit_command_received = True
                
                elif not authenticated:
                    # Require authentication for all other commands
                    self._send_response(client_socket, "530 Not logged in.")
                
                elif cmd == "PWD":
                    # Print working directory
                    current_dir = self.sessions[session_id]["current_dir"]
                    self._send_response(client_socket, f'257 "{current_dir}" is the current directory.')
                
                elif cmd == "CWD":
                    # Change working directory
                    new_dir = self._clean_path(arg, self.sessions[session_id]["current_dir"])
                    self.sessions[session_id]["current_dir"] = new_dir
                    self._send_response(client_socket, f'250 Directory changed to {new_dir}')
                
                elif cmd == "CDUP":
                    # Change to parent directory
                    current_dir = self.sessions[session_id]["current_dir"]
                    if current_dir == "/":
                        new_dir = "/"
                    else:
                        new_dir = "/".join(current_dir.split("/")[:-1])
                        if not new_dir:
                            new_dir = "/"
                    
                    self.sessions[session_id]["current_dir"] = new_dir
                    self._send_response(client_socket, f'250 Directory changed to {new_dir}')
                
                elif cmd == "TYPE":
                    # Set transfer type
                    if arg == "A":
                        self.sessions[session_id]["binary_mode"] = False
                        self._send_response(client_socket, "200 Type set to A.")
                    elif arg == "I":
                        self.sessions[session_id]["binary_mode"] = True
                        self._send_response(client_socket, "200 Type set to I.")
                    else:
                        self._send_response(client_socket, "504 Command not implemented for that parameter.")
                
                elif cmd == "PASV":
                    # Enter passive mode
                    self.sessions[session_id]["passive_mode"] = True
                    
                    # Bind to a random port for data connection
                    data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    data_sock.bind((self.host, 0))
                    data_sock.listen(1)
                    
                    # Get the port number
                    _, data_port = data_sock.getsockname()
                    self.sessions[session_id]["data_port"] = data_port
                    
                    # Convert IP and port to FTP passive mode format
                    ip_parts = self.host.split(".")
                    port_high = data_port // 256
                    port_low = data_port % 256
                    
                    pasv_response = f"227 Entering Passive Mode ({','.join(ip_parts)},{port_high},{port_low})."
                    self._send_response(client_socket, pasv_response)
                    
                    # Wait for data connection in a separate thread
                    data_thread = threading.Thread(
                        target=self._handle_passive_connection,
                        args=(data_sock, session_id)
                    )
                    data_thread.daemon = True
                    data_thread.start()
                
                elif cmd == "PORT":
                    # Enter active mode
                    self.sessions[session_id]["passive_mode"] = False
                    
                    # Parse the PORT command argument
                    parts = arg.split(",")
                    if len(parts) != 6:
                        self._send_response(client_socket, "501 Syntax error in parameters.")
                        continue
                    
                    # Extract IP and port
                    ip = ".".join(parts[:4])
                    port = (int(parts[4]) * 256) + int(parts[5])
                    
                    self.sessions[session_id]["data_ip"] = ip
                    self.sessions[session_id]["data_port"] = port
                    
                    self._send_response(client_socket, "200 PORT command successful.")
                
                elif cmd == "LIST":
                    # List directory contents
                    self._send_response(client_socket, "150 Opening ASCII mode data connection for file list.")
                    
                    # Simulate directory listing
                    current_dir = self.sessions[session_id]["current_dir"]
                    listing = self._get_directory_listing(current_dir)
                    
                    # Send listing via data connection
                    if self.sessions[session_id]["passive_mode"]:
                        # Data connection is handled by _handle_passive_connection
                        if "data_sock" in self.sessions[session_id]:
                            data_sock = self.sessions[session_id]["data_sock"]
                            data_sock.send(listing.encode())
                            data_sock.close()
                            del self.sessions[session_id]["data_sock"]
                            self._send_response(client_socket, "226 Transfer complete.")
                        else:
                            self._send_response(client_socket, "425 Can't open data connection.")
                    else:
                        # Active mode - connect to client
                        try:
                            data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            data_sock.connect((self.sessions[session_id]["data_ip"], self.sessions[session_id]["data_port"]))
                            data_sock.send(listing.encode())
                            data_sock.close()
                            self._send_response(client_socket, "226 Transfer complete.")
                        except Exception as e:
                            self.logger.error(f"Error sending data in active mode: {e}")
                            self._send_response(client_socket, "425 Can't open data connection.")
                
                elif cmd == "RETR":
                    # Retrieve a file
                    filename = arg
                    self._send_response(client_socket, f"550 File not found: {filename}")
                
                elif cmd == "STOR":
                    # Store a file
                    filename = arg
                    self._send_response(client_socket, f"553 Could not create file: {filename}")
                
                elif cmd == "SYST":
                    # Return system type
                    self._send_response(client_socket, "215 UNIX Type: L8")
                
                elif cmd == "NOOP":
                    # No operation
                    self._send_response(client_socket, "200 NOOP command successful.")
                
                else:
                    # Command not implemented
                    self._send_response(client_socket, "502 Command not implemented.")
        
        except Exception as e:
            self.logger.error(f"Error handling FTP client: {e}")
            connection_data["error"] = str(e)
        finally:
            # Clean up session data
            if session_id in self.sessions:
                del self.sessions[session_id]
    
    def _send_response(self, client_socket: socket.socket, response: str) -> None:
        """
        Send an FTP response to the client
        
        Args:
            client_socket: Client socket object
            response: Response string
        """
        try:
            client_socket.send(f"{response}\r\n".encode())
        except Exception as e:
            self.logger.error(f"Error sending FTP response: {e}")
    
    def _handle_passive_connection(self, data_sock: socket.socket, session_id: str) -> None:
        """
        Handle a passive data connection
        
        Args:
            data_sock: Data socket object
            session_id: Session ID
        """
        try:
            # Wait for client to connect (with timeout)
            data_sock.settimeout(30)
            client_sock, addr = data_sock.accept()
            
            # Store the data socket in the session
            self.sessions[session_id]["data_sock"] = client_sock
            
        except socket.timeout:
            self.logger.warning(f"Timeout waiting for data connection for session {session_id}")
        except Exception as e:
            self.logger.error(f"Error handling passive connection: {e}")
        finally:
            # Close the server socket
            data_sock.close()
    
    def _clean_path(self, path: str, current_dir: str) -> str:
        """
        Clean and normalize a path
        
        Args:
            path: Path to clean
            current_dir: Current directory
            
        Returns:
            Cleaned path
        """
        # Handle absolute paths
        if path.startswith("/"):
            new_path = path
        else:
            # Handle relative paths
            if current_dir.endswith("/"):
                new_path = current_dir + path
            else:
                new_path = current_dir + "/" + path
        
        # Normalize path
        parts = []
        for part in new_path.split("/"):
            if part == "..":
                if parts:
                    parts.pop()
            elif part and part != ".":
                parts.append(part)
        
        # Rebuild path
        clean_path = "/" + "/".join(parts)
        if not clean_path:
            clean_path = "/"
            
        return clean_path
    
    def _get_directory_listing(self, path: str) -> str:
        """
        Get a simulated directory listing
        
        Args:
            path: Directory path
            
        Returns:
            Directory listing string
        """
        # Build a fake directory listing based on path
        listing = ""
        
        if path == "/" or path == "":
            listing += "-rw-r--r--  1 ftp  ftp     145 Apr 07 14:23 README.txt\r\n"
            listing += "drwxr-xr-x  2 ftp  ftp    4096 Apr 07 14:23 data\r\n"
            listing += "drwxr-xr-x  2 ftp  ftp    4096 Apr 07 14:23 upload\r\n"
            listing += "drwx------  2 ftp  ftp    4096 Apr 07 14:23 private\r\n"
        elif path == "/data":
            listing += "-rw-r--r--  1 ftp  ftp     256 Apr 07 14:23 sample.txt\r\n"
            listing += "-rw-r--r--  1 ftp  ftp    1024 Apr 07 14:23 data.csv\r\n"
        elif path == "/private":
            # Only show contents if breadcrumbs are enabled
            if self.config["deception"]["breadcrumbs"]:
                listing += "-rw-------  1 ftp  ftp     512 Apr 07 14:23 config.ini\r\n"
            # Otherwise, return empty directory
        elif path == "/upload":
            # Empty directory
            pass
        else:
            # Directory not found
            pass
        
        return listing
