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
    
    def __init__(self, host: str, port: int, config: Dict[str, Any], unified_logger=None):
        """
        Initialize the FTP service
        
        Args:
            host: Host IP to bind to
            port: Port to listen on
            config: Global configuration dictionary
            unified_logger: Unified logging system
        """
        super().__init__(host, port, config, "ftp")
        self.unified_logger = unified_logger
        
        # Verify that credentials were loaded
        self.logger.debug(f"FTP Service initialized. Path to config: {config.get('config_path', 'Unknown')}")
        self.logger.debug(f"Available credentials: {self.credentials}")
        self.logger.debug(f"Service config: {self.service_config}")

        # Set up FTP server banner as an instance attribute
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
        """
        session_id = f"{address[0]}:{address[1]}:{time.time()}"
        self.sessions[session_id] = {
            "authenticated": False,
            "username": None,
            "current_dir": "/",
            "binary_mode": False,
            "passive_mode": False,
            "data_port": None,
            "data_ip": None,
            "commands": [],
            "data_sock": None  # explicitly track the passive socket
        }
    
        self._send_response(client_socket, self.banner)
    
        try:
            while True:
                cmd_line = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
                if not cmd_line:
                    break
    
                if " " in cmd_line:
                    cmd, arg = cmd_line.split(" ", 1)
                else:
                    cmd, arg = cmd_line, ""
    
                cmd = cmd.upper()
    
                session = self.sessions[session_id]
                current_dir = session["current_dir"]
    
                # Record the command in connection data if available
                if "data" in connection_data:
                    connection_data["data"].setdefault("commands", []).append({
                        "timestamp": datetime.datetime.now().isoformat(),
                        "command": cmd_line
                    })
    
                if cmd == "USER":
                    session["username"] = arg
                    self._send_response(client_socket, "331 User name okay, need password.")
                elif cmd == "PASS":
                    username = session["username"]
                    password = arg
                    
                    # Log the authentication attempt
                    auth_data = {
                        "username": username,
                        "password": password,
                        "timestamp": datetime.datetime.now().isoformat()
                    }
                    
                    # Add to connection data if available
                    if "data" in connection_data:
                        connection_data["data"].setdefault("auth_attempts", []).append(auth_data)
                    
                    self.logger.info(f"FTP authentication attempt from {address[0]} with username '{username}' and password '{password}'")
                    
                    # Log the authentication attempt to the unified logger
                    if self.unified_logger:
                        self.unified_logger.log_attack(
                            service="ftp",
                            attacker_ip=address[0],
                            attacker_port=address[1],
                            command="login_attempt",
                            additional_data=auth_data
                        )
                    
                    if self.is_valid_credentials(username, password):
                        session["authenticated"] = True
                        self._send_response(client_socket, "230 User logged in, proceed.")
                    else:
                        self._send_response(client_socket, "530 Login incorrect.")
                elif not session["authenticated"]:
                    self._send_response(client_socket, "530 Not logged in.")
                elif cmd == "PWD":
                    self._send_response(client_socket, f'257 "{current_dir}" is the current directory.')
                elif cmd == "CWD":
                    new_dir = self._clean_path(arg, current_dir)
                    session["current_dir"] = new_dir
                    self._send_response(client_socket, f'250 Directory changed to {new_dir}')
                elif cmd == "TYPE":
                    if arg.upper() == "I":
                        session["binary_mode"] = True
                        self._send_response(client_socket, "200 Type set to I.")
                    else:
                        session["binary_mode"] = False
                        self._send_response(client_socket, "200 Type set to A.")
                elif cmd == "PASV":
                    # Open passive socket
                    psock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    psock.bind((self.host, 0))
                    psock.listen(1)
                    _, data_port = psock.getsockname()
    
                    # Fix passive IP response
                    real_host = self.config.get("public_ip", self.host)
                    if real_host == "0.0.0.0":
                        real_host = "127.0.0.1"
    
                    ip_parts = real_host.split(".")
                    p1, p2 = data_port // 256, data_port % 256
                    self._send_response(client_socket, f"227 Entering Passive Mode ({','.join(ip_parts)},{p1},{p2}).")
    
                    # Accept data connection in background
                    def wait_for_data_conn():
                        try:
                            psock.settimeout(10)
                            dsock, _ = psock.accept()
                            session["data_sock"] = dsock
                        except Exception as e:
                            self.logger.warning(f"Passive mode connection failed: {e}")
                        finally:
                            psock.close()
    
                    threading.Thread(target=wait_for_data_conn, daemon=True).start()
    
                elif cmd == "LIST":
                    # Log the LIST command to unified logger
                    if self.unified_logger:
                        self.unified_logger.log_attack(
                            service="ftp",
                            attacker_ip=address[0],
                            attacker_port=address[1],
                            command=f"LIST {arg}"
                        )
                    
                    self._send_response(client_socket, "150 Here comes the directory listing.")
                    time.sleep(1)
                    if session["data_sock"]:
                        listing = self._get_directory_listing(current_dir)
                        try:
                            session["data_sock"].sendall(listing.encode())
                            session["data_sock"].close()
                            session["data_sock"] = None
                            self._send_response(client_socket, "226 Directory send OK.")
                        except Exception as e:
                            self.logger.error(f"LIST failed: {e}")
                            self._send_response(client_socket, "426 Data connection error.")
                    else:
                        self._send_response(client_socket, "425 Can't open data connection.")
    
                elif cmd == "RETR":
                    # Log the file retrieval attempt to unified logger
                    if self.unified_logger:
                        self.unified_logger.log_attack(
                            service="ftp",
                            attacker_ip=address[0],
                            attacker_port=address[1],
                            command=f"RETR {arg}"
                        )
                    
                    file_path = os.path.join(self.ftproot, current_dir.strip("/"), arg)
                    if os.path.isfile(file_path) and session["data_sock"]:
                        self._send_response(client_socket, f"150 Opening binary mode data connection for {arg}")
                        try:
                            with open(file_path, "rb") as f:
                                data = f.read()
                            session["data_sock"].sendall(data)
                            session["data_sock"].close()
                            session["data_sock"] = None
                            self._send_response(client_socket, "226 Transfer complete.")
                            self.logger.info(f"File {arg} sent to {session['username']} at {address[0]}")
                        except Exception as e:
                            self.logger.error(f"Error sending file: {e}")
                            self._send_response(client_socket, "451 Requested action aborted. Local error.")
                    else:
                        self._send_response(client_socket, "550 File not found or no data connection.")
    
                elif cmd == "STOR":
                    # Log the file upload attempt to unified logger
                    if self.unified_logger:
                        self.unified_logger.log_attack(
                            service="ftp",
                            attacker_ip=address[0],
                            attacker_port=address[1],
                            command=f"STOR {arg}"
                        )
                    
                    upload_path = os.path.join(self.ftproot, "upload", arg)
                    if session["data_sock"]:
                        self._send_response(client_socket, f"150 Ok to send data for {arg}")
                        try:
                            with open(upload_path, "wb") as f:
                                while True:
                                    chunk = session["data_sock"].recv(4096)
                                    if not chunk:
                                        break
                                    f.write(chunk)
                            session["data_sock"].close()
                            session["data_sock"] = None
                            self._send_response(client_socket, "226 Transfer complete.")
                            self.logger.info(f"File {arg} uploaded from {address[0]}")
                        except Exception as e:
                            self.logger.error(f"Error saving file: {e}")
                            self._send_response(client_socket, "451 Transfer aborted due to error.")
                    else:
                        self._send_response(client_socket, "425 Can't open data connection.")
    
                elif cmd == "QUIT":
                    self._send_response(client_socket, "221 Goodbye.")
                    break
                else:
                    # Log other commands to unified logger
                    if self.unified_logger:
                        self.unified_logger.log_attack(
                            service="ftp",
                            attacker_ip=address[0],
                            attacker_port=address[1],
                            command=cmd_line
                        )
                    self._send_response(client_socket, "502 Command not implemented.")
        except Exception as e:
            self.logger.error(f"FTP session error: {e}")
        finally:
            if session_id in self.sessions:
                if self.sessions[session_id].get("data_sock"):
                    try:
                        self.sessions[session_id]["data_sock"].close()
                    except:
                        pass
                del self.sessions[session_id]

    def is_valid_credentials(self, username: str, password: str) -> bool:
        """
        Check if credentials are valid for FTP login by reading from config
        
        Args:
            username: Username
            password: Password
            
        Returns:
            True if credentials are valid, False otherwise
        """
        # Log to debug what credentials we're checking
        self.logger.debug(f"Validating credentials for user: {username}")
        
        # Print the loaded credentials for debugging
        self.logger.debug(f"Loaded credentials: {self.credentials}")
        
        # Use the credentials loaded from the configuration
        for cred in self.credentials:
            if cred.get("username") == username and cred.get("password") == password:
                self.logger.info(f"Valid credentials match for {username}")
                return True
        
        self.logger.info(f"No valid credential match for {username}")
        return False

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
