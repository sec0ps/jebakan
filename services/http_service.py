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
HTTP service emulator for the honeypot system
"""

import socket
import threading
import logging
import datetime
import json
import os
import time
import re
from urllib.parse import unquote, urlparse, parse_qs
from typing import Dict, List, Any, Tuple, Optional

from services.base_service import BaseService

class HTTPService(BaseService):
    """HTTP service emulator for the honeypot"""

    def __init__(self, host: str, port: int, config: Dict[str, Any], unified_logger=None):
        """
        Initialize the HTTP service
    
        Args:
            host: Host IP to bind to
            port: Port to listen on
            config: Global configuration dictionary
            unified_logger: Unified logger instance for centralized logging
        """
        super().__init__(host, port, config, "http")
        
        # Store unified logger instance
        self.unified_logger = unified_logger
    
        # Set up HTTP server
        self.server_name = self.service_config.get("server_name", "Apache/2.4.41 (Ubuntu)")
        self.webroot = self.service_config.get("webroot", "data/http")
    
        # Create webroot directory if it doesn't exist
        os.makedirs(self.webroot, exist_ok=True)
    
        # Ensure default index.html exists
        self._ensure_default_pages()
    
        # Track suspicious patterns
        self.suspicious_patterns = [
            r"/admin",
            r"/manager",
            r"/phpmyadmin",
            r"/mysql",
            r"/wp-admin",
            r"/wp-login",
            r"/shell",
            r"/admin\.php",
            r"/config\.php",
            r"/\.git",
            r"/\.env",
            r"/api/v1",
            r"/solr",
            r"/jenkins",
            r"/cgi-bin",
            r"/xmlrpc\.php",
            r"\.\./\.\./",  # Path traversal
            r"select.*from",  # SQL injection
            r"<script",  # XSS
            r"etc/passwd",  # LFI
        ]
        
    def _ensure_default_pages(self) -> None:
        """
        Ensure default web pages exist in webroot
        """
        # Create default index.html if it doesn't exist
        index_path = os.path.join(self.webroot, "index.html")
        if not os.path.exists(index_path):
            with open(index_path, "w") as f:
                f.write("""
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to Apache HTTP Server</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        h1 {
            color: #0066cc;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>It works!</h1>
        <p>This is the default web page for this server.</p>
        <p>The web server software is running but no content has been added, yet.</p>
        <hr>
        <p><em>Apache/2.4.41 (Ubuntu) Server at localhost Port 80</em></p>
    </div>
</body>
</html>
""")

        # Create login.php - a fake login page
        login_path = os.path.join(self.webroot, "login.php")
        if not os.path.exists(login_path):
            with open(login_path, "w") as f:
                f.write("""
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
            background-color: #f4f4f4;
        }
        h1 {
            color: #0066cc;
        }
        .container {
            max-width: 400px;
            margin: 50px auto;
            padding: 20px;
            background: white;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        button {
            padding: 10px 15px;
            background: #0066cc;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background: #0052a3;
        }
        .error {
            color: red;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Login</h1>
        <div class="error" id="error-message" style="display: none;">Invalid username or password</div>
        <form method="post" action="login.php">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
""")

        # Create admin directory with fake admin panel
        admin_dir = os.path.join(self.webroot, "admin")
        os.makedirs(admin_dir, exist_ok=True)

        admin_index = os.path.join(admin_dir, "index.php")
        if not os.path.exists(admin_index):
            with open(admin_index, "w") as f:
                f.write("""
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
            background-color: #f4f4f4;
        }
        h1 {
            color: #0066cc;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background: white;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .login-form {
            max-width: 400px;
            margin: 0 auto;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        button {
            padding: 10px 15px;
            background: #0066cc;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background: #0052a3;
        }
        .error {
            color: red;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Admin Panel</h1>
        <div class="login-form">
            <div class="error" id="error-message" style="display: none;">Invalid username or password</div>
            <form method="post" action="index.php">
                <div class="form-group">
                    <label for="username">Admin Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Admin Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit">Login</button>
            </form>
        </div>
    </div>
</body>
</html>
""")

    def handle_client(self, client_socket: socket.socket, address: Tuple[str, int],
                     connection_data: Dict[str, Any]) -> None:
        """
        Handle a client connection to the HTTP service
    
        Args:
            client_socket: Client socket object
            address: Client address tuple (ip, port)
            connection_data: Dictionary to store connection data for logging
        """
        # Log connection attempt to unified logger
        if self.unified_logger:
            self.unified_logger.log_attack(
                service="http",
                attacker_ip=address[0],
                attacker_port=address[1],
                command="connection_attempt",
                additional_data={"timestamp": datetime.datetime.now().isoformat()}
            )
            
        try:
            # Receive HTTP request
            request_data = b""
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
    
                request_data += chunk
    
                # Check if we've received the end of the headers
                if b"\r\n\r\n" in request_data:
                    # If this is not a POST request, we're done
                    if not request_data.startswith(b"POST"):
                        break
    
                    # For POST requests, check if we've received the full body
                    headers, body = request_data.split(b"\r\n\r\n", 1)
    
                    # Check for Content-Length header
                    match = re.search(rb"Content-Length: (\d+)", headers)
                    if match:
                        content_length = int(match.group(1))
                        if len(body) >= content_length:
                            break
                    else:
                        # No Content-Length header, we're done
                        break
    
            # Parse the HTTP request
            if not request_data:
                return
    
            connection_data["data"]["raw_request"] = request_data.decode('utf-8', errors='ignore')
    
            # Extract request line
            request_lines = request_data.decode('utf-8', errors='ignore').split("\r\n")
            if not request_lines:
                return
    
            request_line = request_lines[0]
            connection_data["data"]["request_line"] = request_line
    
            # Parse request line
            parts = request_line.split()
            if len(parts) < 3:
                self._send_error(client_socket, 400, "Bad Request")
                
                # Log malformed request to unified logger
                if self.unified_logger:
                    self.unified_logger.log_attack(
                        service="http",
                        attacker_ip=address[0],
                        attacker_port=address[1],
                        command="malformed_request",
                        additional_data={"request_line": request_line}
                    )
                return
    
            method, path, protocol = parts
            connection_data["data"]["method"] = method
            connection_data["data"]["path"] = path
            connection_data["data"]["protocol"] = protocol
            
            # Log HTTP request to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="http",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command=f"http_request_{method}",
                    additional_data={
                        "method": method,
                        "path": path,
                        "protocol": protocol
                    }
                )
    
            # Parse headers
            headers = {}
            for line in request_lines[1:]:
                if not line:
                    break
    
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()
    
            connection_data["data"]["headers"] = headers
    
            # Extract user-agent if present
            if "User-Agent" in headers:
                connection_data["data"]["user_agent"] = headers["User-Agent"]
    
            # Check for suspicious patterns in the request
            suspicious = False
            matched_patterns = []
    
            for pattern in self.suspicious_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    suspicious = True
                    matched_patterns.append(pattern)
    
            if suspicious:
                connection_data["data"]["suspicious"] = True
                connection_data["data"]["matched_patterns"] = matched_patterns
                self.logger.warning(f"Suspicious HTTP request from {address[0]}: {path} - matched patterns: {matched_patterns}")
                
                # Log suspicious request to unified logger
                if self.unified_logger:
                    self.unified_logger.log_attack(
                        service="http",
                        attacker_ip=address[0],
                        attacker_port=address[1],
                        command="suspicious_request",
                        additional_data={
                            "method": method,
                            "path": path,
                            "matched_patterns": matched_patterns
                        }
                    )
    
            # Handle the request based on method
            if method == "GET":
                self._handle_get_request(client_socket, path, headers, connection_data, address)
            elif method == "POST":
                # Extract POST data
                post_data = {}
                if len(request_lines) > 1 and request_data.find(b"\r\n\r\n") != -1:
                    body = request_data.split(b"\r\n\r\n", 1)[1].decode('utf-8', errors='ignore')
    
                    # Simple parsing of application/x-www-form-urlencoded data
                    if "Content-Type" in headers and headers["Content-Type"] == "application/x-www-form-urlencoded":
                        post_params = body.split("&")
                        for param in post_params:
                            if "=" in param:
                                key, value = param.split("=", 1)
                                post_data[key] = unquote(value)
    
                connection_data["data"]["post_data"] = post_data
                self._handle_post_request(client_socket, path, headers, post_data, connection_data, address)
            else:
                # Method not implemented
                self._send_error(client_socket, 501, "Not Implemented")
                
                # Log unsupported method to unified logger
                if self.unified_logger:
                    self.unified_logger.log_attack(
                        service="http",
                        attacker_ip=address[0],
                        attacker_port=address[1],
                        command="unsupported_method",
                        additional_data={
                            "method": method,
                            "path": path
                        }
                    )
    
        except Exception as e:
            self.logger.error(f"Error handling HTTP client: {e}")
            connection_data["error"] = str(e)
            
            # Log error to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="http",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="error",
                    additional_data={"error": str(e)}
                )
                
            try:
                self._send_error(client_socket, 500, "Internal Server Error")
            except:
                pass
            
    def _handle_get_request(self, client_socket: socket.socket, path: str,
                           headers: Dict[str, str], connection_data: Dict[str, Any], address: Tuple[str, int]) -> None:
        """
        Handle HTTP GET requests
    
        Args:
            client_socket: Client socket object
            path: Request path
            headers: HTTP headers dictionary
            connection_data: Dictionary to store connection data for logging
            address: Client address tuple (ip, port)
        """
        # Log GET request details to unified logger
        if self.unified_logger:
            self.unified_logger.log_attack(
                service="http",
                attacker_ip=address[0],
                attacker_port=address[1],
                command="http_get",
                additional_data={
                    "path": path,
                    "headers": headers
                }
            )
        
        # Handle vulnerable paths specially
        if path in self.service_config.get("vulnerable_pages", []):
            self._handle_vulnerable_page(client_socket, path, headers, connection_data, address)
            return
    
        # Clean the path to prevent directory traversal
        original_path = path
        path = self._clean_path(path)
        
        # Log if path was modified (possible directory traversal attempt)
        if path != original_path and self.unified_logger:
            self.unified_logger.log_attack(
                service="http",
                attacker_ip=address[0],
                attacker_port=address[1],
                command="path_traversal_attempt",
                additional_data={
                    "original_path": original_path,
                    "cleaned_path": path
                }
            )
    
        # Check if path is a file
        file_path = os.path.join(self.webroot, path.lstrip("/"))
    
        # If path ends with /, append index.html
        if path.endswith("/"):
            file_path = os.path.join(file_path, "index.html")
            if not os.path.exists(file_path):
                file_path = os.path.join(file_path[:-1], "index.php")
    
        # Check if file exists
        if os.path.isfile(file_path):
            self._serve_file(client_socket, file_path)
        else:
            # Check for PHP files
            php_path = f"{file_path}.php"
            if os.path.isfile(php_path):
                self._serve_file(client_socket, php_path)
            else:
                # File not found
                self._send_error(client_socket, 404, "Not Found")
                
                # Log 404 to unified logger
                if self.unified_logger:
                    self.unified_logger.log_attack(
                        service="http",
                        attacker_ip=address[0],
                        attacker_port=address[1],
                        command="file_not_found",
                        additional_data={
                            "path": path,
                            "file_path": file_path
                        }
                    )

    def _handle_post_request(self, client_socket: socket.socket, path: str,
                            headers: Dict[str, str], post_data: Dict[str, str],
                            connection_data: Dict[str, Any], address: Tuple[str, int]) -> None:
        """
        Handle HTTP POST requests
    
        Args:
            client_socket: Client socket object
            path: Request path
            headers: HTTP headers dictionary
            post_data: Parsed POST data
            connection_data: Dictionary to store connection data for logging
            address: Client address tuple (ip, port)
        """
        # Log POST request details to unified logger
        if self.unified_logger:
            self.unified_logger.log_attack(
                service="http",
                attacker_ip=address[0],
                attacker_port=address[1],
                command="http_post",
                additional_data={
                    "path": path,
                    "headers": headers,
                    "post_data": post_data
                }
            )
        
        # Check for login attempts
        if path == "/login.php" or path == "/admin/index.php":
            username = post_data.get("username", "")
            password = post_data.get("password", "")
    
            # Log the login attempt
            login_attempt = {
                "username": username,
                "password": password,
                "path": path,
                "timestamp": datetime.datetime.now().isoformat()
            }
    
            if "login_attempts" not in connection_data["data"]:
                connection_data["data"]["login_attempts"] = []
    
            connection_data["data"]["login_attempts"].append(login_attempt)
    
            self.logger.info(f"Login attempt from {connection_data['source_ip']} with username '{username}' and password '{password}'")
            
            # Log login attempt to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="http",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="login_attempt",
                    additional_data={
                        "username": username,
                        "password": password,
                        "path": path
                    }
                )
    
            # Always return a login error page
            self._send_login_error(client_socket, path)
        else:
            # Default handler for other POST requests
            self._send_error(client_socket, 403, "Forbidden")
            
            # Log forbidden POST to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="http",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="forbidden_post",
                    additional_data={
                        "path": path,
                        "post_data": post_data
                    }
                )

    def _handle_vulnerable_page(self, client_socket: socket.socket, path: str,
                               headers: Dict[str, str], connection_data: Dict[str, Any], address: Tuple[str, int]) -> None:
        """
        Handle requests to vulnerable pages
    
        Args:
            client_socket: Client socket object
            path: Request path
            headers: HTTP headers dictionary
            connection_data: Dictionary to store connection data for logging
            address: Client address tuple (ip, port)
        """
        # Log vulnerable page access to unified logger
        if self.unified_logger:
            self.unified_logger.log_attack(
                service="http",
                attacker_ip=address[0],
                attacker_port=address[1],
                command="vulnerable_page_access",
                additional_data={
                    "path": path,
                    "headers": headers
                }
            )
        
        # Default response is a login form
        if path == "/admin" or path == "/phpmyadmin" or path == "/wordpress/wp-admin":
            self._send_login_page(client_socket, path)
        else:
            # Default to 404 for unknown vulnerable pages
            self._send_error(client_socket, 404, "Not Found")

    def _serve_file(self, client_socket: socket.socket, file_path: str) -> None:
        """
        Serve a file over HTTP

        Args:
            client_socket: Client socket object
            file_path: Path to the file to serve
        """
        try:
            # Get file extension for content type
            _, ext = os.path.splitext(file_path)
            content_type = self._get_content_type(ext)

            # Read file content
            with open(file_path, "rb") as f:
                content = f.read()

            # Send response headers
            status_line = "HTTP/1.1 200 OK\r\n"
            headers = [
                f"Server: {self.server_name}",
                f"Content-Type: {content_type}",
                f"Content-Length: {len(content)}",
                f"Date: {datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')}",
                "Connection: close"
            ]

            response = status_line + "\r\n".join(headers) + "\r\n\r\n"
            client_socket.send(response.encode())

            # Send file content
            client_socket.send(content)

        except Exception as e:
            self.logger.error(f"Error serving file {file_path}: {e}")
            self._send_error(client_socket, 500, "Internal Server Error")

    def _send_error(self, client_socket: socket.socket, status_code: int, message: str) -> None:
        """
        Send an HTTP error response

        Args:
            client_socket: Client socket object
            status_code: HTTP status code
            message: Error message
        """
        try:
            status_line = f"HTTP/1.1 {status_code} {message}\r\n"
            content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{status_code} {message}</title>
</head>
<body>
    <h1>{status_code} {message}</h1>
    <p>The requested URL was not found on this server.</p>
    <hr>
    <p><em>{self.server_name}</em></p>
</body>
</html>
"""
            headers = [
                f"Server: {self.server_name}",
                "Content-Type: text/html; charset=utf-8",
                f"Content-Length: {len(content)}",
                f"Date: {datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')}",
                "Connection: close"
            ]

            response = status_line + "\r\n".join(headers) + "\r\n\r\n"
            client_socket.send(response.encode())

            # Send content
            client_socket.send(content.encode())

        except Exception as e:
            self.logger.error(f"Error sending HTTP error: {e}")

    def _send_login_page(self, client_socket: socket.socket, path: str) -> None:
        """
        Send a fake login page

        Args:
            client_socket: Client socket object
            path: Request path
        """
        try:
            status_line = "HTTP/1.1 200 OK\r\n"

            # Create a login form based on the path
            title = "Login"
            if path == "/admin":
                title = "Admin Panel"
            elif path == "/phpmyadmin":
                title = "phpMyAdmin"
            elif path == "/wordpress/wp-admin":
                title = "WordPress Admin"

            content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
            background-color: #f4f4f4;
        }}
        h1 {{
            color: #0066cc;
        }}
        .container {{
            max-width: 400px;
            margin: 50px auto;
            padding: 20px;
            background: white;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        .form-group {{
            margin-bottom: 15px;
        }}
        label {{
            display: block;
            margin-bottom: 5px;
        }}
        input[type="text"], input[type="password"] {{
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }}
        button {{
            padding: 10px 15px;
            background: #0066cc;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }}
        button:hover {{
            background: #0052a3;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{title}</h1>
        <form method="post" action="{path}">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""

            headers = [
                f"Server: {self.server_name}",
                "Content-Type: text/html; charset=utf-8",
                f"Content-Length: {len(content)}",
                f"Date: {datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')}",
                "Connection: close"
            ]

            response = status_line + "\r\n".join(headers) + "\r\n\r\n"
            client_socket.send(response.encode())

            # Send content
            client_socket.send(content.encode())

        except Exception as e:
            self.logger.error(f"Error sending login page: {e}")
            self._send_error(client_socket, 500, "Internal Server Error")

    def _send_login_error(self, client_socket: socket.socket, path: str) -> None:
        """
        Send a login error page

        Args:
            client_socket: Client socket object
            path: Request path
        """
        try:
            status_line = "HTTP/1.1 200 OK\r\n"

            # Create a login form with error message
            title = "Login"
            if path == "/admin/index.php":
                title = "Admin Panel"

            content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
            background-color: #f4f4f4;
        }}
        h1 {{
            color: #0066cc;
        }}
        .container {{
            max-width: 400px;
            margin: 50px auto;
            padding: 20px;
            background: white;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        .form-group {{
            margin-bottom: 15px;
        }}
        label {{
            display: block;
            margin-bottom: 5px;
        }}
        input[type="text"], input[type="password"] {{
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }}
        button {{
            padding: 10px 15px;
            background: #0066cc;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }}
        button:hover {{
            background: #0052a3;
        }}
        .error {{
            color: red;
            margin-bottom: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{title}</h1>
        <div class="error">Invalid username or password</div>
        <form method="post" action="{path}">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""

            headers = [
                f"Server: {self.server_name}",
                "Content-Type: text/html; charset=utf-8",
                f"Content-Length: {len(content)}",
                f"Date: {datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')}",
                "Connection: close"
            ]

            response = status_line + "\r\n".join(headers) + "\r\n\r\n"
            client_socket.send(response.encode())

            # Send content
            client_socket.send(content.encode())

        except Exception as e:
            self.logger.error(f"Error sending login error page: {e}")
            self._send_error(client_socket, 500, "Internal Server Error")

    def _clean_path(self, path: str) -> str:
        """
        Clean a path to prevent directory traversal

        Args:
            path: Path to clean

        Returns:
            Cleaned path
        """
        # Remove query string
        if "?" in path:
            path = path.split("?")[0]

        # Remove fragments
        if "#" in path:
            path = path.split("#")[0]

        # Remove multiple slashes
        while "//" in path:
            path = path.replace("//", "/")

        # Remove directory traversal attempts
        parts = []
        for part in path.split("/"):
            if part == "..":
                if parts:
                    parts.pop()
            elif part and part != ".":
                parts.append(part)

        # Rebuild path
        clean_path = "/" + "/".join(parts)
        return clean_path

    def _get_content_type(self, extension: str) -> str:
        """
        Get MIME type for a file extension

        Args:
            extension: File extension

        Returns:
            MIME type string
        """
        content_types = {
            ".html": "text/html",
            ".htm": "text/html",
            ".css": "text/css",
            ".js": "application/javascript",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".gif": "image/gif",
            ".ico": "image/x-icon",
            ".txt": "text/plain",
            ".pdf": "application/pdf",
            ".xml": "application/xml",
            ".json": "application/json",
            ".php": "text/html",  # PHP files are served as HTML
            ".svg": "image/svg+xml",
            ".csv": "text/csv",
            ".doc": "application/msword",
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xls": "application/vnd.ms-excel",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".zip": "application/zip",
            ".tar": "application/x-tar",
            ".gz": "application/gzip",
            ".mp3": "audio/mpeg",
            ".mp4": "video/mp4",
            ".wav": "audio/wav",
            ".ogg": "audio/ogg",
            ".webp": "image/webp",
            ".woff": "font/woff",
            ".woff2": "font/woff2",
            ".ttf": "font/ttf",
            ".otf": "font/otf",
            ".eot": "application/vnd.ms-fontobject"
        }

        return content_types.get(extension.lower(), "application/octet-stream")

    def start(self) -> None:
        """Start the HTTP service"""
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            self.running = True
            
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="http",
                    attacker_ip="system",
                    attacker_port=0,
                    command="service_start",
                    additional_data={"port": self.port}
                )
            
            self.logger.info(f"HTTP honeypot started on port {self.port}")
            
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
                    self.logger.info(f"Connection from {addr[0]}:{addr[1]} to HTTP service")
                    
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
                            service="http",
                            attacker_ip="error",
                            attacker_port=0,
                            command="error",
                            additional_data={"error": str(e)}
                        )
                    self.logger.error(f"Error accepting connection: {e}")
                    
        except Exception as e:
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="http",
                    attacker_ip="error",
                    attacker_port=0,
                    command="service_error",
                    additional_data={"error": str(e)}
                )
            self.logger.error(f"Error starting HTTP service: {e}")
        finally:
            if self.sock:
                self.sock.close()
