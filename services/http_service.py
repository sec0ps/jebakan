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
import uuid
import hashlib
import time
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

    def _check_honeytoken_access(self, path: str, ip_address: str) -> Optional[str]:
        """
        Check if a request is accessing a honeytoken
        
        Args:
            path: Request path
            ip_address: Client IP address
            
        Returns:
            Honeytoken ID if accessing a honeytoken, None otherwise
        """
        # Parse the URL to extract query parameters
        parsed_url = urlparse(path)
        query_params = parse_qs(parsed_url.query)
        
        # Check for token parameter
        token = None
        if 'token' in query_params and query_params['token']:
            token = query_params['token'][0]
        
        # Check specific honeytoken paths
        honeytoken_paths = [
            "/admin/backup.zip",
            "/config/database.yml",
            "/api/keys.json",
            "/.git/config",
            "/wp-admin/access.php",
            "/backup/"
        ]
        
        is_honeytoken_path = any(path.startswith(hp) for hp in honeytoken_paths)
        
        # If no token but it's a honeytoken path, still record the access
        if is_honeytoken_path and not token:
            # Generate a placeholder token
            token = f"path_token_{int(time.time())}"
        
        # If we have a token, update the honeytoken database
        if token and (token.startswith("ht_") or is_honeytoken_path):
            # Load honeytokens database
            honeytokens_dir = os.path.join(self.config["logging"]["dir"], "honeytokens")
            honeytokens_db = os.path.join(honeytokens_dir, "honeytokens.json")
            
            # Check if database exists
            if not os.path.exists(honeytokens_db):
                return token
            
            # Load tokens
            try:
                with open(honeytokens_db, 'r') as f:
                    tokens = json.loads(f.read())
                
                # Check if token exists
                if token in tokens:
                    # Update access information
                    tokens[token]["accessed"] = True
                    tokens[token]["access_count"] += 1
                    tokens[token]["last_accessed"] = datetime.datetime.now().isoformat()
                    
                    # Add IP to access_ips if not already there
                    if ip_address not in tokens[token]["access_ips"]:
                        tokens[token]["access_ips"].append(ip_address)
                    
                    # Save updated honeytokens database
                    with open(honeytokens_db, 'w') as f:
                        json.dump(tokens, f, indent=2)
                    
                    return token
                elif is_honeytoken_path:
                    # This is a honeytoken path but token wasn't found in database
                    # Create a new entry
                    new_token = {
                        "client_id": "unknown",
                        "created": datetime.datetime.now().isoformat(),
                        "accessed": True,
                        "access_count": 1,
                        "last_accessed": datetime.datetime.now().isoformat(),
                        "access_ips": [ip_address],
                        "path": path
                    }
                    
                    tokens[token] = new_token
                    
                    # Save updated honeytokens database
                    with open(honeytokens_db, 'w') as f:
                        json.dump(tokens, f, indent=2)
                    
                    return token
                    
            except Exception as e:
                self.logger.error(f"Error checking honeytoken access: {e}")
        
        # Check if there are any token-like values in the path
        token_pattern = re.compile(r'(token|key|auth|access|api)=([a-zA-Z0-9_\-\.]+)')
        match = token_pattern.search(path)
        if match:
            # This might be an attempt to use a token
            potential_token = match.group(2)
            self.logger.info(f"Potential token usage detected: {potential_token} in path {path}")
            
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="http",
                    attacker_ip=ip_address,
                    attacker_port=0,  # We don't have port info here
                    command="potential_token_usage",
                    additional_data={
                        "token": potential_token,
                        "path": path
                    }
                )
        
        return None

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
            
            # Check for honeytoken access
            honeytoken_id = self._check_honeytoken_access(path, address[0])
            if honeytoken_id:
                connection_data["data"]["honeytoken_access"] = True
                connection_data["data"]["honeytoken_id"] = honeytoken_id
                
                # Log honeytoken access to unified logger
                if self.unified_logger:
                    self.unified_logger.log_attack(
                        service="http",
                        attacker_ip=address[0],
                        attacker_port=address[1],
                        command="honeytoken_access",
                        additional_data={
                            "honeytoken_id": honeytoken_id,
                            "path": path,
                            "method": method
                        }
                    )
                
                self.logger.warning(f"Honeytoken access detected from {address[0]} - Path: {path}, Token: {honeytoken_id}")
            
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
    
            # Parse headers - Enhanced to capture all headers
            headers = {}
            # Define important headers to highlight in logs
            important_headers = [
                "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", 
                "Connection", "Referer", "Cookie", "X-Forwarded-For", 
                "X-Real-IP", "Via", "DNT", "Upgrade-Insecure-Requests",
                "Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform", 
                "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest"
            ]
            
            # Initialize headers section in connection data
            connection_data["data"]["headers"] = {}
            
            for line in request_lines[1:]:
                if not line:
                    break
    
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip()
                    value = value.strip()
                    headers[key] = value
                    
                    # Store all headers for analysis
                    connection_data["data"]["headers"][key] = value
                    
                    # Log important headers specifically
                    if key in important_headers:
                        connection_data["data"][f"header_{key}"] = value
    
            # Extract client fingerprint information
            client_info = self._extract_client_info(headers, address[0])
            connection_data["data"]["client_info"] = client_info
            
            # Extract language and locale information
            if "Accept-Language" in headers:
                languages = headers["Accept-Language"].split(",")
                if languages:
                    primary_language = languages[0].split(";")[0].strip()
                    connection_data["data"]["primary_language"] = primary_language
                    connection_data["data"]["all_languages"] = languages
    
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
                            "matched_patterns": matched_patterns,
                            "client_info": client_info
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
                    if "Content-Type" in headers and "application/x-www-form-urlencoded" in headers["Content-Type"]:
                        post_params = body.split("&")
                        for param in post_params:
                            if "=" in param:
                                key, value = param.split("=", 1)
                                post_data[unquote(key)] = unquote(value)
                    # Parse JSON content if present
                    elif "Content-Type" in headers and "application/json" in headers["Content-Type"]:
                        try:
                            post_data = json.loads(body)
                        except json.JSONDecodeError:
                            # Failed to parse JSON, log the raw body
                            connection_data["data"]["raw_body"] = body
                    # Store raw body for other content types
                    else:
                        connection_data["data"]["raw_body"] = body
    
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
                            "path": path,
                            "client_info": client_info
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
       
    def _extract_client_info(self, headers: Dict[str, str], ip_address: str) -> Dict[str, Any]:
        """
        Extract detailed client information from HTTP headers
        
        Args:
            headers: HTTP headers dictionary
            ip_address: Client IP address
            
        Returns:
            Dictionary containing client information
        """
        client_info = {
            "ip_address": ip_address,
            "is_mobile": False,
            "browser": "Unknown",
            "browser_version": "Unknown",
            "os": "Unknown",
            "os_version": "Unknown",
            "device_type": "Unknown",
            "is_bot": False
        }
        
        # Extract user agent
        user_agent = headers.get("User-Agent", "")
        
        if not user_agent:
            client_info["is_bot"] = True
            client_info["bot_type"] = "Missing User-Agent"
            return client_info
        
        # Check for bots
        bot_patterns = [
            "bot", "crawl", "spider", "slurp", "search", "fetch", "nagios", 
            "monitoring", "monitor", "scanner", "scrape", "zgrab", "scan",
            "curl", "wget", "nmap", "masscan", "nikto", "burp", "zap"
        ]
        
        for pattern in bot_patterns:
            if pattern.lower() in user_agent.lower():
                client_info["is_bot"] = True
                client_info["bot_type"] = pattern.capitalize()
                break
        
        # Browser detection
        if "Chrome" in user_agent and "Safari" in user_agent and "Edge" not in user_agent and "Edg/" not in user_agent:
            client_info["browser"] = "Chrome"
            match = re.search(r"Chrome/(\d+\.\d+\.\d+\.\d+)", user_agent)
            if match:
                client_info["browser_version"] = match.group(1)
        elif "Firefox" in user_agent:
            client_info["browser"] = "Firefox"
            match = re.search(r"Firefox/(\d+\.\d+)", user_agent)
            if match:
                client_info["browser_version"] = match.group(1)
        elif "Safari" in user_agent and "Chrome" not in user_agent:
            client_info["browser"] = "Safari"
            match = re.search(r"Version/(\d+\.\d+\.\d+)", user_agent)
            if match:
                client_info["browser_version"] = match.group(1)
        elif "Edge" in user_agent or "Edg/" in user_agent:
            client_info["browser"] = "Edge"
            match = re.search(r"Edge?/(\d+\.\d+\.\d+\.\d+|\d+\.\d+)", user_agent)
            if match:
                client_info["browser_version"] = match.group(1)
        elif "MSIE" in user_agent or "Trident" in user_agent:
            client_info["browser"] = "Internet Explorer"
            match = re.search(r"MSIE (\d+\.\d+)", user_agent)
            if match:
                client_info["browser_version"] = match.group(1)
            else:
                match = re.search(r"rv:(\d+\.\d+)", user_agent)
                if match:
                    client_info["browser_version"] = match.group(1)
        elif "OPR" in user_agent or "Opera" in user_agent:
            client_info["browser"] = "Opera"
            match = re.search(r"OPR/(\d+\.\d+\.\d+\.\d+)", user_agent)
            if match:
                client_info["browser_version"] = match.group(1)
        
        # OS detection
        if "Windows" in user_agent:
            client_info["os"] = "Windows"
            if "Windows NT 10.0" in user_agent:
                client_info["os_version"] = "10/11"
            elif "Windows NT 6.3" in user_agent:
                client_info["os_version"] = "8.1"
            elif "Windows NT 6.2" in user_agent:
                client_info["os_version"] = "8"
            elif "Windows NT 6.1" in user_agent:
                client_info["os_version"] = "7"
            elif "Windows NT 6.0" in user_agent:
                client_info["os_version"] = "Vista"
            elif "Windows NT 5.1" in user_agent:
                client_info["os_version"] = "XP"
        elif "Macintosh" in user_agent or "Mac OS X" in user_agent:
            client_info["os"] = "macOS"
            match = re.search(r"Mac OS X (\d+[_.]\d+[_.]\d+|\d+[_.]\d+)", user_agent)
            if match:
                client_info["os_version"] = match.group(1).replace("_", ".")
        elif "Linux" in user_agent:
            if "Android" in user_agent:
                client_info["os"] = "Android"
                match = re.search(r"Android (\d+[.]\d+[.]*\d*)", user_agent)
                if match:
                    client_info["os_version"] = match.group(1)
            else:
                client_info["os"] = "Linux"
        elif "iPhone" in user_agent or "iPad" in user_agent or "iPod" in user_agent:
            client_info["os"] = "iOS"
            match = re.search(r"OS (\d+[_]\d+[_]*\d*)", user_agent)
            if match:
                client_info["os_version"] = match.group(1).replace("_", ".")
        
        # Mobile detection
        if "Mobile" in user_agent or "Android" in user_agent or "iPhone" in user_agent:
            client_info["is_mobile"] = True
            
        # Device type detection
        if client_info["is_mobile"]:
            if "iPad" in user_agent or "Tablet" in user_agent:
                client_info["device_type"] = "Tablet"
            else:
                client_info["device_type"] = "Mobile"
        else:
            client_info["device_type"] = "Desktop"
        
        # Client hints (modern browsers)
        if "Sec-Ch-Ua" in headers:
            client_info["client_hints"] = True
            client_info["sec_ch_ua"] = headers["Sec-Ch-Ua"]
            
        if "Sec-Ch-Ua-Mobile" in headers:
            if headers["Sec-Ch-Ua-Mobile"] == "?1":
                client_info["is_mobile"] = True
                
        if "Sec-Ch-Ua-Platform" in headers:
            platform = headers["Sec-Ch-Ua-Platform"].strip('"')
            if platform != "Unknown":
                client_info["platform"] = platform
        
        # Check Accept header to determine if the client can render HTML
        if "Accept" in headers:
            accept = headers["Accept"]
            if "text/html" in accept:
                client_info["accepts_html"] = True
            if "image/*" in accept or "image/jpeg" in accept:
                client_info["accepts_images"] = True
        
        return client_info
            
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
        # Process cookies or set a new tracking cookie
        client_id, is_return_visitor = self._process_cookies(headers, address[0])
        connection_data["data"]["client_id"] = client_id
        connection_data["data"]["is_return_visitor"] = is_return_visitor
        
        # Analyze request parameters
        parameter_analysis = self._analyze_request_parameters("GET", path, headers, {}, connection_data)
        
        # Extract query parameters for logging
        query_params = {}
        if "?" in path:
            path_part, query_part = path.split("?", 1)
            query_string = query_part.split("#")[0]  # Remove any URL fragment
            
            for param in query_string.split("&"):
                if "=" in param:
                    key, value = param.split("=", 1)
                    query_params[unquote(key)] = unquote(value)
        
        # Log GET request details to unified logger
        if self.unified_logger:
            log_data = {
                "path": path,
                "headers": headers,
                "client_id": client_id,
                "is_return_visitor": is_return_visitor,
                "parameter_analysis": parameter_analysis
            }
            
            # Add query parameters if present
            if query_params:
                log_data["query_parameters"] = query_params
                
            # Determine command based on analysis
            command = "http_get"
            if parameter_analysis["attack_vectors"]:
                command = f"attack_{parameter_analysis['attack_type']}"
                
            self.unified_logger.log_attack(
                service="http",
                attacker_ip=address[0],
                attacker_port=address[1],
                command=command,
                additional_data=log_data
            )
        
        # For high-risk attacks, log a warning
        if parameter_analysis["risk_level"] == "high":
            self.logger.warning(
                f"High-risk attack detected from {address[0]}: {parameter_analysis['attack_type']} - "
                f"Path: {path}"
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
                    "cleaned_path": path,
                    "client_id": client_id
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
            self._serve_file(client_socket, file_path, client_id)
        else:
            # Check for PHP files
            php_path = f"{file_path}.php"
            if os.path.isfile(php_path):
                self._serve_file(client_socket, php_path, client_id)
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
                            "file_path": file_path,
                            "client_id": client_id
                        }
                    )

    def _process_cookies(self, headers: Dict[str, str], ip_address: str) -> Tuple[str, bool]:
        """
        Process cookies from request headers and generate tracking cookies
        
        Args:
            headers: HTTP headers dictionary
            ip_address: Client IP address
            
        Returns:
            Tuple of (client_id, is_return_visitor)
        """
        # Initialize cookie tracking file if it doesn't exist
        cookie_db_path = os.path.join(self.config["logging"]["dir"], "http_cookies.json")
        if not os.path.exists(cookie_db_path):
            try:
                with open(cookie_db_path, 'w') as f:
                    json.dump({}, f)
            except Exception as e:
                self.logger.error(f"Error creating cookie tracking file: {e}")
        
        # Check for existing tracking cookie
        client_id = None
        is_return_visitor = False
        
        if "Cookie" in headers:
            cookies = headers["Cookie"].split(";")
            for cookie in cookies:
                if "=" in cookie:
                    name, value = cookie.split("=", 1)
                    name = name.strip()
                    value = value.strip()
                    
                    if name == "HONEYPOT_ID":
                        client_id = value
                        is_return_visitor = True
                        break
        
        # Load the cookie database
        cookie_db = {}
        try:
            with open(cookie_db_path, 'r') as f:
                content = f.read()
                if content:
                    cookie_db = json.loads(content)
        except Exception as e:
            self.logger.error(f"Error reading cookie database: {e}")
        
        # Check if we have a client_id and it exists in the database
        if client_id and client_id in cookie_db:
            # Update last seen timestamp
            cookie_db[client_id]["last_seen"] = datetime.datetime.now().isoformat()
            cookie_db[client_id]["visit_count"] += 1
            
            # Add current IP to the IP history if not already present
            if ip_address not in cookie_db[client_id]["ip_addresses"]:
                cookie_db[client_id]["ip_addresses"].append(ip_address)
        else:
            # Generate a new client ID
            client_id = self._generate_client_id()
            is_return_visitor = False
            
            # Store in the database
            cookie_db[client_id] = {
                "created": datetime.datetime.now().isoformat(),
                "last_seen": datetime.datetime.now().isoformat(),
                "ip_addresses": [ip_address],
                "visit_count": 1,
                "user_agents": []
            }
        
        # Update user agent if available
        if "User-Agent" in headers and headers["User-Agent"] not in cookie_db[client_id].get("user_agents", []):
            cookie_db[client_id].setdefault("user_agents", []).append(headers["User-Agent"])
        
        # Save the updated cookie database
        try:
            with open(cookie_db_path, 'w') as f:
                json.dump(cookie_db, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error updating cookie database: {e}")
        
        return client_id, is_return_visitor

    def _generate_client_id(self) -> str:
        """
        Generate a unique client ID for cookie tracking
        
        Returns:
            Unique client ID string
        """
        
        # Generate a random UUID
        random_id = str(uuid.uuid4())
        
        # Add timestamp for extra uniqueness
        timestamp = str(time.time())
        
        # Create a hash from the combination
        unique_id = hashlib.md5((random_id + timestamp).encode()).hexdigest()
        
        return unique_id

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
        # Process cookies or set a new tracking cookie
        client_id, is_return_visitor = self._process_cookies(headers, address[0])
        connection_data["data"]["client_id"] = client_id
        connection_data["data"]["is_return_visitor"] = is_return_visitor
        
        # Analyze request parameters
        parameter_analysis = self._analyze_request_parameters("POST", path, headers, post_data, connection_data)
        
        # Log POST request details to unified logger
        if self.unified_logger:
            log_data = {
                "path": path,
                "headers": headers,
                "post_data": post_data,
                "client_id": client_id,
                "is_return_visitor": is_return_visitor,
                "parameter_analysis": parameter_analysis
            }
            
            # Determine command based on analysis
            command = "http_post"
            if parameter_analysis["attack_vectors"]:
                command = f"attack_{parameter_analysis['attack_type']}"
                
            self.unified_logger.log_attack(
                service="http",
                attacker_ip=address[0],
                attacker_port=address[1],
                command=command,
                additional_data=log_data
            )
        
        # For high-risk attacks, log a warning
        if parameter_analysis["risk_level"] == "high":
            self.logger.warning(
                f"High-risk attack detected from {address[0]}: {parameter_analysis['attack_type']} - "
                f"Path: {path}, POST data: {post_data}"
            )
        
        # Special handler for fingerprint submission endpoint
        if path == "/fp":
            self._handle_fingerprint_submission(client_socket, headers, connection_data, address)
            return
        
        # Check for login attempts
        if path == "/login.php" or path == "/admin/index.php":
            username = post_data.get("username", "")
            password = post_data.get("password", "")
    
            # Log the login attempt
            login_attempt = {
                "username": username,
                "password": password,
                "path": path,
                "timestamp": datetime.datetime.now().isoformat(),
                "client_id": client_id
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
                        "path": path,
                        "client_id": client_id,
                        "parameter_analysis": parameter_analysis
                    }
                )
    
            # Always return a login error page - pass client_id
            self._send_login_error(client_socket, path, client_id)
        else:
            # Default handler for other POST requests - pass client_id
            self._send_error(client_socket, 403, "Forbidden", client_id)
            
            # Log forbidden POST to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="http",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="forbidden_post",
                    additional_data={
                        "path": path,
                        "post_data": post_data,
                        "client_id": client_id,
                        "parameter_analysis": parameter_analysis
                    }
                )

    def _inject_honeytokens(self, content: str, client_id: str) -> str:
        """
        Inject honeytokens into HTML content
        
        Args:
            content: HTML content string
            client_id: Client tracking ID
            
        Returns:
            Modified HTML content with injected honeytokens
        """
        # Don't try to modify non-HTML content
        if not content or not isinstance(content, str):
            return content
            
        # Create a unique honeytoken for this client
        honeytoken_id = f"ht_{client_id}_{int(time.time())}"
        
        # Store the honeytoken in our database
        self._store_honeytoken(honeytoken_id, client_id)
        
        # Invisible links that look like sensitive resources
        invisible_links = f"""
        <div style="display:none">
            <a href="/admin/backup.zip?token={honeytoken_id}" id="ht1">Admin Backup</a>
            <a href="/config/database.yml?token={honeytoken_id}" id="ht2">Database Config</a>
            <a href="/api/keys.json?token={honeytoken_id}" id="ht3">API Keys</a>
            <a href="/.git/config?token={honeytoken_id}" id="ht4">Git Config</a>
            <a href="/wp-admin/access.php?token={honeytoken_id}" id="ht5">WordPress Admin</a>
        </div>
        """
        
        # Hidden form fields with fake credentials
        hidden_fields = f"""
        <input type="hidden" name="debug_key" value="{honeytoken_id}_admin123">
        <input type="hidden" name="api_token" value="YXBpX3Rva2VuX3tob25leXRva2VuX2lkfQ==">
        """
        
        # Fake API endpoint in JavaScript comment
        js_comment = f"""
        <!-- 
        Internal API endpoints:
        GET /api/v1/users - List all users
        POST /api/v1/auth - Authentication endpoint
        Authorization: Bearer {honeytoken_id}_TOKEN
        -->
        """
        
        # Add fake robots.txt reference
        robots_comment = f"""
        <!-- 
        TODO: Update robots.txt to prevent indexing of /backup/{honeytoken_id} directory
        -->
        """
        
        # Hidden sensitive metadata
        meta_tags = f"""
        <meta name="generator" content="WordPress 5.8.2" />
        <meta name="database-version" content="MySQL 5.7.34" />
        <meta name="server-info" content="Apache/2.4.41 Ubuntu" />
        <meta name="debug-token" content="{honeytoken_id}" />
        """
        
        # Inject the honeytokens into the HTML
        if "<head>" in content:
            content = content.replace("<head>", f"<head>\n{meta_tags}")
        
        if "<body>" in content:
            content = content.replace("<body>", f"<body>\n{invisible_links}")
        
        if "</body>" in content:
            content = content.replace("</body>", f"{js_comment}\n{robots_comment}\n</body>")
        
        # Inject into any forms
        form_pattern = re.compile(r"(<form[^>]*>)", re.IGNORECASE)
        content = form_pattern.sub(r"\1" + hidden_fields, content)
        
        return content

    def _store_honeytoken(self, honeytoken_id: str, client_id: str) -> None:
        """
        Store a honeytoken in the database
        
        Args:
            honeytoken_id: Unique honeytoken identifier
            client_id: Client tracking ID
        """
        # Create honeytokens directory if it doesn't exist
        honeytokens_dir = os.path.join(self.config["logging"]["dir"], "honeytokens")
        os.makedirs(honeytokens_dir, exist_ok=True)
        
        # Path to honeytokens database file
        honeytokens_db = os.path.join(honeytokens_dir, "honeytokens.json")
        
        # Load existing honeytokens
        tokens = {}
        if os.path.exists(honeytokens_db):
            try:
                with open(honeytokens_db, 'r') as f:
                    content = f.read()
                    if content:
                        tokens = json.loads(content)
            except Exception as e:
                self.logger.error(f"Error loading honeytokens database: {e}")
        
        # Add new honeytoken
        tokens[honeytoken_id] = {
            "client_id": client_id,
            "created": datetime.datetime.now().isoformat(),
            "accessed": False,
            "access_count": 0,
            "last_accessed": None,
            "access_ips": []
        }
        
        # Save updated honeytokens database
        try:
            with open(honeytokens_db, 'w') as f:
                json.dump(tokens, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving honeytokens database: {e}")

    def _handle_fingerprint_submission(self, client_socket: socket.socket, headers: Dict[str, str],
                                      connection_data: Dict[str, Any], address: Tuple[str, int]) -> None:
        """
        Handle fingerprint data submission from JavaScript
        
        Args:
            client_socket: Client socket object
            headers: HTTP headers dictionary
            connection_data: Dictionary to store connection data for logging
            address: Client address tuple (ip, port)
        """
        try:
            # Extract the JSON data from the request body
            content_length = int(headers.get("Content-Length", 0))
            if content_length == 0:
                self._send_simple_response(client_socket, "204 No Content")
                return
                
            # Read the request body data
            request_body = b""
            remaining = content_length
            while remaining > 0:
                chunk = client_socket.recv(min(4096, remaining))
                if not chunk:
                    break
                request_body += chunk
                remaining -= len(chunk)
                
            # Parse the JSON data
            try:
                fingerprint_data = json.loads(request_body.decode('utf-8', errors='ignore'))
            except json.JSONDecodeError:
                self._send_simple_response(client_socket, "400 Bad Request")
                return
                
            # Extract the client ID
            client_id = fingerprint_data.get("client_id", "unknown")
            
            # Store fingerprint data in a dedicated file
            fingerprint_dir = os.path.join(self.config["logging"]["dir"], "fingerprints")
            os.makedirs(fingerprint_dir, exist_ok=True)
            
            # Create a filename based on client ID and timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            filename = f"{client_id}_{timestamp}.json"
            file_path = os.path.join(fingerprint_dir, filename)
            
            # Add IP address to the fingerprint data
            fingerprint_data["ip_address"] = address[0]
            
            # Write the fingerprint data to file
            with open(file_path, 'w') as f:
                json.dump(fingerprint_data, f, indent=2)
                
            # Log the fingerprint collection
            self.logger.info(f"Collected browser fingerprint from {address[0]} (Client ID: {client_id})")
            
            # Update the unified logger
            if self.unified_logger:
                # Extract key fingerprint data for logging
                key_data = {
                    "client_id": client_id,
                    "screen_resolution": f"{fingerprint_data.get('screen', {}).get('width', 'unknown')}x{fingerprint_data.get('screen', {}).get('height', 'unknown')}",
                    "browser_features": fingerprint_data.get("features", {}),
                    "timezone": fingerprint_data.get("timezone", {})
                }
                
                self.unified_logger.log_attack(
                    service="http",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="browser_fingerprint",
                    additional_data={
                        "fingerprint_file": filename,
                        "key_data": key_data
                    }
                )
                
            # Send a simple OK response
            self._send_simple_response(client_socket, "204 No Content")
            
        except Exception as e:
            self.logger.error(f"Error handling fingerprint submission: {e}")
            self._send_simple_response(client_socket, "500 Internal Server Error")

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
        # Get client_id from connection data
        client_id = connection_data.get("data", {}).get("client_id")
        
        # Log vulnerable page access to unified logger
        if self.unified_logger:
            self.unified_logger.log_attack(
                service="http",
                attacker_ip=address[0],
                attacker_port=address[1],
                command="vulnerable_page_access",
                additional_data={
                    "path": path,
                    "headers": headers,
                    "client_id": client_id
                }
            )
        
        # Default response is a login form
        if path == "/admin" or path == "/phpmyadmin" or path == "/wordpress/wp-admin":
            self._send_login_page(client_socket, path, client_id)
        else:
            # Default to 404 for unknown vulnerable pages
            self._send_error(client_socket, 404, "Not Found", client_id)

    def _send_simple_response(self, client_socket: socket.socket, status: str) -> None:
        """
        Send a simple HTTP response with no body
        
        Args:
            client_socket: Client socket object
            status: HTTP status line (e.g., "200 OK")
        """
        try:
            status_line = f"HTTP/1.1 {status}\r\n"
            headers = [
                f"Server: {self.server_name}",
                f"Date: {datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')}",
                "Content-Length: 0",
                "Connection: close"
            ]
            
            response = status_line + "\r\n".join(headers) + "\r\n\r\n"
            client_socket.send(response.encode())
            
        except Exception as e:
            self.logger.error(f"Error sending simple response: {e}")

    def _serve_file(self, client_socket: socket.socket, file_path: str, client_id: str = None) -> None:
        """
        Serve a file over HTTP with tracking cookie, JavaScript fingerprinting, and honeytokens
        
        Args:
            client_socket: Client socket object
            file_path: Path to the file to serve
            client_id: Client tracking ID (optional)
        """
        try:
            # Get file extension for content type
            _, ext = os.path.splitext(file_path)
            content_type = self._get_content_type(ext)
    
            # Read file content
            with open(file_path, "rb") as f:
                content = f.read()
                
            # Convert to string for manipulation if it's an HTML file
            if content_type == "text/html" and ext.lower() in ['.html', '.htm', '.php']:
                # Convert to string for manipulation
                content_str = content.decode('utf-8', errors='ignore')
                
                # Inject honeytokens
                if client_id:
                    content_str = self._inject_honeytokens(content_str, client_id)
                
                # Inject fingerprinting JavaScript
                if '</body>' in content_str:
                    # Inject our fingerprinting script before the closing body tag
                    fingerprint_script = self._get_fingerprint_script(client_id)
                    content_str = content_str.replace('</body>', f'{fingerprint_script}\n</body>')
                else:
                    # If no </body> tag, try to append to the end of the document
                    fingerprint_script = self._get_fingerprint_script(client_id)
                    content_str += f'\n{fingerprint_script}\n'
                    
                # Convert back to bytes
                content = content_str.encode('utf-8')
    
            # Send response headers
            status_line = "HTTP/1.1 200 OK\r\n"
            headers = [
                f"Server: {self.server_name}",
                f"Content-Type: {content_type}",
                f"Content-Length: {len(content)}",
                f"Date: {datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')}"
            ]
            
            # Add tracking cookie if client_id is provided
            if client_id:
                expiry_date = (datetime.datetime.now() + datetime.timedelta(days=365)).strftime('%a, %d %b %Y %H:%M:%S GMT')
                cookie_header = f"Set-Cookie: HONEYPOT_ID={client_id}; Expires={expiry_date}; Path=/; HttpOnly"
                headers.append(cookie_header)
            
            headers.append("Connection: close")
    
            response = status_line + "\r\n".join(headers) + "\r\n\r\n"
            client_socket.send(response.encode())
    
            # Send file content
            client_socket.send(content)
    
        except Exception as e:
            self.logger.error(f"Error serving file {file_path}: {e}")
            self._send_error(client_socket, 500, "Internal Server Error")

    def _get_fingerprint_script(self, client_id: str) -> str:
        """
        Generate JavaScript code for fingerprinting the client's browser
        
        Args:
            client_id: Client tracking ID
            
        Returns:
            JavaScript code for fingerprinting
        """
        # Create the fingerprinting endpoint
        fingerprint_endpoint = "/fp"
        
        # Create the fingerprinting script
        script = f"""
    <script type="text/javascript">
        (function() {{
            // Wait for page to load
            window.addEventListener('load', function() {{
                try {{
                    // Create data object
                    var fingerprint = {{
                        client_id: '{client_id}',
                        timestamp: new Date().toISOString(),
                        screen: {{
                            width: window.screen.width,
                            height: window.screen.height,
                            availWidth: window.screen.availWidth,
                            availHeight: window.screen.availHeight,
                            colorDepth: window.screen.colorDepth,
                            pixelDepth: window.screen.pixelDepth
                        }},
                        window: {{
                            innerWidth: window.innerWidth,
                            innerHeight: window.innerHeight,
                            outerWidth: window.outerWidth,
                            outerHeight: window.outerHeight
                        }},
                        navigator: {{
                            userAgent: navigator.userAgent,
                            language: navigator.language,
                            languages: JSON.stringify(navigator.languages || []),
                            platform: navigator.platform,
                            vendor: navigator.vendor,
                            doNotTrack: navigator.doNotTrack,
                            cookieEnabled: navigator.cookieEnabled,
                            hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
                            maxTouchPoints: navigator.maxTouchPoints || 0
                        }},
                        timezone: {{
                            offset: new Date().getTimezoneOffset(),
                            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
                        }},
                        plugins: (function() {{
                            var plugins = [];
                            for (var i = 0; i < navigator.plugins.length; i++) {{
                                var p = navigator.plugins[i];
                                plugins.push({{
                                    name: p.name,
                                    description: p.description,
                                    filename: p.filename
                                }});
                            }}
                            return plugins;
                        }})(),
                        mimeTypes: (function() {{
                            var mimeTypes = [];
                            for (var i = 0; i < navigator.mimeTypes.length; i++) {{
                                var m = navigator.mimeTypes[i];
                                mimeTypes.push({{
                                    type: m.type,
                                    description: m.description,
                                    suffixes: m.suffixes
                                }});
                            }}
                            return mimeTypes;
                        }})(),
                        webgl: (function() {{
                            var canvas = document.createElement('canvas');
                            var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                            if (!gl) return null;
                            
                            return {{
                                vendor: gl.getParameter(gl.VENDOR),
                                renderer: gl.getParameter(gl.RENDERER),
                                version: gl.getParameter(gl.VERSION),
                                shading_version: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
                                extensions: gl.getSupportedExtensions()
                            }};
                        }})(),
                        canvas: (function() {{
                            var canvas = document.createElement('canvas');
                            canvas.width = 200;
                            canvas.height = 50;
                            var ctx = canvas.getContext('2d');
                            
                            // Draw text with different styles
                            ctx.textBaseline = 'top';
                            ctx.font = '14px Arial';
                            ctx.fillStyle = '#F60';
                            ctx.fillRect(0, 0, 200, 50);
                            ctx.fillStyle = '#069';
                            ctx.fillText('Fingerprint', 2, 15);
                            ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
                            ctx.fillText('Test', 2, 30);
                            
                            return {{
                                dataUrl: canvas.toDataURL()
                            }};
                        }})(),
                        connection: {{
                            type: navigator.connection ? navigator.connection.effectiveType : 'unknown',
                            downlink: navigator.connection ? navigator.connection.downlink : 'unknown',
                            rtt: navigator.connection ? navigator.connection.rtt : 'unknown'
                        }},
                        location: window.location.href,
                        referrer: document.referrer,
                        features: {{
                            localStorage: !!window.localStorage,
                            sessionStorage: !!window.sessionStorage,
                            indexedDB: !!window.indexedDB,
                            addEventListenerEnabled: !!window.addEventListener,
                            webSockets: !!window.WebSocket,
                            webRTC: !!window.RTCPeerConnection,
                            webWorkers: !!window.Worker,
                            xhr: !!window.XMLHttpRequest,
                            fetch: !!window.fetch,
                            webP: (function() {{
                                var elem = document.createElement('canvas');
                                if (elem.getContext && elem.getContext('2d')) {{
                                    return elem.toDataURL('image/webp').indexOf('data:image/webp') === 0;
                                }}
                                return false;
                            }})()
                        }}
                    }};
                    
                    // Send fingerprint data to server
                    var request = new XMLHttpRequest();
                    request.open('POST', '{fingerprint_endpoint}', true);
                    request.setRequestHeader('Content-Type', 'application/json');
                    request.send(JSON.stringify(fingerprint));
                }} catch (e) {{
                    // Silently fail
                }}
            }});
        }})();
    </script>
        """
        return script

    def _send_error(self, client_socket: socket.socket, status_code: int, message: str, client_id: str = None) -> None:
        """
        Send an HTTP error response with tracking cookie, fingerprinting, and honeytokens
    
        Args:
            client_socket: Client socket object
            status_code: HTTP status code
            message: Error message
            client_id: Client tracking ID (optional)
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
            # Inject honeytokens if we have a client_id
            if client_id:
                content = self._inject_honeytokens(content, client_id)
                
                # Also inject fingerprinting script
                fingerprint_script = self._get_fingerprint_script(client_id)
                if "</body>" in content:
                    content = content.replace("</body>", f"{fingerprint_script}\n</body>")
                else:
                    content += f"\n{fingerprint_script}\n"
    
            headers = [
                f"Server: {self.server_name}",
                "Content-Type: text/html; charset=utf-8",
                f"Content-Length: {len(content)}"
            ]
            
            # Add tracking cookie if client_id is provided
            if client_id:
                expiry_date = (datetime.datetime.now() + datetime.timedelta(days=365)).strftime('%a, %d %b %Y %H:%M:%S GMT')
                cookie_header = f"Set-Cookie: HONEYPOT_ID={client_id}; Expires={expiry_date}; Path=/; HttpOnly"
                headers.append(cookie_header)
                
            headers.extend([
                f"Date: {datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')}",
                "Connection: close"
            ])
    
            response = status_line + "\r\n".join(headers) + "\r\n\r\n"
            client_socket.send(response.encode())
    
            # Send content
            client_socket.send(content.encode())
    
        except Exception as e:
            self.logger.error(f"Error sending HTTP error: {e}")

    def _send_login_page(self, client_socket: socket.socket, path: str, client_id: str = None) -> None:
        """
        Send a fake login page with tracking cookie, fingerprinting, and honeytokens
    
        Args:
            client_socket: Client socket object
            path: Request path
            client_id: Client tracking ID (optional)
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
            # Inject honeytokens if we have a client_id
            if client_id:
                content = self._inject_honeytokens(content, client_id)
                
                # Also inject fingerprinting script
                fingerprint_script = self._get_fingerprint_script(client_id)
                if "</body>" in content:
                    content = content.replace("</body>", f"{fingerprint_script}\n</body>")
                else:
                    content += f"\n{fingerprint_script}\n"
    
            headers = [
                f"Server: {self.server_name}",
                "Content-Type: text/html; charset=utf-8",
                f"Content-Length: {len(content)}"
            ]
            
            # Add tracking cookie if client_id is provided
            if client_id:
                expiry_date = (datetime.datetime.now() + datetime.timedelta(days=365)).strftime('%a, %d %b %Y %H:%M:%S GMT')
                cookie_header = f"Set-Cookie: HONEYPOT_ID={client_id}; Expires={expiry_date}; Path=/; HttpOnly"
                headers.append(cookie_header)
                
            headers.extend([
                f"Date: {datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')}",
                "Connection: close"
            ])
    
            response = status_line + "\r\n".join(headers) + "\r\n\r\n"
            client_socket.send(response.encode())
    
            # Send content
            client_socket.send(content.encode())
    
        except Exception as e:
            self.logger.error(f"Error sending login page: {e}")
            self._send_error(client_socket, 500, "Internal Server Error", client_id)

    def _send_login_error(self, client_socket: socket.socket, path: str, client_id: str = None) -> None:
        """
        Send a login error page with tracking cookie, fingerprinting, and honeytokens
    
        Args:
            client_socket: Client socket object
            path: Request path
            client_id: Client tracking ID (optional)
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
            # Inject honeytokens if we have a client_id
            if client_id:
                content = self._inject_honeytokens(content, client_id)
                
                # Also inject fingerprinting script
                fingerprint_script = self._get_fingerprint_script(client_id)
                if "</body>" in content:
                    content = content.replace("</body>", f"{fingerprint_script}\n</body>")
                else:
                    content += f"\n{fingerprint_script}\n"
    
            headers = [
                f"Server: {self.server_name}",
                "Content-Type: text/html; charset=utf-8",
                f"Content-Length: {len(content)}"
            ]
            
            # Add tracking cookie if client_id is provided
            if client_id:
                expiry_date = (datetime.datetime.now() + datetime.timedelta(days=365)).strftime('%a, %d %b %Y %H:%M:%S GMT')
                cookie_header = f"Set-Cookie: HONEYPOT_ID={client_id}; Expires={expiry_date}; Path=/; HttpOnly"
                headers.append(cookie_header)
                
            headers.extend([
                f"Date: {datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')}",
                "Connection: close"
            ])
    
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

    def _analyze_request_parameters(self, method: str, path: str, headers: Dict[str, str], 
                                  post_data: Dict[str, str], connection_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze request parameters for both GET and POST requests
        
        Args:
            method: HTTP method
            path: Request path
            headers: HTTP headers dictionary
            post_data: Parsed POST data dictionary
            connection_data: Dictionary to store connection data for logging
            
        Returns:
            Dictionary of analysis results
        """
        analysis = {
            "attack_vectors": [],
            "suspicious_parameters": {},
            "risk_level": "low",
            "attack_type": "unknown"
        }
        
        # Parse query parameters from the URL
        query_params = {}
        if "?" in path:
            path_part, query_part = path.split("?", 1)
            query_string = query_part.split("#")[0]  # Remove any URL fragment
            
            for param in query_string.split("&"):
                if "=" in param:
                    key, value = param.split("=", 1)
                    query_params[unquote(key)] = unquote(value)
        
        # Combine query parameters and POST data for analysis
        all_params = {**query_params, **post_data}
        
        # Known attack patterns to detect
        attack_patterns = {
            "sql_injection": [
                r"[\s'\"`;)(]+(select|union|insert|update|delete|drop|alter|create|where|from|and|or)[\s'\"`;)(]+",
                r"--+.*",
                r"\/\*.*\*\/",
                r";\s*(select|union|insert|update|delete|drop|alter|create|where)",
                r"xp_cmdshell"
            ],
            "xss": [
                r"<[^>]*script.*>",
                r"<[^>]*img[^>]*onerror.*>",
                r"javascript:",
                r"vbscript:",
                r"onload=",
                r"onclick=",
                r"onmouseover=",
                r"<[^>]*iframe.*>",
                r"<svg[^>]*on.*=.*>"
            ],
            "path_traversal": [
                r"\.\.\/",
                r"\.\.\\",
                r"%2e%2e%2f",
                r"%252e%252e%252f",
                r"\/etc\/passwd",
                r"C:\\Windows\\system32",
                r"\/windows\/system32"
            ],
            "command_injection": [
                r"[;&|`].*(?:cat|ls|dir|rm|cp|mv|chmod|wget|curl|bash|sh|python|perl|ruby|nc|ncat|ping|nmap)",
                r"\$\([^)]*\)",
                r"\${[^}]*}",
                r"`[^`]*`"
            ],
            "ldap_injection": [
                r"\*\)",
                r"\(\|\(",
                r"objectClass=\*",
                r"objectClass=person\)",
                r"sn=\)"
            ],
            "xxe": [
                r"<!ENTITY",
                r"<!DOCTYPE",
                r"SYSTEM[\s\"'][^\"']*file:\/\/"
            ],
            "unvalidated_redirect": [
                r"(https?|ftp):\/\/(?!(?:localhost|127\.0\.0\.1))"
            ],
            "scanner_fingerprint": [
                r"acunetix",
                r"nessus",
                r"nikto",
                r"burpsuite",
                r"owasp",
                r"netsparker",
                r"sqlmap",
                r"w3af",
                r"openvas",
                r"nuclei"
            ]
        }
        
        # Check each parameter for attack patterns
        for param_name, param_value in all_params.items():
            # Skip empty values
            if not param_value:
                continue
                
            # Convert to string if not already
            if not isinstance(param_value, str):
                param_value = str(param_value)
            
            # Check against each attack pattern
            for attack_type, patterns in attack_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, param_value, re.IGNORECASE):
                        if attack_type not in analysis["attack_vectors"]:
                            analysis["attack_vectors"].append(attack_type)
                        
                        if param_name not in analysis["suspicious_parameters"]:
                            analysis["suspicious_parameters"][param_name] = []
                        
                        if attack_type not in analysis["suspicious_parameters"][param_name]:
                            analysis["suspicious_parameters"][param_name].append(attack_type)
        
        # Determine risk level based on detected attacks
        high_risk_attacks = ["sql_injection", "command_injection", "xxe"]
        medium_risk_attacks = ["xss", "path_traversal", "ldap_injection", "unvalidated_redirect"]
        
        if any(attack in analysis["attack_vectors"] for attack in high_risk_attacks):
            analysis["risk_level"] = "high"
        elif any(attack in analysis["attack_vectors"] for attack in medium_risk_attacks):
            analysis["risk_level"] = "medium"
        elif "scanner_fingerprint" in analysis["attack_vectors"]:
            analysis["risk_level"] = "medium"
            analysis["attack_type"] = "scanner"
        
        # Determine primary attack type
        if analysis["attack_vectors"]:
            # Prioritize high risk attacks in naming
            for attack in high_risk_attacks:
                if attack in analysis["attack_vectors"]:
                    analysis["attack_type"] = attack
                    break
            else:
                # If no high risk attacks found, use the first detected attack
                analysis["attack_type"] = analysis["attack_vectors"][0]
        
        # Store parameter analysis in connection data
        connection_data["data"]["parameter_analysis"] = analysis
        
        # Check for specific attack tools
        if "User-Agent" in headers:
            user_agent = headers["User-Agent"].lower()
            scanner_signatures = {
                "nikto": r"nikto",
                "acunetix": r"acunetix",
                "nessus": r"nessus",
                "nmap": r"nmap|masscan",
                "burpsuite": r"burp",
                "sqlmap": r"sqlmap",
                "metasploit": r"metasploit",
                "hydra": r"hydra",
                "w3af": r"w3af",
                "dirbuster": r"dirbuster",
                "gobuster": r"gobuster|dirb|dirsearch",
                "owasp zap": r"zap",
                "wfuzz": r"wfuzz",
                "nuclei": r"nuclei"
            }
            
            for scanner, pattern in scanner_signatures.items():
                if re.search(pattern, user_agent, re.IGNORECASE):
                    analysis["attack_type"] = "scanner"
                    analysis["scanner_tool"] = scanner
                    analysis["risk_level"] = "medium"  # Scanner activity is always at least medium risk
                    
                    if "attack_vectors" not in analysis or "scanner_fingerprint" not in analysis["attack_vectors"]:
                        analysis["attack_vectors"].append("scanner_fingerprint")
                    break
        
        return analysis

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
