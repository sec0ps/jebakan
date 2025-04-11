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
Docker API service emulator for the honeypot system
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
from typing import Dict, List, Any, Tuple, Optional

from services.base_service import BaseService

class DockerService(BaseService):
    """Docker API service emulator for the honeypot"""

    def __init__(self, host: str, port: int, config: Dict[str, Any]):
        """
        Initialize the Docker API service

        Args:
            host: Host IP to bind to
            port: Port to listen on
            config: Global configuration dictionary
        """
        super().__init__(host, port, config, "docker")

        # Docker API specific configurations
        self.api_version = self.service_config.get("api_version", "1.41")
        self.docker_version = self.service_config.get("docker_version", "20.10.7")

        # Fake container data
        self.containers = self._generate_fake_containers()
        self.images = self._generate_fake_images()

    def _generate_fake_containers(self) -> List[Dict[str, Any]]:
        """Generate fake container data"""
        return [
            {
                "Id": "abc123def456",
                "Names": ["/web-app"],
                "Image": "nginx:latest",
                "ImageID": "sha256:abc123def456...",
                "Command": "nginx -g 'daemon off;'",
                "Created": int(time.time()) - 86400,  # 1 day ago
                "State": "running",
                "Status": "Up 24 hours",
                "Ports": [{"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}],
                "Labels": {"env": "prod", "service": "web"},
                "NetworkSettings": {
                    "Networks": {
                        "bridge": {
                            "IPAddress": "172.17.0.2",
                            "Gateway": "172.17.0.1"
                        }
                    }
                }
            },
            {
                "Id": "def456abc789",
                "Names": ["/database"],
                "Image": "mysql:5.7",
                "ImageID": "sha256:def456abc789...",
                "Command": "mysqld",
                "Created": int(time.time()) - 43200,  # 12 hours ago
                "State": "running",
                "Status": "Up 12 hours",
                "Ports": [{"IP": "0.0.0.0", "PrivatePort": 3306, "PublicPort": 3306, "Type": "tcp"}],
                "Labels": {"env": "prod", "service": "db"},
                "NetworkSettings": {
                    "Networks": {
                        "bridge": {
                            "IPAddress": "172.17.0.3",
                            "Gateway": "172.17.0.1"
                        }
                    }
                }
            },
            {
                "Id": "ghi789jkl012",
                "Names": ["/redis-cache"],
                "Image": "redis:alpine",
                "ImageID": "sha256:ghi789jkl012...",
                "Command": "redis-server",
                "Created": int(time.time()) - 172800,  # 2 days ago
                "State": "running",
                "Status": "Up 2 days",
                "Ports": [{"IP": "0.0.0.0", "PrivatePort": 6379, "PublicPort": 6379, "Type": "tcp"}],
                "Labels": {"env": "prod", "service": "cache"},
                "NetworkSettings": {
                    "Networks": {
                        "bridge": {
                            "IPAddress": "172.17.0.4",
                            "Gateway": "172.17.0.1"
                        }
                    }
                }
            }
        ]

    def _generate_fake_images(self) -> List[Dict[str, Any]]:
        """Generate fake image data"""
        return [
            {
                "Id": "sha256:abc123def456...",
                "RepoTags": ["nginx:latest"],
                "Created": int(time.time()) - 604800,  # 1 week ago
                "Size": 133288734,
                "VirtualSize": 133288734,
                "SharedSize": 0,
                "Labels": {},
                "Containers": 1
            },
            {
                "Id": "sha256:def456abc789...",
                "RepoTags": ["mysql:5.7"],
                "Created": int(time.time()) - 1209600,  # 2 weeks ago
                "Size": 448560432,
                "VirtualSize": 448560432,
                "SharedSize": 0,
                "Labels": {},
                "Containers": 1
            },
            {
                "Id": "sha256:ghi789jkl012...",
                "RepoTags": ["redis:alpine"],
                "Created": int(time.time()) - 2592000,  # 1 month ago
                "Size": 32450821,
                "VirtualSize": 32450821,
                "SharedSize": 0,
                "Labels": {},
                "Containers": 1
            },
            {
                "Id": "sha256:jkl012mno345...",
                "RepoTags": ["ubuntu:20.04"],
                "Created": int(time.time()) - 3888000,  # 45 days ago
                "Size": 72702294,
                "VirtualSize": 72702294,
                "SharedSize": 0,
                "Labels": {},
                "Containers": 0
            }
        ]

    def handle_client(self, client_socket: socket.socket, address: Tuple[str, int],
                     connection_data: Dict[str, Any]) -> None:
        """
        Handle a client connection to the Docker API service

        Args:
            client_socket: Client socket object
            address: Client address tuple (ip, port)
            connection_data: Dictionary to store connection data for logging
        """
        connection_data["data"]["connection_time"] = datetime.datetime.now().isoformat()

        # Track API calls for this session
        api_calls = []

        try:
            self.logger.info(f"Docker API connection from {address[0]}:{address[1]}")

            while True:
                # Docker API uses HTTP, so receive until we get a complete HTTP request
                request_data = b""
                content_length = 0
                headers_done = False

                while True:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        return

                    request_data += chunk

                    # Check if we've received headers
                    if not headers_done and b"\r\n\r\n" in request_data:
                        headers, body = request_data.split(b"\r\n\r\n", 1)
                        headers_done = True

                        # Extract Content-Length
                        match = re.search(rb"Content-Length: (\d+)", headers)
                        if match:
                            content_length = int(match.group(1))

                    # If we have headers and the complete body, break
                    if headers_done and len(body) >= content_length:
                        break

                if not request_data:
                    break

                # Process HTTP request to Docker API
                http_request = request_data.decode('utf-8', errors='ignore')
                response, api_call_info = self._process_docker_api_request(http_request)

                # Log API call
                if api_call_info:
                    api_calls.append(api_call_info)
                    connection_data["data"]["api_calls"] = api_calls

                # Send response
                client_socket.send(response.encode())

        except Exception as e:
            self.logger.error(f"Error handling Docker API client: {e}")
            connection_data["error"] = str(e)
        finally:
            client_socket.close()

    def _process_docker_api_request(self, request: str) -> Tuple[str, Optional[Dict[str, Any]]]:
        """
        Process HTTP request to Docker API

        Args:
            request: Raw HTTP request

        Returns:
            Tuple of (HTTP response, API call info dict or None)
        """
        # Basic HTTP request parsing
        request_lines = request.strip().split('\r\n')
        if not request_lines:
            return self._generate_error_response(400, "Bad Request"), None

        # Parse request line
        request_line = request_lines[0].split()
        if len(request_line) < 3:
            return self._generate_error_response(400, "Bad Request"), None

        method, path, _ = request_line

        # Extract headers
        headers = {}
        i = 1
        while i < len(request_lines) and request_lines[i]:
            if ': ' in request_lines[i]:
                key, value = request_lines[i].split(': ', 1)
                headers[key.lower()] = value
            i += 1

        # Extract body if present
        body = ""
        if i < len(request_lines) - 1:
            body = '\r\n'.join(request_lines[i+1:])

        # Log the request
        api_call_info = {
            "method": method,
            "path": path,
            "body": body,
            "timestamp": datetime.datetime.now().isoformat()
        }

        self.logger.info(f"Docker API request: {method} {path}")

        # Handle different endpoints
        if path == "/v1.41/version" or path == "/version":
            return self._handle_version(), api_call_info
        elif path == "/v1.41/info" or path == "/info":
            return self._handle_info(), api_call_info
        elif path == "/v1.41/containers/json" or path == "/containers/json":
            return self._handle_list_containers(), api_call_info
        elif path == "/v1.41/images/json" or path == "/images/json":
            return self._handle_list_images(), api_call_info
        elif re.match(r"/v1\.41/containers/create", path) or re.match(r"/containers/create", path):
            return self._handle_create_container(body), api_call_info
        elif re.match(r"/v1\.41/containers/([a-zA-Z0-9]+)/start", path) or re.match(r"/containers/([a-zA-Z0-9]+)/start", path):
            container_id = re.match(r".*containers/([a-zA-Z0-9]+)/start", path).group(1)
            return self._handle_start_container(container_id), api_call_info
        elif re.match(r"/v1\.41/containers/([a-zA-Z0-9]+)/stop", path) or re.match(r"/containers/([a-zA-Z0-9]+)/stop", path):
            container_id = re.match(r".*containers/([a-zA-Z0-9]+)/stop", path).group(1)
            return self._handle_stop_container(container_id), api_call_info
        elif re.match(r"/v1\.41/containers/([a-zA-Z0-9]+)/exec", path) or re.match(r"/containers/([a-zA-Z0-9]+)/exec", path):
            container_id = re.match(r".*containers/([a-zA-Z0-9]+)/exec", path).group(1)
            return self._handle_exec_container(container_id, body), api_call_info
        else:
            return self._generate_error_response(404, "Not Found"), api_call_info

    def _handle_version(self) -> str:
        """Handle version endpoint"""
        response_body = json.dumps({
            "Version": self.docker_version,
            "ApiVersion": self.api_version,
            "MinAPIVersion": "1.12",
            "GitCommit": "f0df350",
            "GoVersion": "go1.13.15",
            "Os": "linux",
            "Arch": "amd64",
            "KernelVersion": "5.4.0-74-generic",
            "BuildTime": "2021-05-12T21:19:41.000000000+00:00"
        })

        return self._generate_http_response(200, "OK", response_body)

    def _handle_info(self) -> str:
        """Handle info endpoint"""
        response_body = json.dumps({
            "ID": "ABCD:EFGH:IJKL:MNOP:QRST:UVWX:YZ01:2345:6789:ABCD:EFGH:IJKL",
            "Containers": len(self.containers),
            "ContainersRunning": sum(1 for c in self.containers if c["State"] == "running"),
            "ContainersPaused": 0,
            "ContainersStopped": sum(1 for c in self.containers if c["State"] != "running"),
            "Images": len(self.images),
            "Driver": "overlay2",
            "DriverStatus": [
                ["Backing Filesystem", "ext"],
                ["Supports d_type", "true"],
                ["Native Overlay Diff", "true"]
            ],
            "SystemStatus": None,
            "Plugins": {
                "Volume": ["local"],
                "Network": ["bridge", "host", "macvlan", "null", "overlay"],
                "Authorization": None,
                "Log": ["awslogs", "fluentd", "gcplogs", "gelf", "journald", "json-file", "local", "logentries", "splunk", "syslog"]
            },
            "MemoryLimit": True,
            "SwapLimit": True,
            "KernelMemory": True,
            "CpuCfsPeriod": True,
            "CpuCfsQuota": True,
            "CPUShares": True,
            "CPUSet": True,
            "IPv4Forwarding": True,
            "BridgeNfIptables": True,
            "BridgeNfIp6tables": True,
            "Debug": False,
            "NFd": 64,
            "OomKillDisable": True,
            "NGoroutines": 42,
            "SystemTime": datetime.datetime.now().isoformat(),
            "LoggingDriver": "json-file",
            "CgroupDriver": "systemd",
            "NEventsListener": 0,
            "KernelVersion": "5.4.0-74-generic",
            "OperatingSystem": "Ubuntu 20.04.2 LTS",
            "OSType": "linux",
            "Architecture": "x86_64",
            "IndexServerAddress": "https://index.docker.io/v1/",
            "RegistryConfig": {
                "AllowNondistributableArtifactsCIDRs": [],
                "AllowNondistributableArtifactsHostnames": [],
                "InsecureRegistryCIDRs": ["127.0.0.0/8"],
                "IndexConfigs": {
                    "docker.io": {
                        "Name": "docker.io",
                        "Mirrors": [],
                        "Secure": True,
                        "Official": True
                    }
                },
                "Mirrors": []
            },
            "NCPU": 4,
            "MemTotal": 8272408576,
            "DockerRootDir": "/var/lib/docker",
            "HttpProxy": "",
            "HttpsProxy": "",
            "NoProxy": "",
            "Name": "docker-host",
            "Labels": [],
            "ExperimentalBuild": False,
            "ServerVersion": self.docker_version,
            "ClusterStore": "",
            "ClusterAdvertise": "",
            "DefaultRuntime": "runc",
            "LiveRestoreEnabled": False,
            "Isolation": "",
            "InitBinary": "docker-init",
            "SecurityOptions": [
                "name=apparmor",
                "name=seccomp,profile=default"
            ]
        })

        return self._generate_http_response(200, "OK", response_body)

    def _handle_list_containers(self) -> str:
        """Handle list containers endpoint"""
        return self._generate_http_response(200, "OK", json.dumps(self.containers))

    def _handle_list_images(self) -> str:
        """Handle list images endpoint"""
        return self._generate_http_response(200, "OK", json.dumps(self.images))

    def _handle_create_container(self, body: str) -> str:
        """Handle create container endpoint"""
        self.logger.warning(f"Attempt to create container with: {body}")

        try:
            # Try to parse the container creation request
            container_config = json.loads(body)

            # Log what image they're trying to run - could indicate attack type
            if "Image" in container_config:
                self.logger.warning(f"Attempt to create container with image: {container_config['Image']}")

            # Log any commands specified
            if "Cmd" in container_config:
                self.logger.warning(f"Container creation command: {container_config['Cmd']}")

            # Check for potentially malicious mounts
            if "HostConfig" in container_config and "Binds" in container_config["HostConfig"]:
                for bind in container_config["HostConfig"]["Binds"]:
                    self.logger.warning(f"Container bind mount: {bind}")

            # Return success with fake container ID
            container_id = str(uuid.uuid4()).replace("-", "")[:12]
            response_body = json.dumps({
                "Id": container_id,
                "Warnings": []
            })

            return self._generate_http_response(201, "Created", response_body)

        except json.JSONDecodeError:
            return self._generate_error_response(400, "Invalid JSON")

    def _handle_start_container(self, container_id: str) -> str:
        """Handle start container endpoint"""
        self.logger.warning(f"Attempt to start container with ID: {container_id}")

        # Always return success in honeypot
        return self._generate_http_response(204, "No Content", "")

    def _handle_stop_container(self, container_id: str) -> str:
        """Handle stop container endpoint"""
        self.logger.warning(f"Attempt to stop container with ID: {container_id}")

        # Always return success in honeypot
        return self._generate_http_response(204, "No Content", "")

    def _handle_exec_container(self, container_id: str, body: str) -> str:
        """Handle exec in container endpoint"""
        self.logger.warning(f"Attempt to exec in container with ID: {container_id}")

        try:
            # Try to parse the exec request
            exec_config = json.loads(body)

            # Log what command they're trying to run
            if "Cmd" in exec_config:
                self.logger.warning(f"Exec command: {exec_config['Cmd']}")

            # Return success with fake exec ID
            exec_id = str(uuid.uuid4()).replace("-", "")[:12]
            response_body = json.dumps({
                "Id": exec_id
            })

            return self._generate_http_response(201, "Created", response_body)

        except json.JSONDecodeError:
            return self._generate_error_response(400, "Invalid JSON")

    def _generate_http_response(self, status_code: int, status_text: str, body: str) -> str:
        """Generate HTTP response"""
        headers = [
            f"HTTP/1.1 {status_code} {status_text}",
            "Content-Type: application/json",
            f"Content-Length: {len(body)}",
            f"Date: {datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')}",
            "Docker-Experimental: false",
            "Ostype: linux",
            "Server: Docker/" + self.docker_version,
            "Api-Version: " + self.api_version,
            "Connection: close"
        ]

        return "\r\n".join(headers) + "\r\n\r\n" + body

    def _generate_error_response(self, status_code: int, error_message: str) -> str:
        """Generate HTTP error response"""
        body = json.dumps({
            "message": error_message
        })

        return self._generate_http_response(status_code, error_message, body)
