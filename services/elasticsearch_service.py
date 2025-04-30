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
Elasticsearch service emulator for the honeypot system
"""

import socket
import threading
import logging
import datetime
import json
import os
import time
import re
import random
from typing import Dict, List, Any, Tuple

from services.base_service import BaseService


class ElasticsearchService(BaseService):
    def __init__(self, host: str, port: int, config: Dict[str, Any], unified_logger=None):
        """
        Initialize the Elasticsearch service
        
        Args:
            host: Host IP to bind to
            port: Port to listen on
            config: Global configuration dictionary
            unified_logger: Unified logger instance for centralized logging
        """
        super().__init__(host, port, config, "elasticsearch")
        
        # Store unified logger instance
        self.unified_logger = unified_logger
        
        self.server_version = self.service_config.get("server_version", "6.8.0")
        self.cluster_name = self.service_config.get("cluster_name", "elasticsearch-cluster")
        self.indices = ["users", "config", "logs", "transactions", "passwords"]
        self.fake_data = self._generate_fake_data()

    def _generate_fake_data(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            "users": [
                {"_id": "1", "username": "admin", "email": "admin@example.com", "admin": True},
                {"_id": "2", "username": "user1", "email": "user1@example.com", "admin": False},
                {"_id": "3", "username": "system", "email": "system@internal", "admin": True}
            ],
            "config": [
                {"_id": "1", "name": "database", "host": "db", "username": "dbuser", "password": "dbpass123"},
                {"_id": "2", "name": "api", "key": "api-key-xyz"},
                {"_id": "3", "name": "email", "smtp": "mail.example.com", "username": "mailer", "password": "smtp-password"}
            ],
            "logs": [
                {"_id": "1", "timestamp": "2024-01-01T00:00:00Z", "level": "INFO", "message": "Startup complete"},
                {"_id": "2", "timestamp": "2024-01-01T00:05:00Z", "level": "ERROR", "message": "DB connection failed"}
            ]
        }

    def handle_client(self, client_socket: socket.socket, address: Tuple[str, int], connection_data: Dict[str, Any]) -> None:
        """
        Handle a client connection to the Elasticsearch service
        
        Args:
            client_socket: Client socket object
            address: Client address tuple (ip, port)
            connection_data: Dictionary to store connection data for logging
        """
        connection_data["data"]["connection_time"] = datetime.datetime.now().isoformat()
        queries = []
        
        # Log connection attempt to unified logger
        if self.unified_logger:
            self.unified_logger.log_attack(
                service="elasticsearch",
                attacker_ip=address[0],
                attacker_port=address[1],
                command="connection_attempt",
                additional_data={"timestamp": datetime.datetime.now().isoformat()}
            )
    
        try:
            self.logger.info(f"Elasticsearch connection from {address[0]}:{address[1]}")
    
            while True:
                request_data = b""
                content_length = 0
                headers_done = False
    
                while True:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        return
                    request_data += chunk
                    if not headers_done and b"\r\n\r\n" in request_data:
                        headers, body = request_data.split(b"\r\n\r\n", 1)
                        headers_done = True
                        match = re.search(rb"Content-Length: (\d+)", headers)
                        if match:
                            content_length = int(match.group(1))
                    if headers_done and len(body) >= content_length:
                        break
    
                if not request_data:
                    break
    
                http_request = request_data.decode("utf-8", errors="ignore")
                self.logger.debug(f"Full HTTP request:\n{http_request}")
                response, query_info = self._process_http_request(http_request, address)
    
                if query_info:
                    queries.append(query_info)
                    connection_data["data"]["queries"] = queries
                    
                    # Log query to unified logger
                    if self.unified_logger:
                        self.unified_logger.log_attack(
                            service="elasticsearch",
                            attacker_ip=address[0],
                            attacker_port=address[1],
                            command=f"elasticsearch_query_{query_info.get('method', 'unknown')}_{query_info.get('operation', 'unknown')}",
                            additional_data=query_info
                        )
    
                client_socket.send(response.encode())
    
        except Exception as e:
            self.logger.error(f"Error handling Elasticsearch client: {e}")
            connection_data["error"] = str(e)
            
            # Log error to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="elasticsearch",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="error",
                    additional_data={"error": str(e)}
                )
        finally:
            client_socket.close()

    def _process_http_request(self, http_request: str, address: Tuple[str, int]) -> Tuple[str, Dict[str, Any]]:
        """
        Process HTTP request to Elasticsearch API
        
        Args:
            http_request: Raw HTTP request
            address: Client address tuple (ip, port)
            
        Returns:
            Tuple of (HTTP response, query info dict)
        """
        lines = http_request.split("\r\n")
        request_line = lines[0] if lines else ""
        self.logger.debug(f"Request line: {request_line}")
    
        parts = request_line.split(" ")
        if len(parts) < 2:
            # Log malformed request to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="elasticsearch",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="malformed_request",
                    additional_data={"request_line": request_line}
                )
            return self._generate_error_response(400, "Bad Request"), {"error": "Malformed request"}
    
        method, raw_path = parts[0], parts[1]
        path = raw_path.split('?')[0].rstrip("/")
    
        body = ""
        if "\r\n\r\n" in http_request:
            body = http_request.split("\r\n\r\n", 1)[1]
    
        # Determine the operation type for better logging
        operation = "unknown"
        if path == "":
            operation = "root"
        elif path == "/_cluster/health":
            operation = "cluster_health"
        elif path.startswith("/_cat/indices"):
            operation = "cat_indices"
        elif path == "/_bulk" and method == "POST":
            operation = "bulk"
        elif path == "/_search" and method == "POST":
            operation = "search_all"
        elif re.match(r"^/[^/]+/_search$", path) and method == "POST":
            operation = "search"
        elif re.match(r"^/[^/]+/_doc$", path) and method == "POST":
            operation = "insert"
        elif re.match(r"^/[^/]+$", path) and method == "DELETE":
            operation = "delete_index"
        elif re.match(r"^/[^/]+/_mapping$", path):
            operation = "mapping"
    
        query_info = {
            "timestamp": datetime.datetime.now().isoformat(),
            "method": method,
            "path": path,
            "operation": operation,
            "body": body if body else None
        }
    
        # Log the query to unified logger with more detailed operation info
        if self.unified_logger:
            additional_info = {"operation_details": {}}
            
            # Extract more details based on operation type
            if operation == "search" or operation == "search_all":
                try:
                    # Try to parse search query if it's JSON
                    if body:
                        search_body = json.loads(body)
                        if "query" in search_body:
                            additional_info["operation_details"]["query"] = search_body["query"]
                        if "sort" in search_body:
                            additional_info["operation_details"]["sort"] = search_body["sort"]
                            
                    # Track index being searched
                    if operation == "search":
                        index = path.split('/')[1]
                        additional_info["operation_details"]["index"] = index
                except json.JSONDecodeError:
                    pass
            
            elif operation == "insert":
                try:
                    if body:
                        # Try to parse the document being inserted
                        doc_body = json.loads(body)
                        # Track index being inserted into
                        index = path.split('/')[1]
                        additional_info["operation_details"]["index"] = index
                        additional_info["operation_details"]["document_keys"] = list(doc_body.keys())
                except json.JSONDecodeError:
                    pass
            
            elif operation == "delete_index":
                # Track which index is being deleted
                index = path.lstrip("/")
                additional_info["operation_details"]["index"] = index
            
            # Update query_info with additional details
            query_info.update(additional_info)
    
        if path == "":
            return self._handle_root_request(address), query_info
        elif path == "/_cluster/health":
            return self._handle_cluster_health(address), query_info
        elif path.startswith("/_cat/indices"):
            return self._handle_cat_indices(address), query_info
        elif path == "/_bulk" and method == "POST":
            return self._handle_bulk(body, address), query_info
        elif path == "/_search" and method == "POST":
            return self._handle_search_all(body, address), query_info
        elif re.match(r"^/[^/]+/_search$", path) and method == "POST":
            index = path.split('/')[1]
            return self._handle_search(index, body, address), query_info
        elif re.match(r"^/[^/]+/_doc$", path) and method == "POST":
            index = path.split('/')[1]
            return self._handle_insert(index, body, address), query_info
        elif re.match(r"^/[^/]+$", path) and method == "DELETE":
            index = path.lstrip("/")
            return self._handle_delete(index, address), query_info
        elif re.match(r"^/[^/]+/_mapping$", path):
            index = path.split('/')[1]
            return self._handle_mapping(index, address), query_info
        else:
            # Log unknown endpoint to unified logger
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="elasticsearch",
                    attacker_ip=address[0],
                    attacker_port=address[1],
                    command="unknown_endpoint",
                    additional_data={"path": path, "method": method}
                )
            return self._generate_error_response(404, f"Endpoint {path} not found"), query_info

    def _handle_root_request(self, address: Tuple[str, int]) -> str:
        """Handle root endpoint request"""
        if self.unified_logger:
            self.unified_logger.log_attack(
                service="elasticsearch",
                attacker_ip=address[0],
                attacker_port=address[1],
                command="elasticsearch_root",
                additional_data={
                    "version": self.server_version,
                    "cluster_name": self.cluster_name
                }
            )
            
        body = json.dumps({
            "name": "node-1",
            "cluster_name": self.cluster_name,
            "cluster_uuid": "uuid123456",
            "version": {
                "number": self.server_version,
                "build_flavor": "default",
                "build_type": "tar",
                "build_hash": "fakehash",
                "build_date": "2024-01-01T00:00:00Z",
                "build_snapshot": False,
                "lucene_version": "7.7.0"
            },
            "tagline": "You Know, for Search"
        })
        return self._generate_http_response(200, "OK", body)

    def _handle_cluster_health(self) -> str:
        body = json.dumps({
            "cluster_name": self.cluster_name,
            "status": "green",
            "timed_out": False,
            "number_of_nodes": 3,
            "active_shards": 10
        })
        return self._generate_http_response(200, "OK", body)

    def _handle_cat_indices(self) -> str:
        header = "health status index uuid pri rep docs.count docs.deleted store.size pri.store.size"
        lines = [header]
        for index in self.indices:
            lines.append(f"green open {index} uuid123 1 1 {random.randint(10,100)} 0 {random.randint(1,10)}kb {random.randint(1,5)}kb")
        return self._generate_http_response(200, "OK", "\n".join(lines), content_type="text/plain")

    def _handle_search(self, index: str, body: str, address: Tuple[str, int]) -> str:
        """Handle search request for a specific index"""
        # Parse the search body if possible
        search_details = {}
        try:
            if body:
                search_body = json.loads(body)
                search_details = search_body
        except json.JSONDecodeError:
            search_details = {"error": "Invalid JSON in search body"}
        
        # Log to unified logger
        if self.unified_logger:
            self.unified_logger.log_attack(
                service="elasticsearch",
                attacker_ip=address[0],
                attacker_port=address[1],
                command="elasticsearch_search",
                additional_data={
                    "index": index,
                    "search_body": search_details
                }
            )
        
        hits = self.fake_data.get(index, [])
        response = {
            "took": random.randint(10, 50),
            "hits": {
                "total": len(hits),
                "max_score": 1.0,
                "hits": [
                    {"_index": index, "_type": "_doc", "_id": doc["_id"], "_score": 1.0, "_source": {k: v for k, v in doc.items() if k != "_id"}}
                    for doc in hits
                ]
            }
        }
        return self._generate_http_response(200, "OK", json.dumps(response))

    def _handle_search_all(self, body: str) -> str:
        all_hits = []
        for index, docs in self.fake_data.items():
            for doc in docs:
                all_hits.append({
                    "_index": index, "_type": "_doc", "_id": doc["_id"], "_score": 1.0,
                    "_source": {k: v for k, v in doc.items() if k != "_id"}
                })
        response = {
            "took": random.randint(10, 50),
            "hits": {"total": len(all_hits), "max_score": 1.0, "hits": all_hits}
        }
        return self._generate_http_response(200, "OK", json.dumps(response))

    def _handle_insert(self, index: str, body: str) -> str:
        fake_id = str(random.randint(1000, 9999))
        response = {
            "_index": index,
            "_type": "_doc",
            "_id": fake_id,
            "_version": 1,
            "result": "created",
            "_shards": {"total": 2, "successful": 1, "failed": 0}
        }
        return self._generate_http_response(201, "Created", json.dumps(response))

    def _handle_delete(self, index: str, address: Tuple[str, int]) -> str:
        """Handle delete index request"""
        # Log sensitive operation to unified logger
        if self.unified_logger:
            self.unified_logger.log_attack(
                service="elasticsearch",
                attacker_ip=address[0],
                attacker_port=address[1],
                command="elasticsearch_delete_index",
                additional_data={
                    "index": index,
                    "sensitive_operation": True
                }
            )
        
        return self._generate_http_response(200, "OK", json.dumps({"acknowledged": True}))

    def _handle_mapping(self, index: str) -> str:
        response = {
            index: {
                "mappings": {
                    "properties": {
                        "username": {"type": "text"},
                        "email": {"type": "keyword"},
                        "admin": {"type": "boolean"}
                    }
                }
            }
        }
        return self._generate_http_response(200, "OK", json.dumps(response))

    def _handle_bulk(self, body: str) -> str:
        items = [{"index": {"_index": "bulk-index", "_id": str(i), "status": 201}} for i in range(3)]
        response = {"took": random.randint(5, 50), "errors": False, "items": items}
        return self._generate_http_response(200, "OK", json.dumps(response))

    def _generate_http_response(self, status_code: int, status_text: str, body: str, content_type: str = "application/json") -> str:
        headers = [
            f"HTTP/1.1 {status_code} {status_text}",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body)}",
            f"Date: {datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')}",
            "Connection: close"
        ]
        return "\r\n".join(headers) + "\r\n\r\n" + body

    def _generate_error_response(self, status_code: int, msg: str) -> str:
        return self._generate_http_response(
            status_code,
            "Error",
            json.dumps({"error": {"reason": msg}, "status": status_code})
        )

    def start(self) -> None:
        """Start the Elasticsearch service"""
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            self.running = True
            
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="elasticsearch",
                    attacker_ip="system",
                    attacker_port=0,
                    command="service_start",
                    additional_data={"port": self.port}
                )
            
            self.logger.info(f"Elasticsearch honeypot started on port {self.port}")
            
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
                    self.logger.info(f"Connection from {addr[0]}:{addr[1]} to Elasticsearch service")
                    
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
                            service="elasticsearch",
                            attacker_ip="error",
                            attacker_port=0,
                            command="error",
                            additional_data={"error": str(e)}
                        )
                    self.logger.error(f"Error accepting connection: {e}")
                    
        except Exception as e:
            if self.unified_logger:
                self.unified_logger.log_attack(
                    service="elasticsearch",
                    attacker_ip="error",
                    attacker_port=0,
                    command="service_error",
                    additional_data={"error": str(e)}
                )
            self.logger.error(f"Error starting Elasticsearch service: {e}")
        finally:
            if self.sock:
                self.sock.close()
