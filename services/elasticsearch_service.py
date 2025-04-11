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
from typing import Dict, List, Any, Tuple, Optional

from services.base_service import BaseService

class ElasticsearchService(BaseService):
    """Elasticsearch service emulator for the honeypot"""

    def __init__(self, host: str, port: int, config: Dict[str, Any]):
        """
        Initialize the Elasticsearch service

        Args:
            host: Host IP to bind to
            port: Port to listen on
            config: Global configuration dictionary
        """
        super().__init__(host, port, config, "elasticsearch")

        # Elasticsearch specific configurations
        self.server_version = self.service_config.get("server_version", "6.8.0")
        self.cluster_name = self.service_config.get("cluster_name", "elasticsearch-cluster")

        # Fake indices and data
        self.indices = ["users", "config", "logs", "transactions", "passwords"]
        self.fake_data = self._generate_fake_data()

    def _generate_fake_data(self) -> Dict[str, List[Dict[str, Any]]]:
        """Generate fake data for indices"""
        data = {}

        # Users index
        data["users"] = [
            {"_id": "1", "username": "admin", "email": "admin@example.com", "admin": True},
            {"_id": "2", "username": "user1", "email": "user1@example.com", "admin": False},
            {"_id": "3", "username": "system", "email": "system@internal", "admin": True}
        ]

        # Config index
        data["config"] = [
            {"_id": "1", "name": "database", "host": "db-server", "username": "dbuser", "password": "dbpass123"},
            {"_id": "2", "name": "api", "key": "c5a8ae582c7ee96a6a4bae6e4f476f2e"},
            {"_id": "3", "name": "email", "smtp_server": "mail.example.com", "username": "notifications", "password": "mailuserpass"}
        ]

        # Logs index
        data["logs"] = [
            {"_id": "1", "timestamp": "2023-01-01T12:00:00Z", "level": "INFO", "message": "System started"},
            {"_id": "2", "timestamp": "2023-01-01T12:05:00Z", "level": "WARN", "message": "High memory usage detected"},
            {"_id": "3", "timestamp": "2023-01-01T12:10:00Z", "level": "ERROR", "message": "Failed to connect to database"}
        ]

        return data

    def handle_client(self, client_socket: socket.socket, address: Tuple[str, int],
                     connection_data: Dict[str, Any]) -> None:
        """
        Handle a client connection to the Elasticsearch service

        Args:
            client_socket: Client socket object
            address: Client address tuple (ip, port)
            connection_data: Dictionary to store connection data for logging
        """
        connection_data["data"]["connection_time"] = datetime.datetime.now().isoformat()

        # Track queries for this session
        queries = []

        try:
            self.logger.info(f"Elasticsearch connection from {address[0]}:{address[1]}")

            while True:
                # Elasticsearch uses HTTP, so receive until we get a complete HTTP request
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

                # Process HTTP request to Elasticsearch
                http_request = request_data.decode('utf-8', errors='ignore')
                response, query_info = self._process_http_request(http_request)

                # Log query
                if query_info:
                    queries.append(query_info)
                    connection_data["data"]["queries"] = queries

                # Send response
                client_socket.send(response.encode())

        except Exception as e:
            self.logger.error(f"Error handling Elasticsearch client: {e}")
            connection_data["error"] = str(e)
        finally:
            client_socket.close()

    def _handle_root_request(self) -> str:
        """Handle request to root endpoint - return cluster info"""
        response_body = json.dumps({
            "name": "node-1",
            "cluster_name": self.cluster_name,
            "cluster_uuid": "Tjs9JeWWQ9G88CArGXzj8g",
            "version": {
                "number": self.server_version,
                "build_flavor": "default",
                "build_type": "tar",
                "build_hash": "f27399d",
                "build_date": "2019-03-11T18:39:09.576086Z",
                "build_snapshot": False,
                "lucene_version": "7.7.0"
            },
            "tagline": "You Know, for Search"
        })

        return self._generate_http_response(200, "OK", response_body)

    def _handle_cluster_health(self) -> str:
        """Handle cluster health request"""
        response_body = json.dumps({
            "cluster_name": self.cluster_name,
            "status": "green",  # Always report healthy
            "timed_out": False,
            "number_of_nodes": 3,
            "number_of_data_nodes": 3,
            "active_primary_shards": 5,
            "active_shards": 10,
            "relocating_shards": 0,
            "initializing_shards": 0,
            "unassigned_shards": 0,
            "delayed_unassigned_shards": 0,
            "number_of_pending_tasks": 0,
            "number_of_in_flight_fetch": 0,
            "task_max_waiting_in_queue_millis": 0,
            "active_shards_percent_as_number": 100.0
        })

        return self._generate_http_response(200, "OK", response_body)

    def _handle_cat_indices(self) -> str:
        """Handle request to list indices"""
        # Format: health status index uuid pri rep docs.count docs.deleted store.size pri.store.size
        lines = []
        for index in self.indices:
            lines.append(f"green open {index} abcdefghijk123456789 1 1 {random.randint(10, 1000)} 0 {random.randint(1, 100)}kb {random.randint(1, 50)}kb")

        return self._generate_http_response(200, "OK", "\n".join(lines))

    def _handle_search(self, index: str, body: str) -> str:
        """Handle search request on a specific index"""
        if index not in self.indices:
            return self._generate_error_response(404, f"Index '{index}' not found")

        # Log the search attempt - this could be useful for understanding attacker's goals
        self.logger.info(f"Search request on index '{index}' with body: {body}")

        # Return fake search results
        hits = []
        if index in self.fake_data:
            hits = self.fake_data[index]

        response_body = json.dumps({
            "took": random.randint(1, 50),
            "timed_out": False,
            "_shards": {
                "total": 1,
                "successful": 1,
                "skipped": 0,
                "failed": 0
            },
            "hits": {
                "total": len(hits),
                "max_score": 1.0,
                "hits": [
                    {
                        "_index": index,
                        "_type": "_doc",
                        "_id": hit["_id"],
                        "_score": 1.0,
                        "_source": {k: v for k, v in hit.items() if k != "_id"}
                    }
                    for hit in hits
                ]
            }
        })

        return self._generate_http_response(200, "OK", response_body)

    def _handle_search_all(self, body: str) -> str:
        """Handle search request across all indices"""
        # Log the search attempt
        self.logger.info(f"Search request across all indices with body: {body}")

        # Collect hits from all indices
        all_hits = []
        for index, hits in self.fake_data.items():
            for hit in hits:
                all_hits.append({
                    "_index": index,
                    "_type": "_doc",
                    "_id": hit["_id"],
                    "_score": 1.0,
                    "_source": {k: v for k, v in hit.items() if k != "_id"}
                })

        response_body = json.dumps({
            "took": random.randint(1, 50),
            "timed_out": False,
            "_shards": {
                "total": len(self.indices),
                "successful": len(self.indices),
                "skipped": 0,
                "failed": 0
            },
            "hits": {
                "total": len(all_hits),
                "max_score": 1.0,
                "hits": all_hits
            }
        })

        return self._generate_http_response(200, "OK", response_body)

    def _generate_http_response(self, status_code: int, status_text: str, body: str) -> str:
        """Generate HTTP response"""
        headers = [
            f"HTTP/1.1 {status_code} {status_text}",
            "Content-Type: application/json",
            f"Content-Length: {len(body)}",
            f"Date: {datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')}",
            "Connection: close"
        ]

        return "\r\n".join(headers) + "\r\n\r\n" + body

    def _generate_error_response(self, status_code: int, error_message: str) -> str:
        """Generate HTTP error response"""
        body = json.dumps({
            "error": {
                "root_cause": [
                    {
                        "type": "error",
                        "reason": error_message
                    }
                ],
                "type": "error",
                "reason": error_message
            },
            "status": status_code
        })

        return self._generate_http_response(status_code, error_message, body)
        
    def _process_http_request(self, http_request: str) -> Tuple[str, Dict[str, Any]]:
        """
        Process HTTP request to Elasticsearch
        
        Args:
            http_request: HTTP request string
        
        Returns:
            Tuple of (response, query_info)
        """
        # Parse HTTP request
        request_lines = http_request.split('\r\n')
        request_line = request_lines[0] if request_lines else ""
        
        # Extract method, path and HTTP version
        parts = request_line.split(' ')
        if len(parts) >= 2:
            method, path = parts[0], parts[1]
        else:
            return self._generate_error_response(400, "Bad Request"), {"error": "Invalid request format"}
        
        # Extract request body if present
        body = ""
        if "\r\n\r\n" in http_request:
            body = http_request.split("\r\n\r\n", 1)[1]
        
        # Build query info for logging
        query_info = {
            "timestamp": datetime.datetime.now().isoformat(),
            "method": method,
            "path": path,
            "body": body if body else None
        }
        
        # Route request to appropriate handler
        if path == "/":
            return self._handle_root_request(), query_info
        elif path == "/_cluster/health":
            return self._handle_cluster_health(), query_info
        elif path == "/_cat/indices":
            return self._handle_cat_indices(), query_info
        elif path.startswith("/_search"):
            return self._handle_search_all(body), query_info
        elif re.match(r'^/([^/]+)/_search$', path):
            index = re.match(r'^/([^/]+)/_search$', path).group(1)
            return self._handle_search(index, body), query_info
        else:
            return self._generate_error_response(404, f"Endpoint {path} not found"), query_info
