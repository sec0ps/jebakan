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
    def __init__(self, host: str, port: int, config: Dict[str, Any]):
        super().__init__(host, port, config, "elasticsearch")
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
        connection_data["data"]["connection_time"] = datetime.datetime.now().isoformat()
        queries = []

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
                response, query_info = self._process_http_request(http_request)

                if query_info:
                    queries.append(query_info)
                    connection_data["data"]["queries"] = queries

                client_socket.send(response.encode())

        except Exception as e:
            self.logger.error(f"Error handling Elasticsearch client: {e}")
            connection_data["error"] = str(e)
        finally:
            client_socket.close()

    def _process_http_request(self, http_request: str) -> Tuple[str, Dict[str, Any]]:
        lines = http_request.split("\r\n")
        request_line = lines[0] if lines else ""
        self.logger.debug(f"Request line: {request_line}")

        parts = request_line.split(" ")
        if len(parts) < 2:
            return self._generate_error_response(400, "Bad Request"), {"error": "Malformed request"}

        method, raw_path = parts[0], parts[1]
        path = raw_path.split('?')[0].rstrip("/")

        body = ""
        if "\r\n\r\n" in http_request:
            body = http_request.split("\r\n\r\n", 1)[1]

        query_info = {
            "timestamp": datetime.datetime.now().isoformat(),
            "method": method,
            "path": path,
            "body": body if body else None
        }

        if path == "":
            return self._handle_root_request(), query_info
        elif path == "/_cluster/health":
            return self._handle_cluster_health(), query_info
        elif path.startswith("/_cat/indices"):
            return self._handle_cat_indices(), query_info
        elif path == "/_bulk" and method == "POST":
            return self._handle_bulk(body), query_info
        elif path == "/_search" and method == "POST":
            return self._handle_search_all(body), query_info
        elif re.match(r"^/[^/]+/_search$", path) and method == "POST":
            index = path.split('/')[1]
            return self._handle_search(index, body), query_info
        elif re.match(r"^/[^/]+/_doc$", path) and method == "POST":
            index = path.split('/')[1]
            return self._handle_insert(index, body), query_info
        elif re.match(r"^/[^/]+$", path) and method == "DELETE":
            index = path.lstrip("/")
            return self._handle_delete(index), query_info
        elif re.match(r"^/[^/]+/_mapping$", path):
            index = path.split('/')[1]
            return self._handle_mapping(index), query_info
        else:
            return self._generate_error_response(404, f"Endpoint {path} not found"), query_info

    def _handle_root_request(self) -> str:
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

    def _handle_search(self, index: str, body: str) -> str:
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

    def _handle_delete(self, index: str) -> str:
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
