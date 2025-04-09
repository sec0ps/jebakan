#!/usr/bin/env python3
"""
Dashboard server for the honeypot system
"""

import os
import json
import logging
import datetime
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Dict, List, Any, Tuple, Optional
import urllib.parse

class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the honeypot dashboard"""
    
    def __init__(self, *args, **kwargs):
        # BaseHTTPRequestHandler calls do_GET inside __init__, so we need to
        # override this method and set instance variables here
        self.analytics_engine = None
        self.config = None
        self.logger = None
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        """Override to use our logger instead of printing to stderr"""
        if self.logger:
            self.logger.debug("%s - - [%s] %s" % (
                self.address_string(),
                self.log_date_time_string(),
                format % args
            ))
    
    def do_GET(self):
        """Handle GET requests"""
        try:
            # Parse URL
            parsed_url = urllib.parse.urlparse(self.path)
            path = parsed_url.path
            
            # Handle authentication if required
            if not self._authenticate():
                self._send_auth_required()
                return
            
            # Handle requests based on path
            if path == "/" or path == "/index.html":
                self._serve_dashboard()
            elif path == "/api/stats":
                self._serve_stats()
            elif path.startswith("/static/"):
                self._serve_static_file(path[8:])  # Remove /static/ prefix
            elif path.startswith("/reports/"):
                self._serve_report(path[9:])  # Remove /reports/ prefix
            elif path.startswith("/viz/"):
                self._serve_visualization(path[5:])  # Remove /viz/ prefix
            else:
                self._send_not_found()
        
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error handling dashboard request: {e}")
            self._send_error()
    
    def _authenticate(self) -> bool:
        """
        Authenticate the request
        
        Returns:
            True if authentication is successful, False otherwise
        """
        # Skip authentication if not enabled
        if not self.config or not self.config.get("dashboard", {}).get("username"):
            return True
        
        # Get Authorization header
        auth_header = self.headers.get("Authorization", "")
        
        # Check if we have a Basic Auth header
        if not auth_header.startswith("Basic "):
            return False
        
        # Decode credentials
        import base64
        try:
            credentials = base64.b64decode(auth_header[6:]).decode('utf-8')
            username, password = credentials.split(':', 1)
            
            # Check against configured credentials
            return (username == self.config["dashboard"]["username"] and 
                    password == self.config["dashboard"]["password"])
        except:
            return False
    
    def _send_auth_required(self) -> None:
        """Send authentication required response"""
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Honeypot Dashboard"')
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        
        response = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authentication Required</title>
        </head>
        <body>
            <h1>Authentication Required</h1>
            <p>Please provide valid credentials to access the dashboard.</p>
        </body>
        </html>
        """
        
        self.wfile.write(response.encode())
    
    def _serve_dashboard(self) -> None:
        """Serve the main dashboard page"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        
        # Load dashboard HTML template
        dashboard_html = self._get_dashboard_html()
        self.wfile.write(dashboard_html.encode())
    
    def _serve_stats(self) -> None:
        """Serve statistics as JSON"""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        
        if self.analytics_engine:
            stats = self.analytics_engine.get_statistics()
            self.wfile.write(json.dumps(stats).encode())
        else:
            self.wfile.write(json.dumps({"error": "Analytics engine not available"}).encode())
    
    def _serve_static_file(self, file_path: str) -> None:
        """
        Serve a static file
        
        Args:
            file_path: Path to the file relative to the static directory
        """
        # Sanitize file path to prevent directory traversal
        file_path = os.path.normpath(file_path)
        if file_path.startswith("..") or file_path.startswith("/"):
            self._send_not_found()
            return
        
        # Determine full path
        static_dir = os.path.join(os.path.dirname(__file__), "../static")
        full_path = os.path.join(static_dir, file_path)
        
        # Check if file exists
        if not os.path.isfile(full_path):
            self._send_not_found()
            return
        
        # Determine content type
        content_type = self._get_content_type(file_path)
        
        # Send file
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        
        with open(full_path, "rb") as f:
            self.wfile.write(f.read())
    
    def _serve_report(self, report_name: str) -> None:
        """
        Serve a report file
        
        Args:
            report_name: Name of the report file
        """
        # Sanitize file path to prevent directory traversal
        report_name = os.path.normpath(report_name)
        if report_name.startswith("..") or report_name.startswith("/"):
            self._send_not_found()
            return
        
        # Determine full path
        reports_dir = os.path.join("data", "reports")
        full_path = os.path.join(reports_dir, report_name)
        
        # Check if file exists
        if not os.path.isfile(full_path):
            self._send_not_found()
            return
        
        # Send file
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        
        with open(full_path, "rb") as f:
            self.wfile.write(f.read())
    
    def _serve_visualization(self, viz_name: str) -> None:
        """
        Serve a visualization image
        
        Args:
            viz_name: Name of the visualization file
        """
        # Sanitize file path to prevent directory traversal
        viz_name = os.path.normpath(viz_name)
        if viz_name.startswith("..") or viz_name.startswith("/"):
            self._send_not_found()
            return
        
        # Determine full path
        viz_dir = os.path.join("data", "reports", "visualizations")
        full_path = os.path.join(viz_dir, viz_name)
        
        # Check if file exists
        if not os.path.isfile(full_path):
            self._send_not_found()
            return
        
        # Determine content type
        content_type = self._get_content_type(viz_name)
        
        # Send file
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        
        with open(full_path, "rb") as f:
            self.wfile.write(f.read())
    
    def _send_not_found(self) -> None:
        """Send a 404 Not Found response"""
        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        
        response = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>404 Not Found</title>
        </head>
        <body>
            <h1>404 Not Found</h1>
            <p>The requested resource was not found on this server.</p>
        </body>
        </html>
        """
        
        self.wfile.write(response.encode())
    
    def _send_error(self) -> None:
        """Send a 500 Internal Server Error response"""
        self.send_response(500)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        
        response = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>500 Internal Server Error</title>
        </head>
        <body>
            <h1>500 Internal Server Error</h1>
            <p>An error occurred while processing your request.</p>
        </body>
        </html>
        """
        
        self.wfile.write(response.encode())
    
    def _get_content_type(self, file_path: str) -> str:
        """
        Get the content type for a file
        
        Args:
            file_path: Path to the file
            
        Returns:
            Content type string
        """
        extension = os.path.splitext(file_path)[1].lower()
        
        content_types = {
            ".html": "text/html",
            ".css": "text/css",
            ".js": "application/javascript",
            ".json": "application/json",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".svg": "image/svg+xml",
            ".ico": "image/x-icon"
        }
        
        return content_types.get(extension, "application/octet-stream")
    
    def _get_dashboard_html(self) -> str:
        """
        Get the HTML for the dashboard
        
        Returns:
            Dashboard HTML string
        """
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Honeypot Dashboard</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background-color: #2c3e50;
            color: white;
            padding: 1rem;
        }
        
        h1, h2, h3 {
            margin-top: 0;
        }
        
        .flex-container {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
        }
        
        .card {
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            padding: 20px;
            margin-bottom: 20px;
            flex: 1;
            min-width: 300px;
        }
        
        .card h3 {
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
            margin-bottom: 15px;
        }
        
        .stat {
            font-size: 2rem;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .stat-label {
            font-size: 0.9rem;
            color: #7f8c8d;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        table th, table td {
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        table th {
            background-color: #f2f2f2;
        }
        
        .tabs {
            display: flex;
            border-bottom: 1px solid #ddd;
            margin-bottom: 20px;
        }
        
        .tab {
            padding: 10px 20px;
            cursor: pointer;
            border: 1px solid #ddd;
            border-bottom: none;
            background-color: #f5f5f5;
            margin-right: 5px;
            border-radius: 5px 5px 0 0;
        }
        
        .tab.active {
            background-color: white;
            border-bottom: 1px solid white;
            margin-bottom: -1px;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .visualization {
            text-align: center;
            margin: 20px 0;
        }
        
        .visualization img {
            max-width: 100%;
            height: auto;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        
        .refresh-btn {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            float: right;
        }
        
        .refresh-btn:hover {
            background-color: #2980b9;
        }
        
        .alert {
            padding: 10px;
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
            border-radius: 4px;
            margin-bottom: 10px;
        }
        
        .timestamp {
            font-size: 0.8rem;
            color: #7f8c8d;
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>Honeypot Dashboard</h1>
            <p>Real-time monitoring and analytics for honeypot activity</p>
        </div>
    </header>
    
    <div class="container">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
            <h2>System Overview</h2>
            <button id="refreshBtn" class="refresh-btn">Refresh Data</button>
        </div>
        
        <div id="lastUpdated" class="timestamp">Last updated: Loading...</div>
        
        <div class="flex-container">
            <div class="card">
                <h3>Total Connections</h3>
                <div class="stat" id="totalConnections">-</div>
                <div class="stat-label">All services combined</div>
            </div>
            
            <div class="card">
                <h3>Unique IPs</h3>
                <div class="stat" id="uniqueIPs">-</div>
                <div class="stat-label">Distinct source addresses</div>
            </div>
            
            <div class="card">
                <h3>Authentication Attempts</h3>
                <div class="stat" id="authAttempts">-</div>
                <div class="stat-label">Success rate: <span id="authSuccessRate">-%</span></div>
            </div>
        </div>
        
        <div class="tabs">
            <div class="tab active" data-tab="overview">Overview</div>
            <div class="tab" data-tab="connections">Connections</div>
            <div class="tab" data-tab="authentication">Authentication</div>
            <div class="tab" data-tab="commands">Commands</div>
            <div class="tab" data-tab="attacks">Attack Patterns</div>
        </div>
        
        <div id="overview" class="tab-content active">
            <div class="flex-container">
                <div class="card">
                    <h3>Connections by Service</h3>
                    <div class="visualization">
                        <img id="connectionsChart" src="/viz/connections_by_service.png" alt="Connections by Service">
                    </div>
                </div>
                
                <div class="card">
                    <h3>Connections Over Time</h3>
                    <div class="visualization">
                        <img id="timelineChart" src="/viz/connections_over_time.png" alt="Connections Over Time">
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h3>Recent Alerts</h3>
                <div id="recentAlerts">Loading...</div>
            </div>
        </div>
        
        <div id="connections" class="tab-content">
            <div class="card">
                <h3>Top Source IPs</h3>
                <div class="visualization">
                    <img id="topIPsChart" src="/viz/top_source_ips.png" alt="Top Source IPs">
                </div>
                <table id="topIPsTable">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Connection Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td colspan="2">Loading...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
        
        <div id="authentication" class="tab-content">
            <div class="card">
                <h3>Authentication Results by Service</h3>
                <div class="visualization">
                    <img id="authStatsChart" src="/viz/auth_stats.png" alt="Authentication Statistics">
                </div>
            </div>
            
            <div class="flex-container">
                <div class="card">
                    <h3>Top Usernames</h3>
                    <table id="topUsernamesTable">
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>Attempts</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td colspan="2">Loading...</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                
                <div class="card">
                    <h3>Top Passwords</h3>
                    <table id="topPasswordsTable">
                        <thead>
                            <tr>
                                <th>Password</th>
                                <th>Attempts</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td colspan="2">Loading...</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <div id="commands" class="tab-content">
            <div class="card">
                <h3>Top Commands by Service</h3>
                <div id="topCommands">Loading...</div>
            </div>
        </div>
        
        <div id="attacks" class="tab-content">
            <div class="card">
                <h3>Recent Attack Patterns</h3>
                <div id="attackPatterns">Loading...</div>
            </div>
        </div>
    </div>
    
    <script>
        // Tab functionality
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                
                tab.classList.add('active');
                document.getElementById(tab.getAttribute('data-tab')).classList.add('active');
            });
        });
        
        // Refresh data
        document.getElementById('refreshBtn').addEventListener('click', () => {
            fetchData();
        });
        
        // Fetch data from API
        function fetchData() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    updateDashboard(data);
                })
                .catch(error => {
                    console.error('Error fetching data:', error);
                });
        }
        
        // Update dashboard with data
        function updateDashboard(data) {
            // Update last updated timestamp
            document.getElementById('lastUpdated').textContent = 'Last updated: ' + new Date().toLocaleString();
            
            // Update main stats
            document.getElementById('totalConnections').textContent = data.total_connections || 0;
            
            if (data.top_source_ips) {
                document.getElementById('uniqueIPs').textContent = data.top_source_ips.length;
            }
            
            // Calculate authentication attempts and success rate
            let totalAttempts = 0;
            let successfulAttempts = 0;
            
            if (data.authentication_stats) {
                for (const service in data.authentication_stats) {
                    totalAttempts += data.authentication_stats[service].success + data.authentication_stats[service].failure;
                    successfulAttempts += data.authentication_stats[service].success;
                }
            }
            
            document.getElementById('authAttempts').textContent = totalAttempts;
            
            if (totalAttempts > 0) {
                const successRate = (successfulAttempts / totalAttempts * 100).toFixed(1);
                document.getElementById('authSuccessRate').textContent = successRate + '%';
            } else {
                document.getElementById('authSuccessRate').textContent = '0%';
            }
            
            // Update recent alerts
            if (data.recent_alerts && data.recent_alerts.length > 0) {
                const alertsHtml = data.recent_alerts.map(alert => {
                    return `
                        <div class="alert">
                            <strong>${alert.type}</strong> from ${alert.source_ip || 'unknown'}
                            <div class="timestamp">${new Date(alert.timestamp).toLocaleString()}</div>
                        </div>
                    `;
                }).join('');
                
                document.getElementById('recentAlerts').innerHTML = alertsHtml;
            } else {
                document.getElementById('recentAlerts').innerHTML = '<p>No recent alerts</p>';
            }
            
            // Update top IPs table
            if (data.top_source_ips && data.top_source_ips.length > 0) {
                const ipsHtml = data.top_source_ips.map(ip => {
                    return `
                        <tr>
                            <td>${ip.ip}</td>
                            <td>${ip.count}</td>
                        </tr>
                    `;
                }).join('');
                
                document.getElementById('topIPsTable').querySelector('tbody').innerHTML = ipsHtml;
            }
            
            // Update top usernames table
            if (data.top_usernames && data.top_usernames.length > 0) {
                const usernamesHtml = data.top_usernames.map(user => {
                    return `
                        <tr>
                            <td>${user.username}</td>
                            <td>${user.count}</td>
                        </tr>
                    `;
                }).join('');
                
                document.getElementById('topUsernamesTable').querySelector('tbody').innerHTML = usernamesHtml;
            }
            
            // Update top passwords table
            if (data.top_passwords && data.top_passwords.length > 0) {
                const passwordsHtml = data.top_passwords.map(pass => {
                    return `
                        <tr>
                            <td>${pass.password}</td>
                            <td>${pass.count}</td>
                        </tr>
                    `;
                }).join('');
                
                document.getElementById('topPasswordsTable').querySelector('tbody').innerHTML = passwordsHtml;
            }
            
            // Refresh visualizations
            const timestamp = new Date().getTime();
            document.getElementById('connectionsChart').src = `/viz/connections_by_service.png?t=${timestamp}`;
            document.getElementById('timelineChart').src = `/viz/connections_over_time.png?t=${timestamp}`;
            document.getElementById('topIPsChart').src = `/viz/top_source_ips.png?t=${timestamp}`;
            document.getElementById('authStatsChart').src = `/viz/auth_stats.png?t=${timestamp}`;
        }
        
        // Initial data fetch
        fetchData();
        
        // Auto-refresh every 60 seconds
        setInterval(fetchData, 60000);
    </script>
</body>
</html>
"""


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread"""
    pass


class DashboardServer:
    """Dashboard server for the honeypot system"""
    
    def __init__(self, config: Dict[str, Any], analytics_engine=None):
        """
        Initialize the dashboard server
        
        Args:
            config: Global configuration dictionary
            analytics_engine: Analytics engine instance
        """
        self.config = config
        self.analytics_engine = analytics_engine
        self.logger = logging.getLogger("honeypot.dashboard")
        self.running = False
        self.server = None
        
        # Create static directory if it doesn't exist
        static_dir = os.path.join(os.path.dirname(__file__), "../static")
        os.makedirs(static_dir, exist_ok=True)
    
    def start(self) -> None:
        """Start the dashboard server"""
        try:
            # Configure server
            host = "0.0.0.0"
            port = self.config["dashboard"]["port"]
            
            # Create custom handler with access to config and analytics engine
            handler = DashboardHandler
            handler.config = self.config
            handler.analytics_engine = self.analytics_engine
            handler.logger = self.logger
            
            # Create and start server
            self.server = ThreadedHTTPServer((host, port), handler)
            self.running = True
            
            self.logger.info(f"Dashboard server started on http://{host}:{port}")
            
            # Run server in current thread
            while self.running:
                self.server.handle_request()
                
        except Exception as e:
            self.logger.error(f"Error starting dashboard server: {e}")
        finally:
            if self.server:
                self.server.server_close()
    
    def stop(self) -> None:
        """Stop the dashboard server"""
        self.running = False
        if self.server:
            self.server.server_close()
        self.logger.info("Dashboard server stopped")
