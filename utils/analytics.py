#!/usr/bin/env python3
"""
Analytics engine for the honeypot system
"""

import os
import json
import time
import sqlite3
import logging
import datetime
import ipaddress
import threading
import re
from typing import Dict, List, Any, Tuple, Optional
from collections import Counter, defaultdict
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend

class AnalyticsEngine:
    """Analytics engine for processing honeypot data"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the analytics engine
        
        Args:
            config: Global configuration dictionary
        """
        self.config = config
        self.logger = logging.getLogger("honeypot.analytics")
        self.running = False
        
        # Set up database
        self.db_path = self.config["analytics"]["database"]["path"]
        self.db_lock = threading.Lock()
        
        # Ensure database directory exists
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # Initialize database
        self._init_database()
        
        # Statistics cache
        self.stats_cache = {}
        self.stats_cache_time = 0
        self.stats_cache_lifetime = 60  # seconds
    
    def start(self) -> None:
        """Start the analytics engine"""
        self.running = True
        self.logger.info("Analytics engine started")
        
        try:
            while self.running:
                try:
                    # Process log files and update database
                    self._process_logs()
                    
                    # Generate analytics and reports
                    self._generate_reports()
                    
                    # Sleep for the configured interval
                    time.sleep(self.config["analytics"]["analysis_interval"])
                    
                except Exception as e:
                    self.logger.error(f"Error in analytics processing: {e}")
                    time.sleep(60)  # Wait a minute before trying again
                
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self) -> None:
        """Stop the analytics engine"""
        self.running = False
        self.logger.info("Analytics engine stopped")
    
    def _init_database(self) -> None:
        """Initialize the SQLite database"""
        try:
            with self.db_lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Create tables if they don't exist
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS connections (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        source_ip TEXT NOT NULL,
                        source_port INTEGER NOT NULL,
                        service TEXT NOT NULL,
                        duration REAL,
                        auth_success INTEGER,
                        username TEXT,
                        password TEXT,
                        data TEXT
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS commands (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        connection_id INTEGER NOT NULL,
                        timestamp TEXT NOT NULL,
                        command TEXT NOT NULL,
                        service TEXT NOT NULL,
                        FOREIGN KEY (connection_id) REFERENCES connections (id)
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        alert_type TEXT NOT NULL,
                        source_ip TEXT,
                        service TEXT,
                        details TEXT
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ip_info (
                        ip TEXT PRIMARY KEY,
                        country TEXT,
                        city TEXT,
                        isp TEXT,
                        last_updated TEXT,
                        is_known_bad INTEGER DEFAULT 0
                    )
                ''')
                
                # Create indexes for performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_connections_ip ON connections (source_ip)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_connections_service ON connections (service)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_connections_timestamp ON connections (timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_commands_connection ON commands (connection_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts (source_ip)')
                
                conn.commit()
                conn.close()
                
                self.logger.info("Database initialized")
                
        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")
    
    def _process_logs(self) -> None:
        """Process log files and update the database"""
        log_dir = self.config["logging"]["dir"]
        if not os.path.exists(log_dir):
            return
        
        # Process connection logs for each service
        services = ["ssh", "http", "ftp", "telnet"]
        
        for service in services:
            log_file = os.path.join(log_dir, f"{service}_connections.json")
            if not os.path.exists(log_file):
                continue
            
            try:
                # Create a temporary file for processed entries
                processed_file = log_file + ".processed"
                unprocessed_entries = []
                
                # Check if the file is being written to
                try:
                    with open(log_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                try:
                                    entry = json.loads(line)
                                    unprocessed_entries.append(entry)
                                except json.JSONDecodeError:
                                    # Skip invalid JSON lines
                                    pass
                    
                    # Process each entry
                    with self.db_lock:
                        conn = sqlite3.connect(self.db_path)
                        cursor = conn.cursor()
                        
                        for entry in unprocessed_entries:
                            # Insert connection data
                            auth_success = 0
                            username = None
                            password = None
                            
                            # Extract authentication data if available
                            if "data" in entry:
                                if "auth_result" in entry["data"]:
                                    auth_success = 1 if entry["data"]["auth_result"] == "success" else 0
                                
                                if "auth_attempts" in entry["data"] and entry["data"]["auth_attempts"]:
                                    # Use the last authentication attempt
                                    last_attempt = entry["data"]["auth_attempts"][-1]
                                    username = last_attempt.get("username")
                                    password = last_attempt.get("password")
                            
                            # Serialize data for storage
                            data_json = json.dumps(entry.get("data", {}))
                            
                            # Insert connection record
                            cursor.execute('''
                                INSERT INTO connections 
                                (timestamp, source_ip, source_port, service, duration, auth_success, username, password, data)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ''', (
                                entry.get("timestamp"),
                                entry.get("source_ip"),
                                entry.get("source_port"),
                                entry.get("service"),
                                entry.get("duration"),
                                auth_success,
                                username,
                                password,
                                data_json
                            ))
                            
                            connection_id = cursor.lastrowid
                            
                            # Insert command data if available
                            if "data" in entry and "commands" in entry["data"]:
                                for cmd in entry["data"]["commands"]:
                                    cursor.execute('''
                                        INSERT INTO commands 
                                        (connection_id, timestamp, command, service)
                                        VALUES (?, ?, ?, ?)
                                    ''', (
                                        connection_id,
                                        cmd.get("timestamp"),
                                        cmd.get("command"),
                                        entry.get("service")
                                    ))
                        
                        conn.commit()
                        conn.close()
                    
                    # Move processed entries to the processed file
                    with open(processed_file, 'a') as f:
                        for entry in unprocessed_entries:
                            f.write(json.dumps(entry) + "\n")
                    
                    # Truncate the original file
                    with open(log_file, 'w') as f:
                        pass
                    
                except Exception as e:
                    self.logger.error(f"Error processing {service} log file: {e}")
                
            except Exception as e:
                self.logger.error(f"Error accessing {service} log file: {e}")
        
        # Process alerts
        alerts_file = os.path.join(log_dir, "alerts.json")
        if os.path.exists(alerts_file):
            try:
                with open(alerts_file, 'r') as f:
                    alerts = []
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                alert = json.loads(line)
                                alerts.append(alert)
                            except json.JSONDecodeError:
                                # Skip invalid JSON lines
                                pass
                
                # Process alerts
                if alerts:
                    with self.db_lock:
                        conn = sqlite3.connect(self.db_path)
                        cursor = conn.cursor()
                        
                        for alert in alerts:
                            details = {k: v for k, v in alert.items() if k not in ["timestamp", "alert_type", "source_ip", "service"]}
                            details_json = json.dumps(details)
                            
                            cursor.execute('''
                                INSERT INTO alerts 
                                (timestamp, alert_type, source_ip, service, details)
                                VALUES (?, ?, ?, ?, ?)
                            ''', (
                                alert.get("timestamp"),
                                alert.get("alert_type"),
                                alert.get("source_ip"),
                                alert.get("service"),
                                details_json
                            ))
                        
                        conn.commit()
                        conn.close()
                    
                    # Clear the alerts file
                    with open(alerts_file, 'w') as f:
                        pass
                    
            except Exception as e:
                self.logger.error(f"Error processing alerts file: {e}")
    
    def _generate_reports(self) -> None:
        """Generate analytics reports"""
        try:
            # Create reports directory
            reports_dir = os.path.join("data", "reports")
            os.makedirs(reports_dir, exist_ok=True)
            
            # Generate various reports
            self._generate_connection_report(reports_dir)
            self._generate_authentication_report(reports_dir)
            self._generate_command_report(reports_dir)
            self._generate_attack_patterns_report(reports_dir)
            self._generate_visualization(reports_dir)
            
            self.logger.info("Generated analytics reports")
            
        except Exception as e:
            self.logger.error(f"Error generating reports: {e}")
    
    def _generate_connection_report(self, reports_dir: str) -> None:
        """
        Generate a report of connection statistics
        
        Args:
            reports_dir: Directory to save the report
        """
        with self.db_lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get total connections by service
            cursor.execute('''
                SELECT service, COUNT(*) as count 
                FROM connections 
                GROUP BY service
            ''')
            service_counts = {row["service"]: row["count"] for row in cursor.fetchall()}
            
            # Get top 10 source IPs
            cursor.execute('''
                SELECT source_ip, COUNT(*) as count 
                FROM connections 
                GROUP BY source_ip 
                ORDER BY count DESC 
                LIMIT 10
            ''')
            top_ips = [{
                "ip": row["source_ip"],
                "count": row["count"]
            } for row in cursor.fetchall()]
            
            # Get connections per day for the last 7 days
            cursor.execute('''
                SELECT date(timestamp) as date, COUNT(*) as count 
                FROM connections 
                WHERE timestamp >= date('now', '-7 days')
                GROUP BY date 
                ORDER BY date
            ''')
            daily_counts = {row["date"]: row["count"] for row in cursor.fetchall()}
            
            conn.close()
            
            # Create report
            report = {
                "generated_at": datetime.datetime.now().isoformat(),
                "total_connections": sum(service_counts.values()),
                "connections_by_service": service_counts,
                "top_source_ips": top_ips,
                "connections_per_day": daily_counts
            }
            
            # Save report
            report_file = os.path.join(reports_dir, "connection_report.json")
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=4)
    
    def _generate_authentication_report(self, reports_dir: str) -> None:
        """
        Generate a report of authentication statistics
        
        Args:
            reports_dir: Directory to save the report
        """
        with self.db_lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get authentication success/failure counts
            cursor.execute('''
                SELECT service, auth_success, COUNT(*) as count 
                FROM connections 
                WHERE username IS NOT NULL
                GROUP BY service, auth_success
            ''')
            
            auth_stats = {}
            for row in cursor.fetchall():
                service = row["service"]
                if service not in auth_stats:
                    auth_stats[service] = {"success": 0, "failure": 0}
                
                if row["auth_success"] == 1:
                    auth_stats[service]["success"] += row["count"]
                else:
                    auth_stats[service]["failure"] += row["count"]
            
            # Get top usernames
            cursor.execute('''
                SELECT username, COUNT(*) as count 
                FROM connections 
                WHERE username IS NOT NULL
                GROUP BY username 
                ORDER BY count DESC 
                LIMIT 15
            ''')
            top_usernames = [{
                "username": row["username"],
                "count": row["count"]
            } for row in cursor.fetchall()]
            
            # Get top passwords
            cursor.execute('''
                SELECT password, COUNT(*) as count 
                FROM connections 
                WHERE password IS NOT NULL
                GROUP BY password 
                ORDER BY count DESC 
                LIMIT 15
            ''')
            top_passwords = [{
                "password": row["password"],
                "count": row["count"]
            } for row in cursor.fetchall()]
            
            # Get top username/password combinations
            cursor.execute('''
                SELECT username, password, COUNT(*) as count 
                FROM connections 
                WHERE username IS NOT NULL AND password IS NOT NULL
                GROUP BY username, password 
                ORDER BY count DESC 
                LIMIT 15
            ''')
            top_combinations = [{
                "username": row["username"],
                "password": row["password"],
                "count": row["count"]
            } for row in cursor.fetchall()]
            
            conn.close()
            
            # Create report
            report = {
                "generated_at": datetime.datetime.now().isoformat(),
                "authentication_stats": auth_stats,
                "top_usernames": top_usernames,
                "top_passwords": top_passwords,
                "top_combinations": top_combinations
            }
            
            # Save report
            report_file = os.path.join(reports_dir, "authentication_report.json")
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=4)
    
    def _generate_command_report(self, reports_dir: str) -> None:
        """
        Generate a report of command statistics
        
        Args:
            reports_dir: Directory to save the report
        """
        with self.db_lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get top commands by service
            cursor.execute('''
                SELECT service, command, COUNT(*) as count 
                FROM commands 
                GROUP BY service, command 
                ORDER BY count DESC
            ''')
            
            commands_by_service = {}
            for row in cursor.fetchall():
                service = row["service"]
                if service not in commands_by_service:
                    commands_by_service[service] = []
                
                if len(commands_by_service[service]) < 15:
                    commands_by_service[service].append({
                        "command": row["command"],
                        "count": row["count"]
                    })
            
            # Detect command patterns
            cursor.execute('''
                SELECT c.connection_id, c.command, c.service
                FROM commands c
                ORDER BY c.connection_id, c.id
            ''')
            
            command_sequences = defaultdict(list)
            for row in cursor.fetchall():
                command_sequences[row["connection_id"]].append(row["command"])
            
            # Analyze command sequences
            sequence_patterns = []
            for conn_id, commands in command_sequences.items():
                if len(commands) > 2:
                    # Check for reconnaissance patterns
                    recon_commands = ['ls', 'pwd', 'whoami', 'id', 'uname', 'ps', 'netstat', 'ifconfig']
                    recon_count = sum(1 for cmd in commands if any(cmd.startswith(rc) for rc in recon_commands))
                    
                    # Check for exploitation patterns
                    exploit_indicators = ['wget', 'curl', 'gcc', 'nc', 'netcat', 'python', 'perl', 'bash', 'chmod']
                    exploit_count = sum(1 for cmd in commands if any(cmd.startswith(ei) for ei in exploit_indicators))
                    
                    # Check for lateral movement patterns
                    lateral_indicators = ['ssh', 'scp', 'ftp', 'nc']
                    lateral_count = sum(1 for cmd in commands if any(cmd.startswith(li) for li in lateral_indicators))
                    
                    if recon_count > 2 or exploit_count > 0 or lateral_count > 0:
                        cursor.execute('SELECT source_ip FROM connections WHERE id = ?', (conn_id,))
                        result = cursor.fetchone()
                        source_ip = result["source_ip"] if result else "unknown"
                        
                        sequence_patterns.append({
                            "connection_id": conn_id,
                            "source_ip": source_ip,
                            "commands": commands,
                            "recon_count": recon_count,
                            "exploit_count": exploit_count,
                            "lateral_count": lateral_count
                        })
            
            conn.close()
            
            # Create report
            report = {
                "generated_at": datetime.datetime.now().isoformat(),
                "top_commands_by_service": commands_by_service,
                "command_sequence_patterns": sequence_patterns[:15]  # Limit to top 15
            }
            
            # Save report
            report_file = os.path.join(reports_dir, "command_report.json")
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=4)
    
    def _generate_attack_patterns_report(self, reports_dir: str) -> None:
        """
        Generate a report of attack patterns
        
        Args:
            reports_dir: Directory to save the report
        """
        with self.db_lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get alert statistics
            cursor.execute('''
                SELECT alert_type, COUNT(*) as count 
                FROM alerts 
                GROUP BY alert_type
            ''')
            alert_counts = {row["alert_type"]: row["count"] for row in cursor.fetchall()}
            
            # Get top IPs with alerts
            cursor.execute('''
                SELECT source_ip, COUNT(*) as count 
                FROM alerts 
                WHERE source_ip IS NOT NULL
                GROUP BY source_ip 
                ORDER BY count DESC 
                LIMIT 10
            ''')
            top_alert_ips = [{
                "ip": row["source_ip"],
                "count": row["count"]
            } for row in cursor.fetchall()]
            
            # Get HTTP attack patterns
            cursor.execute('''
                SELECT data FROM connections 
                WHERE service = 'http' AND json_extract(data, '$.suspicious') = 1
                ORDER BY timestamp DESC
                LIMIT 100
            ''')
            
            http_attacks = []
            for row in cursor.fetchall():
                try:
                    data = json.loads(row["data"])
                    attack_info = {
                        "path": data.get("path", ""),
                        "method": data.get("method", ""),
                        "matched_patterns": data.get("matched_patterns", [])
                    }
                    
                    # Add user agent if available
                    if "user_agent" in data:
                        attack_info["user_agent"] = data["user_agent"]
                    
                    # Add source IP
                    cursor.execute('SELECT source_ip FROM connections WHERE data = ?', (row["data"],))
                    source_result = cursor.fetchone()
                    if source_result:
                        attack_info["source_ip"] = source_result["source_ip"]
                    
                    http_attacks.append(attack_info)
                except json.JSONDecodeError:
                    pass
            
            # Get malware download attempts
            cursor.execute('''
                SELECT c.source_ip, cmd.command, cmd.timestamp
                FROM commands cmd
                JOIN connections c ON cmd.connection_id = c.id
                WHERE (cmd.command LIKE '%wget%' OR cmd.command LIKE '%curl%')
                    AND (cmd.command LIKE '%.sh%' OR cmd.command LIKE '%.pl%' 
                         OR cmd.command LIKE '%.py%' OR cmd.command LIKE '%.bin%'
                         OR cmd.command LIKE '%.elf%' OR cmd.command LIKE '%.malware%')
                ORDER BY cmd.timestamp DESC
                LIMIT 20
            ''')
            
            malware_downloads = [{
                "source_ip": row["source_ip"],
                "command": row["command"],
                "timestamp": row["timestamp"]
            } for row in cursor.fetchall()]
            
            conn.close()
            
            # Create report
            report = {
                "generated_at": datetime.datetime.now().isoformat(),
                "alert_statistics": alert_counts,
                "top_alerted_ips": top_alert_ips,
                "http_attack_patterns": http_attacks[:20],  # Limit to top 20
                "malware_download_attempts": malware_downloads
            }
            
            # Save report
            report_file = os.path.join(reports_dir, "attack_patterns_report.json")
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=4)
    
    def _generate_visualization(self, reports_dir: str) -> None:
        """
        Generate visualizations of honeypot data
        
        Args:
            reports_dir: Directory to save the visualizations
        """
        # Create visualizations directory
        viz_dir = os.path.join(reports_dir, "visualizations")
        os.makedirs(viz_dir, exist_ok=True)
        
        # Get statistics from database
        stats = self.get_statistics()
        
        # Generate connection by service pie chart
        if "connections_by_service" in stats:
            plt.figure(figsize=(10, 6))
            labels = list(stats["connections_by_service"].keys())
            sizes = list(stats["connections_by_service"].values())
            
            plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
            plt.axis('equal')
            plt.title('Connections by Service')
            plt.tight_layout()
            plt.savefig(os.path.join(viz_dir, "connections_by_service.png"))
            plt.close()
        
        # Generate connections over time line chart
        if "connections_over_time" in stats:
            plt.figure(figsize=(12, 6))
            dates = list(stats["connections_over_time"].keys())
            counts = list(stats["connections_over_time"].values())
            
            plt.plot(dates, counts, marker='o')
            plt.title('Connections Over Time')
            plt.xlabel('Date')
            plt.ylabel('Connection Count')
            plt.xticks(rotation=45)
            plt.grid(True, linestyle='--', alpha=0.7)
            plt.tight_layout()
            plt.savefig(os.path.join(viz_dir, "connections_over_time.png"))
            plt.close()
        
        # Generate top source IPs bar chart
        if "top_source_ips" in stats:
            plt.figure(figsize=(12, 6))
            ips = [entry["ip"] for entry in stats["top_source_ips"]]
            counts = [entry["count"] for entry in stats["top_source_ips"]]
            
            plt.barh(ips, counts)
            plt.title('Top Source IPs')
            plt.xlabel('Connection Count')
            plt.ylabel('Source IP')
            plt.grid(True, linestyle='--', alpha=0.7)
            plt.tight_layout()
            plt.savefig(os.path.join(viz_dir, "top_source_ips.png"))
            plt.close()
        
        # Generate authentication statistics bar chart
        if "authentication_stats" in stats:
            plt.figure(figsize=(10, 6))
            services = list(stats["authentication_stats"].keys())
            success_counts = [stats["authentication_stats"][service]["success"] for service in services]
            failure_counts = [stats["authentication_stats"][service]["failure"] for service in services]
            
            x = range(len(services))
            width = 0.35
            
            plt.bar([i - width/2 for i in x], success_counts, width, label='Success')
            plt.bar([i + width/2 for i in x], failure_counts, width, label='Failure')
            
            plt.title('Authentication Results by Service')
            plt.xlabel('Service')
            plt.ylabel('Count')
            plt.xticks(x, services)
            plt.legend()
            plt.grid(True, linestyle='--', alpha=0.7)
            plt.tight_layout()
            plt.savefig(os.path.join(viz_dir, "auth_stats.png"))
            plt.close()
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics from the database
        
        Returns:
            Dictionary with statistics
        """
        # Check if cache is valid
        current_time = time.time()
        if self.stats_cache and (current_time - self.stats_cache_time) < self.stats_cache_lifetime:
            return self.stats_cache
        
        # If cache is invalid, regenerate statistics
        stats = {}
        
        try:
            with self.db_lock:
                conn = sqlite3.connect(self.db_path)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Get total connection count
                cursor.execute('SELECT COUNT(*) as count FROM connections')
                result = cursor.fetchone()
                stats["total_connections"] = result["count"] if result else 0
                
                # Get connections by service
                cursor.execute('''
                    SELECT service, COUNT(*) as count 
                    FROM connections 
                    GROUP BY service
                ''')
                stats["connections_by_service"] = {row["service"]: row["count"] for row in cursor.fetchall()}
                
                # Get connections over time (last 7 days)
                cursor.execute('''
                    SELECT date(timestamp) as date, COUNT(*) as count 
                    FROM connections 
                    WHERE timestamp >= date('now', '-7 days')
                    GROUP BY date 
                    ORDER BY date
                ''')
                stats["connections_over_time"] = {row["date"]: row["count"] for row in cursor.fetchall()}
                
                # Get top source IPs
                cursor.execute('''
                    SELECT source_ip, COUNT(*) as count 
                    FROM connections 
                    GROUP BY source_ip 
                    ORDER BY count DESC 
                    LIMIT 10
                ''')
                stats["top_source_ips"] = [{
                    "ip": row["source_ip"],
                    "count": row["count"]
                } for row in cursor.fetchall()]
                
                # Get authentication statistics
                cursor.execute('''
                    SELECT service, auth_success, COUNT(*) as count 
                    FROM connections 
                    WHERE username IS NOT NULL
                    GROUP BY service, auth_success
                ''')
                
                auth_stats = {}
                for row in cursor.fetchall():
                    service = row["service"]
                    if service not in auth_stats:
                        auth_stats[service] = {"success": 0, "failure": 0}
                    
                    if row["auth_success"] == 1:
                        auth_stats[service]["success"] += row["count"]
                    else:
                        auth_stats[service]["failure"] += row["count"]
                
                stats["authentication_stats"] = auth_stats
                
                # Get top usernames and passwords
                cursor.execute('''
                    SELECT username, COUNT(*) as count 
                    FROM connections 
                    WHERE username IS NOT NULL
                    GROUP BY username 
                    ORDER BY count DESC 
                    LIMIT 10
                ''')
                stats["top_usernames"] = [{
                    "username": row["username"],
                    "count": row["count"]
                } for row in cursor.fetchall()]
                
                cursor.execute('''
                    SELECT password, COUNT(*) as count 
                    FROM connections 
                    WHERE password IS NOT NULL
                    GROUP BY password 
                    ORDER BY count DESC 
                    LIMIT 10
                ''')
                stats["top_passwords"] = [{
                    "password": row["password"],
                    "count": row["count"]
                } for row in cursor.fetchall()]
                
                # Get recent alerts
                cursor.execute('''
                    SELECT alert_type, source_ip, timestamp
                    FROM alerts
                    ORDER BY timestamp DESC
                    LIMIT 10
                ''')
                stats["recent_alerts"] = [{
                    "type": row["alert_type"],
                    "source_ip": row["source_ip"],
                    "timestamp": row["timestamp"]
                } for row in cursor.fetchall()]
                
                conn.close()
            
            # Update cache
            self.stats_cache = stats
            self.stats_cache_time = current_time
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return {}
