#!/usr/bin/env python3
"""
Alert manager for the honeypot system
"""

import os
import json
import logging
import datetime
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Any, Tuple, Optional

class AlertManager:
    """Alert manager for handling and dispatching honeypot alerts"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the alert manager
        
        Args:
            config: Global configuration dictionary
        """
        self.config = config
        self.logger = logging.getLogger("honeypot.alerts")
        
        # Track alert timestamps by IP to avoid flooding
        self.alert_history = {}
        
        # Set alert cooldown period (seconds)
        self.alert_cooldown = 300  # 5 minutes
    
    def trigger_alert(self, alert_type: str, source_ip: str = None, service: str = None,
                     details: Dict[str, Any] = None) -> bool:
        """
        Trigger an alert
        
        Args:
            alert_type: Type of alert
            source_ip: Source IP address (if applicable)
            service: Service name (if applicable)
            details: Additional alert details
            
        Returns:
            True if alert was triggered, False otherwise
        """
        # Check if we should throttle alerts for this IP
        if source_ip:
            current_time = datetime.datetime.now().timestamp()
            
            # Check if we've alerted about this IP recently
            if source_ip in self.alert_history:
                last_alert_time = self.alert_history[source_ip].get(alert_type)
                if last_alert_time and (current_time - last_alert_time) < self.alert_cooldown:
                    # Skip alert due to cooldown
                    return False
            
            # Update alert history
            if source_ip not in self.alert_history:
                self.alert_history[source_ip] = {}
            
            self.alert_history[source_ip][alert_type] = current_time
        
        # Create alert data
        alert_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "alert_type": alert_type,
            "source_ip": source_ip,
            "service": service
        }
        
        # Add additional details if provided
        if details:
            for key, value in details.items():
                if key not in alert_data:
                    alert_data[key] = value
        
        # Log the alert
        self._log_alert(alert_data)
        
        # Dispatch alert based on configured channels
        self._dispatch_alert(alert_data)
        
        return True
    
    def _log_alert(self, alert_data: Dict[str, Any]) -> None:
        """
        Log an alert to file
        
        Args:
            alert_data: Alert data dictionary
        """
        try:
            log_dir = self.config["logging"]["dir"]
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            alert_file = os.path.join(log_dir, "alerts.json")
            
            with open(alert_file, "a") as f:
                f.write(json.dumps(alert_data) + "\n")
                
            self.logger.info(f"Alert logged: {alert_data['alert_type']} from {alert_data.get('source_ip', 'unknown')}")
            
        except Exception as e:
            self.logger.error(f"Error logging alert: {e}")
    
    def _dispatch_alert(self, alert_data: Dict[str, Any]) -> None:
        """
        Dispatch an alert to configured channels
        
        Args:
            alert_data: Alert data dictionary
        """
        # Send email alert if enabled
        if self.config["alerts"]["email"]["enabled"]:
            self._send_email_alert(alert_data)
        
        # Send webhook alert if enabled
        if self.config["alerts"]["webhook"]["enabled"]:
            self._send_webhook_alert(alert_data)
    
    def _send_email_alert(self, alert_data: Dict[str, Any]) -> None:
        """
        Send an email alert
        
        Args:
            alert_data: Alert data dictionary
        """
        try:
            email_config = self.config["alerts"]["email"]
            
            # Create email message
            msg = MIMEMultipart()
            msg["From"] = email_config["from_address"]
            msg["To"] = ", ".join(email_config["to_addresses"])
            msg["Subject"] = f"Honeypot Alert: {alert_data['alert_type']}"
            
            # Build email body
            body = f"Honeypot Alert\n\n"
            body += f"Type: {alert_data['alert_type']}\n"
            body += f"Time: {alert_data['timestamp']}\n"
            
            if alert_data.get("source_ip"):
                body += f"Source IP: {alert_data['source_ip']}\n"
            
            if alert_data.get("service"):
                body += f"Service: {alert_data['service']}\n"
            
            # Add additional details
            body += "\nAdditional Details:\n"
            for key, value in alert_data.items():
                if key not in ["timestamp", "alert_type", "source_ip", "service"]:
                    body += f"{key}: {value}\n"
            
            msg.attach(MIMEText(body, "plain"))
            
            # Connect to SMTP server and send email
            server = smtplib.SMTP(email_config["smtp_server"], email_config["smtp_port"])
            
            if email_config["use_tls"]:
                server.starttls()
            
            if email_config["username"] and email_config["password"]:
                server.login(email_config["username"], email_config["password"])
            
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"Email alert sent: {alert_data['alert_type']}")
            
        except Exception as e:
            self.logger.error(f"Error sending email alert: {e}")
    
    def _send_webhook_alert(self, alert_data: Dict[str, Any]) -> None:
        """
        Send a webhook alert
        
        Args:
            alert_data: Alert data dictionary
        """
        try:
            webhook_url = self.config["alerts"]["webhook"]["url"]
            
            # Send webhook request
            response = requests.post(
                webhook_url,
                json=alert_data,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code >= 200 and response.status_code < 300:
                self.logger.info(f"Webhook alert sent: {alert_data['alert_type']}")
            else:
                self.logger.error(f"Error sending webhook alert: HTTP {response.status_code}")
            
        except Exception as e:
            self.logger.error(f"Error sending webhook alert: {e}")
