# Jebakan: Python Honeypot System (Community Edition)

Jebakan is a modular honeypot system written in Python for cybersecurity research, threat intelligence gathering, and network security monitoring.

## Overview

This honeypot system creates convincing decoy services to attract and study attackers without exposing your real systems. It's designed to be highly configurable, easy to deploy, and capable of detailed logging and analysis of attack patterns.

## Features

### Core Functionality
- **Modular Architecture**: Easily add or customize service emulators
- **Multiple Service Emulation**: SSH, HTTP, FTP, Telnet, MySQL, MSSQL, Redis, Elasticsearch, Docker API, RDP, VNC
- **Flexible Configuration**: JSON-based configuration with command-line overrides
- **Interaction Levels**: Configure low, medium, or high interaction for different honeypot scenarios
- **Comprehensive Logging**: Detailed logs of all interactions for later analysis

### Security Features
- **Isolated Environment**: Designed to safely contain and monitor attacker activities
- **Resource Limiting**: Prevent DoS attacks with connection limits and timeouts
- **Port Availability Checking**: Automatically checks if ports are available before starting services
- **Secure Defaults**: All emulated services run with the minimum required privileges

### Analysis and Monitoring
- **Real-time Alerts**: Configurable alerts for suspicious activities
- **Attack Pattern Recognition**: Identifies common attack patterns and tools
- **Dashboard**: Web-based dashboard for monitoring honeypot activity
- **Analytics Engine**: Process and visualize attack data
- **JSON Log Format**: Easy integration with existing SIEM and analysis tools

### Deception Techniques
- **Configurable Banners**: Customize service banners to mimic different systems
- **Breadcrumbs**: Plant convincing fake credentials and sensitive information
- **Realistic Responses**: Service emulators provide realistic feedback to common commands
- **System Information Spoofing**: Configure OS and service versions to target specific threats

## Installation

### Prerequisites
- Python 3.8+
- Required Python packages:
  - paramiko
  - colorama
  - flask (for dashboard)

### Quick Start

1. Clone the repository:
   ```
   git clone https://github.com/username/jebakan.git
   cd jebakan
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Create a basic configuration:
   ```
   mkdir -p config
   cp examples/config.json config/honeypot.json
   ```

4. Run the honeypot:
   ```
   python jebakan.py
   ```

### Command Line Options

```
python jebakan.py [-h] [-c CONFIG] [-v] [-n] [--interaction {low,medium,high}] [--services SERVICES]
```

Options:
- `-h, --help`: Show help message
- `-c, --config CONFIG`: Path to configuration file (default: config/honeypot.json)
- `-v, --verbose`: Increase output verbosity
- `-n, --no-prompt`: Start with default services (no interactive prompt)
- `--interaction {low,medium,high}`: Set global interaction level
- `--services SERVICES`: Comma-separated list of services to enable or 'all'

## Service Configuration

Each service can be independently configured:

```json
{
  "services": {
    "ssh": {
      "enabled": true,
      "port": 2222,
      "interaction_level": "medium",
      "banner": "SSH-2.0-OpenSSH_7.4p1 Ubuntu-10",
      "credentials": [
        {"username": "admin", "password": "password1"},
        {"username": "root", "password": "toor"}
      ]
    },
    ...
  }
}
```

## Dashboard

The built-in web dashboard provides:
- Real-time activity monitoring
- Attack visualization
- Geographic attacker distribution
- Login attempt statistics
- Service-specific analytics

Access the dashboard at `http://localhost:8080` when enabled.

## Security Considerations

- **Network Isolation**: Always run honeypots in isolated networks
- **Resource Monitoring**: Monitor system resources to prevent compromise
- **Legal Compliance**: Ensure your honeypot deployment complies with local laws
- **Data Privacy**: Be mindful of what data you collect and how you store it

## Project Structure

```
jebakan/
├── jebakan.py          # Main application
├── config/             # Configuration files
├── data/               # Data files for services
├── logs/               # Log output
├── services/           # Service emulators
│   ├── base_service.py # Base service class
│   ├── ssh_service.py
│   ├── http_service.py
│   └── ...
└── utils/              # Utility modules
    ├── config_manager.py
    ├── analytics.py
    ├── dashboard.py
    └── alert_manager.py
```

## Disclaimer

This tool is for educational and research purposes only. Users are responsible for how they deploy and use this honeypot system. Always obtain proper authorization before deploying honeypots in production environments.
## License

**Author**: Keith Pachulski  
**Company**: Red Cell Security, LLC  
**Email**: keith@redcellsecurity.org  
**Website**: www.redcellsecurity.org  

© 2025 Keith Pachulski. All rights reserved.

**License**: This software is licensed under the MIT License. You are free to use, modify, and distribute this software in accordance with the terms of the license.

## Support My Work

If you find my work useful and want to support continued development, you can donate here:

[![Donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/sec0ps)

> **DISCLAIMER**:  
> This software is provided "as-is," without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. In no event shall the authors or copyright holders
> be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.
> This tool is for educational and research purposes only. Users are responsible for how they deploy and use this honeypot system. Always obtain proper authorization before deploying honeypots in production environments.
