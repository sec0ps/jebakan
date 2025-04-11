# Jebakan - Honeypot System

A modular Python-based honeypot system for cybersecurity research and threat intelligence gathering. This honeypot emulates multiple network services to attract and analyze attack patterns.

## Features

- **Multi-Service Emulation**: SSH, HTTP, FTP, and Telnet services
- **Configurable Interaction Levels**: Low, medium, and high interaction levels for each service
- **Comprehensive Logging**: Detailed logging of all attacker interactions
- **Authentication Traps**: Fake authentication systems to capture credentials
- **Real-time Alerts**: Email and webhook notifications for suspicious activities
- **Data Analytics**: Built-in analytics engine for attack pattern recognition
- **Web Dashboard**: Visual dashboard for monitoring honeypot activity
- **Breadcrumb Deployment**: Configurable breadcrumbs to attract advanced attackers
- **Modular Architecture**: Easily extensible to add new service emulators

## System Requirements

- Python 3.7+
- Required Python packages (see requirements.txt)
- At least 512MB RAM
- 1GB free disk space
- Internet connection (for sending alerts and gathering IP intelligence)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/python-honeypot.git
   cd python-honeypot
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Create the initial directory structure:
   ```
   mkdir -p data/http data/ftp logs config
   ```

5. Generate the default configuration file:
   ```
   python honeypot.py --generate-config
   ```

## Configuration

The honeypot is configured using a JSON file located at `config/honeypot.json`. The default configuration will be generated if this file doesn't exist.

Key configuration options:

- **Network Settings**: IP binding and connection limits
- **Service Configuration**: Enable/disable services and set ports
- **Logging Settings**: Log file locations and rotation policies
- **Authentication**: Credentials for each service
- **Alert Settings**: Email and webhook notification setup
- **Dashboard**: Web interface configuration

Example configuration:

```json
{
  "network": {
    "bind_ip": "0.0.0.0",
    "max_connections": 100
  },
  "services": {
    "ssh": {
      "enabled": true,
      "port": 2222,
      "banner": "SSH-2.0-OpenSSH_7.4p1 Ubuntu-10",
      "interaction_level": "medium"
    },
    "http": {
      "enabled": true,
      "port": 8080,
      "server_name": "Apache/2.4.41 (Ubuntu)",
      "interaction_level": "medium"
    },
    "ftp": {
      "enabled": true,
      "port": 2121,
      "banner": "220 FTP Server Ready",
      "interaction_level": "medium"
    },
    "telnet": {
      "enabled": true,
      "port": 2323,
      "banner": "Ubuntu 18.04 LTS",
      "interaction_level": "medium"
    }
  }
}
```

## Usage

### Starting the Honeypot

```
python honeypot.py
```

### Command-Line Options

- `--config`: Specify a custom configuration file path
- `--verbose`: Enable verbose debugging output
- `--generate-config`: Generate a default configuration file
- `--service`: Start only specific services (e.g., `--service ssh http`)

### Dashboard Access

The web dashboard is available at `http://your-server-ip:8000` (default port). Login credentials are specified in the configuration file.

## Security Considerations

- **Network Isolation**: Always run honeypots in isolated networks
- **Firewall Rules**: Set up proper firewall rules to protect your infrastructure
- **Regular Monitoring**: Check logs regularly for signs of containment bypass
- **Resource Limits**: Configure resource limits to prevent DoS conditions
- **Legal Compliance**: Ensure your honeypot deployment complies with local laws

## Extending the Honeypot

### Adding a New Service

1. Create a new service module in the `services` directory
2. Extend the `BaseService` class
3. Implement the `handle_client` method
4. Update the configuration schema
5. Register the service in `honeypot.py`

Example service module template:

```python
from services.base_service import BaseService

class MyService(BaseService):
    def __init__(self, host, port, config):
        super().__init__(host, port, config, "myservice")
        
    def handle_client(self, client_socket, address, connection_data):
        # Implement service-specific logic here
        pass
```

## Analytics and Reporting

The honeypot includes an analytics engine that processes collected data and generates various reports:

- Connection statistics
- Authentication attempt analysis
- Command execution patterns
- Attack pattern recognition
- Geographic IP distribution

Reports are automatically generated in the `data/reports` directory.

## Troubleshooting

### Common Issues

- **Service won't start**: Check if ports are already in use
- **Database errors**: Verify database file permissions
- **Email alerts not working**: Check SMTP server configuration
- **High CPU usage**: Adjust the resource limits in configuration
- **Dashboard unavailable**: Verify network connectivity and firewall rules

## License

This project is licensed under the MIT License - see the LICENSE file for details.
