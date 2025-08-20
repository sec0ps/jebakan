# Jebakan: Python Honeypot System

**Jebakan** is a modular, service-rich honeypot platform built to detect, deceive, and document attacker behavior in real time. Designed by Red Cell Security, this Python-based system emulates real-world services across multiple protocols, enabling threat intelligence collection without exposing production assets.

## Features

- **Multi-Protocol Emulation:** SSH, RDP, MySQL, MSSQL, Redis, Elasticsearch, FTP, HTTP, Telnet, and VNC
- **Realistic Service Behavior:** Simulated login prompts, command shells, vulnerable endpoints, and fake file systems
- **Deep Logging:** Captures authentication attempts, file access, command execution, SQL injections, and more
- **Unified Threat Logging:** JSON-formatted, structured attack data with timestamped session details
- **Configurable Deception:** Define fake credentials, system info, breadcrumbs, and interaction levels
- **Low Interaction to High Interaction:** Choose between fake banners, partial responses, or full protocol simulation
- **Safe Deployment:** Fully isolated from production—ideal for DMZs, SOC labs, or dedicated decoy servers
- **ML Enhancements:** Machine learning integrated to detect anomalous attack patterns, assign real-time risk scores, and silently flag high-priority threats for analyst review.

## Installation

### Quick Start

1. Clone the repository:
   ```
   git clone https://github.com/username/jebakan.git
   cd jebakan
   ```

2. Install jebakan:
   ```
   python install_jebakan.py
   ```

3. Run the honeypot:
   ```
   cd /opt/jebakan
   python jebakan.py
   ```

## Security Considerations

- **Network Isolation**: Always run honeypots in isolated networks
- **Resource Monitoring**: Monitor system resources to prevent compromise
- **Legal Compliance**: Ensure your honeypot deployment complies with local laws
- **Data Privacy**: Be mindful of what data you collect and how you store it

## Disclaimer

This tool is for educational and research purposes only. Users are responsible for how they deploy and use this honeypot system. Always obtain proper authorization before deploying honeypots in production environments.

## Contact
For professional services, integrations, or support contact: operations@redcellsecurity.org

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
