# 🛡️ AI Security Agent

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)

AI-powered security log analyzer with MITRE ATT&CK framework integration for automated threat detection and incident response.

## ✨ Features

- 🤖 **AI-Powered Analysis** - Uses Claude AI for intelligent threat assessment
- 🎯 **MITRE ATT&CK Mapping** - Automatically maps attacks to techniques and tactics
- 📊 **Multi-Source Logs** - Analyzes host-centric and network-centric logs
- ⚡ **Real-Time Monitoring** - Continuous log monitoring and alerting
- 📈 **Automated Reporting** - Professional incident reports with recommendations
- 🔍 **Threat Hunting** - Built-in queries for common attack patterns
- 🪟 **Windows Integration** - Native Windows Event Log support
- 🐧 **Linux Support** - Syslog and Linux audit log parsing

## 🚀 Quick Start

### Windows (PowerShell)

```powershell
# Clone the repository
git clone https://github.com/yourusername/ai-security-agent.git
cd ai-security-agent

# Run automated setup
.\scripts\powershell\Complete-Setup.ps1

# Set your API key
$env:ANTHROPIC_API_KEY = "sk-ant-your-key-here"

# Run example
python examples\basic_usage.py
```

### Linux/Mac (Bash)

```bash
# Clone the repository
git clone https://github.com/yourusername/ai-security-agent.git
cd ai-security-agent

# Run setup
./scripts/bash/install.sh

# Set your API key
export ANTHROPIC_API_KEY="sk-ant-your-key-here"

# Run example
python examples/basic_usage.py
```

### Manual Installation

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
.\venv\Scripts\Activate.ps1
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## 📋 Requirements

- Python 3.8+
- Anthropic API key ([Get one here](https://console.anthropic.com))
- Windows 10+ (for Windows Event Log features) or Linux
- PowerShell 5.1+ (Windows) or Bash (Linux/Mac)

## 🎯 Usage

### Basic Log Analysis

```python
from src.security_analyzer import SecuritySystem

# Initialize the system
system = SecuritySystem()

# Analyze logs
logs = [
    "2024-10-20 10:15:32 Failed login for user admin from 192.168.1.100",
    "2024-10-20 10:16:45 Process started: cmd.exe by user john.doe",
    "2024-10-20 10:17:12 PowerShell: Mimikatz credential dumping detected"
]

# Ingest and analyze
system.ingest_logs(logs)
analysis = system.analyze_threats()
report = system.generate_report()

print(report)
```

### Windows Event Log Analysis

```powershell
# Export Windows Security logs
.\scripts\powershell\Export-SecurityLogs.ps1

# Analyze exported logs
python examples\windows_integration.py

# View report
Get-Content security_report.txt
```

### Real-Time Monitoring

```powershell
# Start real-time monitoring (Windows)
.\scripts\powershell\Monitor-SecurityLogs.ps1 -CheckInterval 60

# Or on Linux
./scripts/bash/monitor.sh
```

### Filter by Log Type

```python
from src.security_analyzer import SecuritySystem, LogType

system = SecuritySystem()
system.ingest_logs(your_logs)

# Get only authentication logs
auth_logs = system.filter.filter_by_type(
    system.logs, 
    [LogType.AUTHENTICATION]
)

# Get network-centric logs
network_logs = system.filter.network_centric_logs(system.logs)

# Get high-severity threats
threats = system.filter.filter_by_severity(
    system.logs, 
    Severity.HIGH
)
```

## 🏗️ Architecture

```
┌─────────────────┐
│   Log Sources   │ (Windows Events, Syslog, Firewall, IDS/IPS)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Log Parser    │ (Pattern matching, field extraction, classification)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  MITRE Mapper   │ (ATT&CK technique identification, tactic mapping)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  AI Analyzer    │ (Claude: threat assessment, attack narratives)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│     Output      │ (Reports, alerts, recommendations, IOCs)
└─────────────────┘
```

## 🎓 MITRE ATT&CK Coverage

The system detects techniques across all MITRE ATT&CK tactics:

| Tactic | Example Techniques | Detection Method |
|--------|-------------------|------------------|
| **Initial Access** | T1566 - Phishing | Email logs, attachment analysis |
| **Execution** | T1059 - Command Interpreters | Process creation monitoring |
| **Persistence** | T1547 - Registry Run Keys | Registry modification logs |
| **Privilege Escalation** | T1055 - Process Injection | API call monitoring |
| **Defense Evasion** | T1562 - Disable Security Tools | Service stop events |
| **Credential Access** | T1110 - Brute Force | Failed login patterns |
| **Discovery** | T1046 - Network Scanning | Port scan detection |
| **Lateral Movement** | T1021 - Remote Services | RDP/SSH connections |
| **Collection** | T1074 - Data Staged | File staging detection |
| **Command & Control** | T1071 - Web Protocols | Suspicious HTTP beaconing |
| **Exfiltration** | T1041 - Exfiltration Over C2 | Large data transfers |
| **Impact** | T1486 - Ransomware | Mass file encryption |

[See full technique list](docs/mitre_integration.md)

## 📊 Supported Log Types

### Host-Centric Logs
- ✅ Windows Event Logs (Security, System, Application)
- ✅ Linux Syslog
- ✅ Authentication logs
- ✅ Process creation events
- ✅ File access logs
- ✅ Registry modifications (Windows)

### Network-Centric Logs
- ✅ Firewall logs (Windows Firewall, iptables)
- ✅ IDS/IPS alerts (Snort, Suricata)
- ✅ Proxy logs
- ✅ DNS query logs
- ✅ VPN connection logs
- ✅ Network traffic captures

## 📚 Documentation

- [Installation Guide](docs/installation.md) - Detailed setup instructions
- [Usage Guide](docs/usage.md) - Examples and tutorials
- [API Reference](docs/api_reference.md) - Code documentation
- [MITRE Integration](docs/mitre_integration.md) - ATT&CK framework details
- [Windows Integration](docs/windows_integration.md) - Event Log specifics
- [Contributing Guide](CONTRIBUTING.md) - How to contribute

## 🔧 Configuration

Create a `config.yaml` file:

```yaml
# AI Configuration
ai:
  model: "claude-sonnet-4-5-20250929"
  api_key_env: "ANTHROPIC_API_KEY"
  max_tokens: 2048

# Log Sources
log_sources:
  windows_events: true
  syslog: true
  firewall: true
  
# Analysis Settings
analysis:
  min_severity: "MEDIUM"
  auto_report: true
  real_time: false
  
# Output
output:
  report_format: "text"  # or "json", "html"
  save_reports: true
  report_directory: "./reports"
```

## 🧪 Testing

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test
pytest tests/test_parser.py
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Quick Contribution Steps

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is designed for **defensive security purposes only**. It should be used to:
- Monitor and secure your own systems
- Detect threats in authorized environments
- Improve security posture

**Do not use this tool for:**
- Unauthorized access to systems
- Malicious activities
- Attacks against third parties

Use responsibly and in accordance with all applicable laws and regulations.

## 🙏 Acknowledgments

- [MITRE ATT&CK®](https://attack.mitre.org/) - Framework and techniques
- [Anthropic](https://www.anthropic.com/) - Claude AI platform
- [Security Community](https://github.com/topics/cybersecurity) - Inspiration and feedback
- All contributors who help improve this project

## 🐛 Known Issues

- Mock mode has limited AI capabilities (requires API key)
- Windows Event Log parsing requires administrator privileges
- Some log formats may need custom parsing rules

See [Issues](https://github.com/yourusername/ai-security-agent/issues) for a complete list.

## 🗺️ Roadmap

- [ ] Web-based dashboard interface
- [ ] Integration with popular SIEMs (Splunk, ELK, QRadar)
- [ ] Machine learning for anomaly detection
- [ ] Multi-language log support
- [ ] Docker containerization
- [ ] Cloud deployment options (AWS, Azure, GCP)
- [ ] Mobile app for alerts
- [ ] APT group mapping
- [ ] Threat intelligence feed integration

## 📧 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/ai-security-agent/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/ai-security-agent/discussions)
- **Email**: security@yourdomain.com

## 📈 Stats

![GitHub stars](https://img.shields.io/github/stars/yourusername/ai-security-agent?style=social)
![GitHub forks](https://img.shields.io/github/forks/yourusername/ai-security-agent?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/yourusername/ai-security-agent?style=social)

---

**Made with ❤️ for the Security Community**

[⬆ back to top](#-ai-security-agent)