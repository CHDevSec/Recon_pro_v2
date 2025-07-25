# 🔍 Recon Pro v2.0

<div align="center">

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Status](https://img.shields.io/badge/status-Professional-success)

**Professional Web Reconnaissance Tool**

*Developed by Pentester Caio | CHDEVSEC*

</div>

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Modular Architecture](#-modular-architecture)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Examples](#-examples)
- [Reports](#-reports)
- [Supported APIs](#-supported-apis)
- [Contributing](#-contributing)
- [Disclaimer](#-disclaimer)

## 🎯 Overview

**Recon Pro v2.0** is a professional web reconnaissance tool completely redesigned with modular architecture, focused on asset discovery, advanced fuzzing, vulnerability detection, and executive report generation.

### 🚀 Key Improvements v2.0

- **Modular Architecture**: Code organized in specialized modules
- **Advanced Discovery**: Multiple intelligence sources (APIs, CT logs, external tools)
- **Intelligent Fuzzing**: Technology-specific payloads
- **Vulnerability Engine**: Automatic detection of 15+ vulnerability types
- **Professional Reports**: HTML, JSON, CSV and executive summary
- **Flexible Configuration**: Complete JSON configuration system

## ✨ Features

### 🔍 Asset Discovery
- **External Tools**: Subfinder, Assetfinder, Amass, Findomain, Chaos
- **Premium APIs**: SecurityTrails, Shodan, VirusTotal, Censys
- **Certificate Transparency**: crt.sh, Certspotter
- **DNS Bruteforce**: Optimized wordlists + intelligent DNS
- **Search Engines**: Google, Bing (with official APIs)

### 🎯 Advanced Fuzzing
- **Admin Panels**: 50+ common paths
- **Sensitive Files**: .env, configs, backups, logs
- **API Endpoints**: REST, GraphQL, SOAP, WebSocket
- **Authentication Bypass**: Custom headers, IP spoofing
- **Technology Payloads**: WordPress, Laravel, Django, Node.js, etc.

### 🛡️ Vulnerability Detection
- **Injections**: SQL, XSS, LFI, RFI, RCE, SSTI, XXE
- **Data Exposure**: Credentials, debug info, paths
- **Configurations**: CORS, CSP, Security headers
- **Technology-Specific**: WordPress, Drupal, Joomla, Laravel
- **Context Analysis**: Confidence scoring, risk assessment

### 📊 Professional Reports
- **Interactive HTML**: Charts, metrics, drill-down
- **Executive Summary**: For management and decision making
- **Structured JSON**: For integration and automation
- **Analytical CSV**: For data analysis
- **Visualizations**: Charts.js, gauges, progress bars

## 🏗️ Modular Architecture

```
recon_pro_v2/
├── modules/
│   ├── __init__.py          # Package initialization
│   ├── discovery.py         # Asset discovery engine
│   ├── fuzzer.py           # Advanced fuzzing module
│   ├── vulnerabilities.py  # Vulnerability detection
│   └── reporting.py        # Professional reporting
├── recon_pro_v2.py         # Main application
├── config.json             # Configuration file
└── requirements.txt        # Dependencies
```

### 📦 Modules

| Module | Responsibility | Main Classes |
|--------|----------------|--------------|
| `discovery.py` | Subdomain and asset discovery | `AssetDiscovery` |
| `fuzzer.py` | Fuzzing and penetration testing | `AdvancedFuzzer` |
| `vulnerabilities.py` | Vulnerability detection and analysis | `VulnerabilityEngine` |
| `reporting.py` | Professional report generation | `AdvancedReporting` |

## 🔧 Installation

### Prerequisites
- Python 3.8+
- pip
- Git

### Python Dependencies
```bash
pip install -r requirements.txt
```

### External Tools (Optional)
```bash
# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Assetfinder  
go install github.com/tomnomnom/assetfinder@latest

# Amass
snap install amass

# Findomain
wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux
chmod +x findomain-linux && sudo mv findomain-linux /usr/local/bin/findomain
```

## ⚙️ Configuration

### 1. Configuration File

Copy and edit the `config.json` file:

```bash
cp config.json my_config.json
```

### 2. APIs (Optional but Recommended)

Add your API keys in `config.json`:

```json
{
  "api_keys": {
    "SECURITYTRAILS": "your_api_key_here",
    "SHODAN": "your_api_key_here",
    "VIRUSTOTAL": "your_api_key_here",
    "GOOGLE_API_KEY": "your_api_key_here",
    "GOOGLE_CSE_ID": "your_cse_id_here"
  }
}
```

### 3. Environment Variables (Alternative)

```bash
export SECURITYTRAILS_API_KEY="your_key"
export SHODAN_API_KEY="your_key"
export VIRUSTOTAL_API_KEY="your_key"
```

## 🚀 Usage

### Basic Usage

```bash
# Complete default scan
python recon_pro_v2.py example.com

# With configuration file
python recon_pro_v2.py example.com --config my_config.json

# Quick scan
python recon_pro_v2.py example.com --scan-type quick

# Deep scan
python recon_pro_v2.py example.com --scan-type deep
```

### Advanced Options

```bash
# Customize threads and timeout
python recon_pro_v2.py example.com --threads 30 --verbose

# Specific output directory
python recon_pro_v2.py example.com --output-dir /path/to/results

# Verbose mode for debugging
python recon_pro_v2.py example.com --verbose
```

### Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `domain` | Target domain (required) | - |
| `--config` | JSON configuration file | `config.json` |
| `--scan-type` | Scan type: quick/full/deep | `full` |
| `--output-dir` | Output directory | `recon_results` |
| `--threads` | Number of threads | `20` |
| `--verbose` | Debug/verbose mode | `False` |

## 💡 Examples

### Example 1: Basic Scan

```bash
python recon_pro_v2.py tesla.com
```

**Output:**
- `recon_report_tesla.com_20240101_120000.html` - Main report
- `recon_data_tesla.com_20240101_120000.json` - Structured data
- `executive_summary_tesla.com_20240101_120000.html` - Executive summary

### Example 2: Custom Scan

```bash
python recon_pro_v2.py microsoft.com \
  --config enterprise_config.json \
  --scan-type deep \
  --threads 50 \
  --output-dir ./microsoft_recon \
  --verbose
```

### Example 3: Specific Configuration

```json
{
  "threads": 30,
  "timeout": 20,
  "rate_limit": 0.2,
  "api_keys": {
    "SECURITYTRAILS": "st_api_key_here",
    "SHODAN": "shodan_key_here"
  },
  "advanced_options": {
    "stealth_mode": true,
    "custom_headers": {
      "X-Forwarded-For": "127.0.0.1"
    }
  }
}
```

## 📊 Reports

### 📄 Main HTML Report

The HTML report includes:

- **Executive Dashboard**: Key metrics and risk score
- **Discovered Subdomains**: Interactive table with technologies
- **Sensitive Findings**: High-risk URLs with evidence
- **Vulnerabilities**: Detailed by severity with remediation
- **Google Dorks**: Intelligence gathering results
- **Recommendations**: Prioritized by impact

### 📈 Visualizations

- **Pie Charts**: Vulnerability distribution
- **Bar Charts**: Findings by category
- **Risk Gauge**: Visual score from 0-10
- **Technology Bars**: Most found technologies

### 📋 Executive Summary

Condensed version focused on:
- Business risks
- Financial impact
- Strategic recommendations
- Remediation timeline

## 🔗 Supported APIs

| API | Functionality | Status | Documentation |
|-----|---------------|--------|---------------|
| **SecurityTrails** | Subdomains + DNS History | ✅ | [Docs](https://docs.securitytrails.com/) |
| **Shodan** | Hosts + Ports + Banners | ✅ | [Docs](https://developer.shodan.io/) |
| **VirusTotal** | Subdomains + Reputation | ✅ | [Docs](https://developers.virustotal.com/) |
| **Censys** | Certificates + Hosts | ✅ | [Docs](https://search.censys.io/api) |
| **Google CSE** | Search Engine Intelligence | ✅ | [Docs](https://developers.google.com/custom-search) |
| **Bing Search** | Search Engine Results | ✅ | [Docs](https://docs.microsoft.com/bing-web-search/) |

### 🔑 Getting Free APIs

1. **SecurityTrails**: 50 queries/month free
2. **Shodan**: 100 queries/month free  
3. **VirusTotal**: 1000 requests/day free
4. **Google CSE**: 100 queries/day free

## 🏆 Version Comparison

| Feature | v1.0 | v2.0 |
|---------|------|------|
| Architecture | Monolithic | Modular |
| APIs | 3 | 6+ |
| Vuln Types | 7 | 15+ |
| Reports | Basic HTML | HTML + JSON + CSV + Executive |
| Configuration | Hardcoded | Flexible JSON |
| Fuzzing | Basic | Intelligent by technology |
| Performance | Simple threading | Optimized + Rate limiting |
| Tech Detection | Headers only | Headers + Content + Context |

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork the project
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### 🛠️ Development

```bash
# Clone the repository
git clone https://github.com/yourusername/recon-pro-v2.git

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Linting
flake8 modules/ recon_pro_v2.py
```

## ⚖️ Disclaimer

**⚠️ IMPORTANT**: This software is intended EXCLUSIVELY for:

- ✅ Authorized testing on own systems
- ✅ Pentests with written authorization
- ✅ Bug bounty programs
- ✅ Ethical security research
- ✅ Cybersecurity education

**❌ DO NOT use for:**
- ❌ Unauthorized attacks
- ❌ Systems that are not yours
- ❌ Illegal activities
- ❌ Terms of service violations

The author is not responsible for misuse of this tool. The user is fully responsible for ensuring they have proper authorization before executing any tests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Pentester Caio | CHDEVSEC**

- 🐙 GitHub: [@CHDEVSEC](https://github.com/CHDevSec)

---

<div align="center">

**If this tool was helpful, consider giving it a ⭐ on the repository!**

Made with ❤️ by [Pentester Caio](https://github.com/yourusername)

</div>
