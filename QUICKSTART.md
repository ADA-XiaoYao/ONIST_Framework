# Quick Start Guide - OSINT Framework

Get started with OSINT Framework in 5 minutes!

## Prerequisites

- Linux/macOS/WSL
- Python 3.8+
- Go 1.21+ (for core engine)
- Basic command line knowledge

## Installation (5 minutes)

### Step 1: Clone Repository

```bash
git clone https://github.com/ADA-XiaoYao/ONIST_Framework.git
cd ONIST_Framework
```

### Step 2: Install Python Dependencies

```bash
pip3 install -r requirements.txt
```

### Step 3: Install Security Tools (Optional but Recommended)

```bash
chmod +x install_tools.sh
./install_tools.sh
```

This will install 100+ security tools including:
- subfinder, httpx, nuclei (ProjectDiscovery)
- amass (OWASP)
- nmap, masscan
- And many more...

**Note**: This step takes 15-30 minutes depending on your system.

### Step 4: Update Vulnerability Databases

```bash
chmod +x update_databases.sh
./update_databases.sh
```

This downloads:
- CVE database (10,000+ entries)
- CWE patterns (1,000+ weaknesses)
- Exploit-DB (45,000+ exploits)
- Nuclei templates (5,000+ checks)

### Step 5: Compile Go Engine (Optional)

```bash
go build -o recon_master recon_master.go
```

If you don't have Go installed, you can still use Python modules.

## First Scan (30 seconds)

### Basic Reconnaissance

```bash
python3 osint_intelligence_engine.py -d example.com
```

This will:
- ✓ Enumerate subdomains from 30+ sources
- ✓ Collect emails and social media
- ✓ Analyze DNS records
- ✓ Check for data breaches
- ✓ Generate comprehensive report

### GitHub Code Leak Scan

```bash
export GITHUB_TOKEN="ghp_your_token_here"
python3 github_intelligence.py -d example.com -t $GITHUB_TOKEN
```

Searches for:
- API keys and secrets
- Leaked credentials
- Sensitive configuration files
- Private keys

### Vulnerability Scanning

```bash
# First, create target list
echo "https://example.com" > targets.txt

# Run vulnerability hunter
python3 vuln_hunter.py --targets targets.txt --full
```

## Configuration

### API Keys (Optional but Recommended)

Add to `~/.bashrc` or `~/.zshrc`:

```bash
# Shodan (https://account.shodan.io/)
export SHODAN_API_KEY="your_key_here"

# VirusTotal (https://www.virustotal.com/gui/my-apikey)
export VIRUSTOTAL_API_KEY="your_key_here"

# GitHub (https://github.com/settings/tokens)
export GITHUB_TOKEN="ghp_your_token_here"

# Censys (https://search.censys.io/account/api)
export CENSYS_API_ID="your_id"
export CENSYS_API_SECRET="your_secret"

# SecurityTrails (https://securitytrails.com/app/account/credentials)
export SECURITYTRAILS_API_KEY="your_key"

# Hunter.io (https://hunter.io/api_keys)
export HUNTER_API_KEY="your_key"
```

Reload:
```bash
source ~/.bashrc
```

## Common Use Cases

### 1. Bug Bounty Reconnaissance

```bash
# Full reconnaissance
python3 osint_intelligence_engine.py -d target.com --all-modules

# Advanced DNS enumeration
./advanced_dns_enum.sh -d target.com -w ~/wordlists/dns-10m.txt

# Web asset discovery
./web_asset_discovery.sh -l subdomains.txt

# Vulnerability scanning
python3 vuln_hunter.py --targets alive_hosts.txt --full
```

### 2. Penetration Testing

```bash
# Run Go engine for maximum speed
./recon_master -d target.com --aggressive

# Auto-exploitation (use with caution!)
python3 vuln_hunter.py --target https://target.com --auto-exploit --lhost YOUR_IP
```

### 3. Security Research

```bash
# GitHub leak hunting
python3 github_intelligence.py -u target-org -t $GITHUB_TOKEN

# Dark web monitoring
python3 osint_intelligence_engine.py -d target.com --dark-web
```

### 4. Continuous Monitoring

```bash
# Add to crontab for daily scans
0 2 * * * cd /path/to/ONIST_Framework && python3 osint_intelligence_engine.py -d target.com

# Update databases weekly
0 3 * * 0 cd /path/to/ONIST_Framework && ./update_databases.sh
```

## Output

Results are saved in timestamped directories:

```
recon_example.com_20240219_143022/
├── 01_reconnaissance/
│   ├── subdomains.txt (1,234 found)
│   ├── emails.txt (89 found)
│   └── certificates.json
├── 02_vulnerability_scan/
│   ├── critical.json (5 vulns)
│   ├── high.json (23 vulns)
│   └── exploits_available.json
├── 03_intelligence/
│   ├── github_leaks.json (12 secrets!)
│   ├── breach_data.json
│   └── social_media.json
└── OSINT_REPORT.md
```

## Troubleshooting

### Python Import Errors

```bash
pip3 install --upgrade -r requirements.txt
```

### Tool Not Found

```bash
# Re-run installer
./install_tools.sh

# Or install specific tool
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### Database Errors

```bash
# Delete old databases
rm -rf databases/

# Re-download
./update_databases.sh
```

### Permission Denied

```bash
# Fix permissions
chmod +x *.sh *.py
```

## Next Steps

1. Read full [README.md](README.md) for detailed documentation
2. Configure API keys for maximum data sources
3. Run `./test_framework.sh` to verify installation
4. Start with safe targets (your own domains)
5. Join community discussions on GitHub

## Safety Reminders

⚠️ **IMPORTANT**:
- Only test systems you own or have permission to test
- Auto-exploitation is powerful - use responsibly
- Some scans are noisy - consider stealth options
- Follow responsible disclosure for vulnerabilities found
- Comply with all applicable laws and regulations

## Getting Help

- GitHub Issues: https://github.com/ADA-XiaoYao/ONIST_Framework/issues
- Documentation: See `/docs` folder (coming soon)
- Community: GitHub Discussions

## What's Next?

Now that you're set up, explore:
- Advanced reconnaissance techniques
- Custom exploit development
- Automation and scripting
- Integration with other tools (Metasploit, Burp Suite)

Happy hunting! 🎯

