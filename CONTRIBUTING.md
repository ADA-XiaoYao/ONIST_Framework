# Contributing to OSINT Framework

First off, thank you for considering contributing to OSINT Framework! 🎉

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Submitting Changes](#submitting-changes)
- [Adding New Features](#adding-new-features)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

### Our Standards

- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on constructive criticism
- Respect differing viewpoints
- Prioritize security and ethical use

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear title** and description
- **Steps to reproduce** the problem
- **Expected behavior** vs actual behavior
- **Environment details** (OS, Python version, etc.)
- **Screenshots** if applicable
- **Log files** or error messages

### Suggesting Enhancements

Enhancement suggestions are welcome! Please provide:

- Clear description of the enhancement
- Use case and benefits
- Potential implementation approach
- Any relevant examples or references

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Make your changes
4. Test thoroughly
5. Commit with clear messages
6. Push to your fork
7. Open a Pull Request

## Development Setup

### Prerequisites

```bash
# Install system dependencies
sudo apt update
sudo apt install -y python3 python3-pip golang git

# Clone your fork
git clone https://github.com/YOUR_USERNAME/ONIST_Framework.git
cd ONIST_Framework

# Install Python dependencies
pip3 install -r requirements.txt

# Run tests
bash test_framework.sh
```

### Project Structure

```
ONIST_Framework/
├── recon_master.go           # Go core engine
├── osint_intelligence_engine.py  # OSINT collection
├── github_intelligence.py    # GitHub scanning
├── vuln_hunter.py           # Vulnerability scanning
├── advanced_dns_enum.sh     # DNS enumeration
├── web_asset_discovery.sh   # Web asset discovery
├── install_tools.sh         # Tool installation
├── update_databases.sh      # Database updates
├── requirements.txt         # Python dependencies
├── config.example.json      # Configuration example
└── tests/                   # Test files
```

## Coding Standards

### Python

- Follow **PEP 8** style guide
- Use **type hints** where appropriate
- Add **docstrings** to all functions/classes
- Keep functions small and focused
- Use meaningful variable names

```python
def fetch_subdomains(domain: str, sources: List[str]) -> Set[str]:
    """
    Fetch subdomains from multiple sources.
    
    Args:
        domain: Target domain to enumerate
        sources: List of data sources to query
        
    Returns:
        Set of discovered subdomains
        
    Raises:
        ValueError: If domain is invalid
    """
    # Implementation
    pass
```

### Go

- Follow **Go standard conventions**
- Use **gofmt** for formatting
- Add **comments** for exported functions
- Handle **errors explicitly**
- Use **context** for cancellation

```go
// EnumerateSubdomains discovers subdomains using multiple techniques
func EnumerateSubdomains(ctx context.Context, domain string) ([]string, error) {
    if domain == "" {
        return nil, errors.New("domain cannot be empty")
    }
    // Implementation
}
```

### Bash

- Use **shellcheck** for linting
- Add **comments** for complex logic
- Use **functions** for reusable code
- Check **exit codes** properly
- Quote **variables** to prevent word splitting

```bash
# Function to enumerate subdomains
enumerate_subdomains() {
    local domain="$1"
    local output_file="$2"
    
    if [ -z "$domain" ]; then
        echo "Error: Domain required" >&2
        return 1
    fi
    
    # Implementation
}
```

## Submitting Changes

### Commit Messages

Follow conventional commits format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

**Examples:**

```
feat(osint): add AlienVault OTX integration

Add AlienVault OTX as new data source for subdomain enumeration.
Includes API client, error handling, and rate limiting.

Closes #123
```

```
fix(vuln): correct CVE matching logic

Fix bug where CVE matching was case-sensitive, causing missed matches.

Fixes #456
```

### Pull Request Guidelines

**Title Format:**
```
[Type] Brief description
```

**Description Template:**

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tests pass locally
- [ ] New tests added
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Comments added where needed
- [ ] Documentation updated
- [ ] No new warnings generated
```

## Adding New Features

### 1. New Data Source

To add a new OSINT data source:

```python
# In osint_intelligence_engine.py

async def _your_source_subdomains(self) -> Set[str]:
    """Query YourSource for subdomains"""
    try:
        url = f'https://api.yoursource.com/domains/{self.target}'
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=30) as resp:
                data = await resp.json()
                return {item['domain'] for item in data}
    except:
        return set()

# Add to subdomain_enumeration():
sources = [
    # ... existing sources ...
    self._your_source_subdomains,
]
```

### 2. New Vulnerability Check

To add a new vulnerability test:

```python
# In vuln_hunter.py

def test_your_vuln(self, target):
    """Test for YourVuln vulnerability"""
    try:
        # Test implementation
        payload = "your_test_payload"
        response = requests.get(f"{target}?test={payload}")
        
        # Check for vulnerability indicators
        if "vuln_indicator" in response.text:
            return True
    except:
        pass
    
    return False

# Add to test_web_vulnerabilities():
if self.test_your_vuln(target):
    vulns.append({
        'type': 'YourVuln',
        'severity': 'HIGH',
        'description': 'YourVuln vulnerability detected',
        'url': target
    })
```

### 3. New Exploit Module

To add a custom exploit:

```python
# In custom_exploits/ directory

from exploit_engine import BaseExploit

class YourExploit(BaseExploit):
    name = "Your Exploit Name"
    cve = "CVE-2024-XXXXX"
    description = "Exploit description"
    
    def check(self, target):
        """Check if target is vulnerable"""
        # Implementation
        return is_vulnerable
    
    def exploit(self, target, payload):
        """Execute exploit"""
        # Implementation
        return shell_session
```

### 4. New Tool Integration

To integrate a new tool:

```bash
# In install_tools.sh

# Add to install_go_tools():
go install -v github.com/author/yourtool/cmd/yourtool@latest

# Add to TOOLS array:
TOOLS=("existing_tools" "yourtool")
```

## Testing

### Running Tests

```bash
# Full test suite
bash test_framework.sh

# Python tests only
python -m pytest tests/

# Go tests
go test ./...

# Bash script tests
shellcheck *.sh
```

### Writing Tests

Add tests for new features:

```python
# tests/test_osint.py

def test_subdomain_enumeration():
    """Test subdomain enumeration"""
    engine = OSINTEngine("example.com", "test_output")
    subdomains = asyncio.run(engine._crtsh_subdomains())
    
    assert len(subdomains) > 0
    assert all('example.com' in s for s in subdomains)
```

## Areas for Contribution

We especially welcome contributions in these areas:

### High Priority
- [ ] Additional OSINT data sources
- [ ] New exploit modules
- [ ] Improved evasion techniques
- [ ] Better error handling
- [ ] Performance optimizations

### Medium Priority
- [ ] Additional vulnerability checks
- [ ] Report generation improvements
- [ ] UI/Dashboard (web interface)
- [ ] Docker containerization
- [ ] Cloud deployment guides

### Documentation
- [ ] Video tutorials
- [ ] Use case examples
- [ ] API documentation
- [ ] Translation to other languages
- [ ] Blog posts / articles

## Recognition

Contributors will be:
- Listed in README.md
- Credited in release notes
- Recognized in Hall of Fame
- Given contributor badge

## Questions?

- Open an issue with `[Question]` tag
- Join discussions on GitHub
- Contact: See README.md for contact information

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to OSINT Framework! 🙏

Together we're building the most comprehensive security assessment platform! 🚀
