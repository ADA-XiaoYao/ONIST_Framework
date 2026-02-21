#!/bin/bash

# ========================================
# OSINT Framework - Comprehensive Test Suite
# Tests all modules and fixes issues
# ========================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASSED=0
FAILED=0
WARNINGS=0

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}OSINT Framework - Test Suite${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Test 1: Check Python syntax
test_python_syntax() {
    echo -e "${YELLOW}[TEST 1]${NC} Python Syntax Check..."
    
    PYTHON_FILES=(
        "osint_intelligence_engine.py"
        "github_intelligence.py"
        "vuln_hunter.py"
    )
    
    for file in "${PYTHON_FILES[@]}"; do
        if python3 -m py_compile "$file" 2>/dev/null; then
            echo -e "  ${GREEN}✓${NC} $file - Syntax OK"
            ((PASSED++))
        else
            echo -e "  ${RED}✗${NC} $file - Syntax Error"
            ((FAILED++))
        fi
    done
    echo ""
}

# Test 2: Check Bash syntax
test_bash_syntax() {
    echo -e "${YELLOW}[TEST 2]${NC} Bash Syntax Check..."
    
    BASH_FILES=(
        "advanced_dns_enum.sh"
        "web_asset_discovery.sh"
        "install_tools.sh"
        "update_databases.sh"
    )
    
    for file in "${BASH_FILES[@]}"; do
        if bash -n "$file" 2>/dev/null; then
            echo -e "  ${GREEN}✓${NC} $file - Syntax OK"
            ((PASSED++))
        else
            echo -e "  ${RED}✗${NC} $file - Syntax Error"
            ((FAILED++))
        fi
    done
    echo ""
}

# Test 3: Check Python imports
test_python_imports() {
    echo -e "${YELLOW}[TEST 3]${NC} Python Import Check..."
    
    python3 - <<'EOF'
import sys
failed = []

# Test osint_intelligence_engine.py imports
try:
    import asyncio
    import aiohttp
    import json
    import dns.resolver
    import socket
    import ssl
    print("  ✓ osint_intelligence_engine.py - Core imports OK")
except ImportError as e:
    print(f"  ✗ osint_intelligence_engine.py - Missing: {e}")
    failed.append("osint")

# Test github_intelligence.py imports
try:
    import requests
    import json
    import os
    import sys
    import argparse
    import base64
    import re
    from concurrent.futures import ThreadPoolExecutor
    print("  ✓ github_intelligence.py - Core imports OK")
except ImportError as e:
    print(f"  ✗ github_intelligence.py - Missing: {e}")
    failed.append("github")

# Test vuln_hunter.py imports
try:
    import json
    import requests
    import sqlite3
    import os
    import sys
    import argparse
    import subprocess
    from datetime import datetime
    print("  ✓ vuln_hunter.py - Core imports OK")
except ImportError as e:
    print(f"  ✗ vuln_hunter.py - Missing: {e}")
    failed.append("vuln")

if failed:
    print(f"\n  Missing packages for: {', '.join(failed)}")
    print("  Install with: pip3 install aiohttp dnspython requests")
    sys.exit(1)
else:
    sys.exit(0)
EOF

    if [ $? -eq 0 ]; then
        ((PASSED+=3))
    else
        ((FAILED+=3))
        echo -e "  ${YELLOW}⚠${NC} Some Python packages are missing"
        echo -e "  ${YELLOW}⚠${NC} Run: pip3 install aiohttp dnspython requests whois"
        ((WARNINGS++))
    fi
    echo ""
}

# Test 4: Check tool availability
test_tools_availability() {
    echo -e "${YELLOW}[TEST 4]${NC} Tool Availability Check..."
    
    REQUIRED_TOOLS=(
        "python3:Required"
        "bash:Required"
        "curl:Required"
        "wget:Required"
        "jq:Recommended"
    )
    
    OPTIONAL_TOOLS=(
        "subfinder:Optional"
        "httpx:Optional"
        "nuclei:Optional"
        "nmap:Optional"
        "amass:Optional"
    )
    
    echo "  Required Tools:"
    for tool_info in "${REQUIRED_TOOLS[@]}"; do
        tool="${tool_info%%:*}"
        status="${tool_info##*:}"
        
        if command -v "$tool" &> /dev/null; then
            echo -e "    ${GREEN}✓${NC} $tool - Available"
            ((PASSED++))
        else
            echo -e "    ${RED}✗${NC} $tool - Missing ($status)"
            ((FAILED++))
        fi
    done
    
    echo ""
    echo "  Optional Tools (install with install_tools.sh):"
    for tool_info in "${OPTIONAL_TOOLS[@]}"; do
        tool="${tool_info%%:*}"
        
        if command -v "$tool" &> /dev/null; then
            echo -e "    ${GREEN}✓${NC} $tool - Available"
        else
            echo -e "    ${YELLOW}○${NC} $tool - Not installed (optional)"
            ((WARNINGS++))
        fi
    done
    echo ""
}

# Test 5: Test Python scripts help
test_python_help() {
    echo -e "${YELLOW}[TEST 5]${NC} Python Scripts Help Test..."
    
    if python3 osint_intelligence_engine.py --help &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} osint_intelligence_engine.py --help works"
        ((PASSED++))
    else
        echo -e "  ${RED}✗${NC} osint_intelligence_engine.py --help failed"
        ((FAILED++))
    fi
    
    if python3 github_intelligence.py --help &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} github_intelligence.py --help works"
        ((PASSED++))
    else
        echo -e "  ${RED}✗${NC} github_intelligence.py --help failed"
        ((FAILED++))
    fi
    
    if python3 vuln_hunter.py --help &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} vuln_hunter.py --help works"
        ((PASSED++))
    else
        echo -e "  ${RED}✗${NC} vuln_hunter.py --help failed"
        ((FAILED++))
    fi
    echo ""
}

# Test 6: Check file permissions
test_file_permissions() {
    echo -e "${YELLOW}[TEST 6]${NC} File Permissions Check..."
    
    EXEC_FILES=(
        "advanced_dns_enum.sh"
        "web_asset_discovery.sh"
        "install_tools.sh"
        "update_databases.sh"
        "osint_intelligence_engine.py"
        "github_intelligence.py"
        "vuln_hunter.py"
    )
    
    for file in "${EXEC_FILES[@]}"; do
        if [ -x "$file" ]; then
            echo -e "  ${GREEN}✓${NC} $file - Executable"
            ((PASSED++))
        else
            echo -e "  ${YELLOW}⚠${NC} $file - Not executable (fixing...)"
            chmod +x "$file"
            ((WARNINGS++))
        fi
    done
    echo ""
}

# Test 7: Check README
test_readme() {
    echo -e "${YELLOW}[TEST 7]${NC} README Check..."
    
    if [ -f "README.md" ]; then
        # Check for key sections
        sections=(
            "Installation"
            "Quick Start"
            "Features"
            "Usage"
        )
        
        for section in "${sections[@]}"; do
            if grep -qi "$section" README.md; then
                echo -e "  ${GREEN}✓${NC} README contains: $section"
                ((PASSED++))
            else
                echo -e "  ${YELLOW}⚠${NC} README missing: $section"
                ((WARNINGS++))
            fi
        done
    else
        echo -e "  ${RED}✗${NC} README.md not found"
        ((FAILED++))
    fi
    echo ""
}

# Test 8: Test database directory creation
test_database_setup() {
    echo -e "${YELLOW}[TEST 8]${NC} Database Setup Test..."
    
    mkdir -p ./databases_test
    
    if [ -d "./databases_test" ]; then
        echo -e "  ${GREEN}✓${NC} Database directory creation works"
        ((PASSED++))
        rm -rf ./databases_test
    else
        echo -e "  ${RED}✗${NC} Cannot create database directory"
        ((FAILED++))
    fi
    echo ""
}

# Test 9: Test Python database initialization
test_database_init() {
    echo -e "${YELLOW}[TEST 9]${NC} Database Initialization Test..."
    
    python3 - <<'EOF'
import sqlite3
import os
import tempfile

temp_dir = tempfile.mkdtemp()
db_path = os.path.join(temp_dir, 'test.db')

try:
    # Test SQLite
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS test (
            id INTEGER PRIMARY KEY,
            data TEXT
        )
    ''')
    
    cursor.execute('INSERT INTO test (data) VALUES (?)', ('test_data',))
    conn.commit()
    
    cursor.execute('SELECT * FROM test')
    result = cursor.fetchone()
    
    conn.close()
    
    if result and result[1] == 'test_data':
        print("  ✓ SQLite database operations work")
        import shutil
        shutil.rmtree(temp_dir)
        exit(0)
    else:
        print("  ✗ SQLite database test failed")
        exit(1)
        
except Exception as e:
    print(f"  ✗ Database initialization failed: {e}")
    exit(1)
EOF

    if [ $? -eq 0 ]; then
        ((PASSED++))
    else
        ((FAILED++))
    fi
    echo ""
}

# Test 10: Test HTTP requests
test_http_requests() {
    echo -e "${YELLOW}[TEST 10]${NC} HTTP Request Test..."
    
    python3 - <<'EOF'
try:
    import requests
    
    # Test basic HTTP request
    response = requests.get('https://httpbin.org/get', timeout=10)
    
    if response.status_code == 200:
        print("  ✓ HTTP requests work")
        exit(0)
    else:
        print(f"  ✗ HTTP request failed: {response.status_code}")
        exit(1)
        
except requests.exceptions.Timeout:
    print("  ⚠ HTTP request timeout (network issue)")
    exit(2)
except Exception as e:
    print(f"  ✗ HTTP request failed: {e}")
    exit(1)
EOF

    result=$?
    if [ $result -eq 0 ]; then
        ((PASSED++))
    elif [ $result -eq 2 ]; then
        echo -e "  ${YELLOW}⚠${NC} Network connectivity issue"
        ((WARNINGS++))
    else
        ((FAILED++))
    fi
    echo ""
}

# Run all tests
main() {
    test_python_syntax
    test_bash_syntax
    test_python_imports
    test_tools_availability
    test_python_help
    test_file_permissions
    test_readme
    test_database_setup
    test_database_init
    test_http_requests
    
    # Summary
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}Test Summary${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}Passed:${NC}   $PASSED"
    echo -e "${RED}Failed:${NC}   $FAILED"
    echo -e "${YELLOW}Warnings:${NC} $WARNINGS"
    echo ""
    
    if [ $FAILED -eq 0 ]; then
        echo -e "${GREEN}✓ All critical tests passed!${NC}"
        echo ""
        echo -e "${BLUE}Quick Start:${NC}"
        echo "  1. Install tools: ./install_tools.sh"
        echo "  2. Update databases: ./update_databases.sh"
        echo "  3. Run scan: python3 osint_intelligence_engine.py -d example.com"
        echo ""
        exit 0
    else
        echo -e "${RED}✗ Some tests failed. Please fix issues before using.${NC}"
        echo ""
        exit 1
    fi
}

main

