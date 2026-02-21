#!/usr/bin/env python3
"""
Automated Vulnerability Hunter
Integrates CVE, CWE, Exploit-DB, and custom vulnerability databases
Auto-exploitation capabilities with Metasploit integration
"""

import json
import requests
import sqlite3
import os
import sys
import argparse
import subprocess
from datetime import datetime
from typing import Dict, List, Set
import concurrent.futures
import xml.etree.ElementTree as ET

class VulnerabilityHunter:
    def __init__(self, config_file='config.json'):
        self.load_config(config_file)
        self.init_databases()
        
        self.findings = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        self.exploited = []
        self.shells = []
        
    def load_config(self, config_file):
        """Load configuration"""
        default_config = {
            'databases': {
                'cve_db': './databases/cve.db',
                'cwe_db': './databases/cwe.db',
                'exploitdb': './databases/exploitdb.db',
                'custom_db': './databases/custom.db'
            },
            'exploitation': {
                'auto_exploit': False,
                'metasploit': True,
                'payload_type': 'reverse_shell',
                'lhost': '10.0.0.1',
                'lport': 4444
            },
            'scan_options': {
                'threads': 50,
                'timeout': 30,
                'verify_ssl': False
            }
        }
        
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
        
        self.config = default_config
        
    def init_databases(self):
        """Initialize vulnerability databases"""
        print("[*] Initializing vulnerability databases...")
        
        # CVE Database
        self.cve_db = sqlite3.connect(self.config['databases']['cve_db'])
        self.init_cve_table()
        
        # CWE Database
        self.cwe_db = sqlite3.connect(self.config['databases']['cwe_db'])
        self.init_cwe_table()
        
        # Exploit-DB
        self.exploitdb = sqlite3.connect(self.config['databases']['exploitdb'])
        self.init_exploitdb_table()
        
        # Custom exploits
        self.custom_db = sqlite3.connect(self.config['databases']['custom_db'])
        self.init_custom_table()
        
        print("[✓] Databases initialized")
        
    def init_cve_table(self):
        """Initialize CVE database table"""
        cursor = self.cve_db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                cvss_v2 REAL,
                cvss_v3 REAL,
                severity TEXT,
                cwe_id TEXT,
                published_date TEXT,
                modified_date TEXT,
                references TEXT,
                exploitable INTEGER DEFAULT 0,
                exploit_available INTEGER DEFAULT 0
            )
        ''')
        self.cve_db.commit()
        
    def init_cwe_table(self):
        """Initialize CWE database table"""
        cursor = self.cwe_db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cwes (
                cwe_id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                extended_description TEXT,
                category TEXT,
                likelihood TEXT,
                severity TEXT,
                detection_methods TEXT,
                mitigation TEXT,
                examples TEXT
            )
        ''')
        self.cwe_db.commit()
        
    def init_exploitdb_table(self):
        """Initialize Exploit-DB table"""
        cursor = self.exploitdb.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS exploits (
                edb_id INTEGER PRIMARY KEY,
                title TEXT,
                description TEXT,
                type TEXT,
                platform TEXT,
                cve TEXT,
                author TEXT,
                published_date TEXT,
                verified INTEGER DEFAULT 0,
                exploit_code TEXT,
                file_path TEXT
            )
        ''')
        self.exploitdb.commit()
        
    def init_custom_table(self):
        """Initialize custom exploits table"""
        cursor = self.custom_db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS custom_exploits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                description TEXT,
                cve TEXT,
                type TEXT,
                target_service TEXT,
                target_version TEXT,
                reliability INTEGER,
                exploit_code TEXT,
                payload_templates TEXT,
                evasion_techniques TEXT,
                created_date TEXT
            )
        ''')
        self.custom_db.commit()
    
    def update_cve_database(self):
        """Update CVE database from NVD"""
        print("[*] Updating CVE database from NVD...")
        
        # NVD API endpoint
        nvd_api = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        try:
            # Get recent CVEs (last 120 days)
            response = requests.get(
                nvd_api,
                params={'resultsPerPage': 2000, 'lastModStartDate': '2024-01-01T00:00:00.000'},
                timeout=60
            )
            
            if response.status_code == 200:
                data = response.json()
                
                cursor = self.cve_db.cursor()
                
                for item in data.get('vulnerabilities', []):
                    cve = item.get('cve', {})
                    cve_id = cve.get('id')
                    
                    # Extract metrics
                    metrics = cve.get('metrics', {})
                    cvss_v3 = None
                    cvss_v2 = None
                    severity = 'UNKNOWN'
                    
                    if 'cvssMetricV31' in metrics:
                        cvss_v3 = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                        severity = metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
                    elif 'cvssMetricV2' in metrics:
                        cvss_v2 = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                    
                    # Get CWE
                    cwe_id = None
                    weaknesses = cve.get('weaknesses', [])
                    if weaknesses:
                        cwe_id = weaknesses[0].get('description', [{}])[0].get('value')
                    
                    # Description
                    descriptions = cve.get('descriptions', [])
                    description = descriptions[0].get('value', '') if descriptions else ''
                    
                    # Insert or update
                    cursor.execute('''
                        INSERT OR REPLACE INTO cves 
                        (cve_id, description, cvss_v2, cvss_v3, severity, cwe_id, published_date, modified_date)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        cve_id, description, cvss_v2, cvss_v3, severity, cwe_id,
                        cve.get('published'), cve.get('lastModified')
                    ))
                
                self.cve_db.commit()
                print(f"[✓] Updated {len(data.get('vulnerabilities', []))} CVEs")
                
        except Exception as e:
            print(f"[!] Error updating CVE database: {e}")
    
    def update_exploitdb(self):
        """Update Exploit-DB database"""
        print("[*] Updating Exploit-DB database...")
        
        try:
            # Clone or update exploit-db repository
            exploitdb_path = "./databases/exploitdb-repo"
            
            if not os.path.exists(exploitdb_path):
                subprocess.run([
                    'git', 'clone', 
                    'https://github.com/offensive-security/exploitdb.git',
                    exploitdb_path
                ])
            else:
                subprocess.run(['git', 'pull'], cwd=exploitdb_path)
            
            # Parse files.csv
            csv_file = os.path.join(exploitdb_path, 'files_exploits.csv')
            
            if os.path.exists(csv_file):
                cursor = self.exploitdb.cursor()
                
                with open(csv_file, 'r', encoding='utf-8') as f:
                    import csv
                    reader = csv.DictReader(f)
                    
                    for row in reader:
                        cursor.execute('''
                            INSERT OR REPLACE INTO exploits
                            (edb_id, title, description, type, platform, cve, author, published_date, file_path)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            row.get('id'),
                            row.get('description'),
                            row.get('description'),
                            row.get('type'),
                            row.get('platform'),
                            row.get('codes'),
                            row.get('author'),
                            row.get('date'),
                            row.get('file')
                        ))
                
                self.exploitdb.commit()
                print("[✓] Exploit-DB updated")
                
        except Exception as e:
            print(f"[!] Error updating Exploit-DB: {e}")
    
    def scan_target(self, target, reconnaissance_data=None):
        """
        Scan target for vulnerabilities
        
        Args:
            target: Target URL or host
            reconnaissance_data: Optional reconnaissance data (from recon_master)
        """
        print(f"[*] Scanning target: {target}")
        
        # Technology detection
        technologies = self.detect_technologies(target, reconnaissance_data)
        print(f"[*] Detected technologies: {', '.join(technologies)}")
        
        # CVE matching
        cves = self.match_cves(technologies)
        print(f"[*] Found {len(cves)} potential CVEs")
        
        # CWE pattern detection
        cwes = self.detect_cwe_patterns(target)
        print(f"[*] Found {len(cwes)} CWE patterns")
        
        # Web vulnerability testing
        web_vulns = self.test_web_vulnerabilities(target)
        print(f"[*] Found {len(web_vulns)} web vulnerabilities")
        
        # Compile findings
        all_findings = cves + cwes + web_vulns
        
        # Categorize by severity
        for finding in all_findings:
            severity = finding.get('severity', 'info').lower()
            if severity in self.findings:
                self.findings[severity].append(finding)
        
        print(f"[✓] Scan complete: {len(all_findings)} vulnerabilities found")
        
        return all_findings
    
    def detect_technologies(self, target, recon_data=None):
        """Detect technologies used by target"""
        technologies = []
        
        if recon_data and 'technologies' in recon_data:
            technologies = recon_data['technologies']
        else:
            # Basic detection via HTTP headers and content
            try:
                response = requests.get(target, timeout=10, verify=False)
                
                # Server header
                server = response.headers.get('Server', '')
                if server:
                    technologies.append(server)
                
                # X-Powered-By
                powered_by = response.headers.get('X-Powered-By', '')
                if powered_by:
                    technologies.append(powered_by)
                
                # Content analysis
                content = response.text.lower()
                
                tech_signatures = {
                    'wordpress': ['wp-content', 'wp-includes'],
                    'drupal': ['drupal', 'sites/default'],
                    'joomla': ['joomla', 'com_content'],
                    'apache': ['apache'],
                    'nginx': ['nginx'],
                    'php': ['php'],
                    'asp.net': ['asp.net', '__viewstate'],
                    'react': ['react', '__react'],
                    'angular': ['ng-', 'angular'],
                    'vue': ['vue', 'v-app']
                }
                
                for tech, signatures in tech_signatures.items():
                    if any(sig in content or sig in server.lower() for sig in signatures):
                        technologies.append(tech)
                        
            except:
                pass
        
        return list(set(technologies))
    
    def match_cves(self, technologies):
        """Match CVEs based on detected technologies"""
        cves = []
        
        cursor = self.cve_db.cursor()
        
        for tech in technologies:
            # Search CVE database
            cursor.execute('''
                SELECT cve_id, description, cvss_v3, cvss_v2, severity, cwe_id
                FROM cves
                WHERE description LIKE ?
                ORDER BY cvss_v3 DESC, cvss_v2 DESC
                LIMIT 100
            ''', (f'%{tech}%',))
            
            for row in cursor.fetchall():
                cve_id, desc, cvss_v3, cvss_v2, severity, cwe_id = row
                
                # Check if exploit available
                exploit = self.find_exploit(cve_id)
                
                cves.append({
                    'type': 'CVE',
                    'id': cve_id,
                    'description': desc,
                    'cvss_v3': cvss_v3,
                    'cvss_v2': cvss_v2,
                    'severity': severity or 'UNKNOWN',
                    'cwe': cwe_id,
                    'technology': tech,
                    'exploit_available': bool(exploit),
                    'exploit': exploit
                })
        
        return cves
    
    def find_exploit(self, cve_id):
        """Find exploit for CVE"""
        # Search Exploit-DB
        cursor = self.exploitdb.cursor()
        cursor.execute('''
            SELECT edb_id, title, type, platform, file_path
            FROM exploits
            WHERE cve LIKE ?
            ORDER BY verified DESC
            LIMIT 1
        ''', (f'%{cve_id}%',))
        
        result = cursor.fetchone()
        if result:
            return {
                'source': 'exploitdb',
                'edb_id': result[0],
                'title': result[1],
                'type': result[2],
                'platform': result[3],
                'file_path': result[4]
            }
        
        # Search custom database
        cursor = self.custom_db.cursor()
        cursor.execute('''
            SELECT id, name, type, exploit_code
            FROM custom_exploits
            WHERE cve = ?
            ORDER BY reliability DESC
            LIMIT 1
        ''', (cve_id,))
        
        result = cursor.fetchone()
        if result:
            return {
                'source': 'custom',
                'id': result[0],
                'name': result[1],
                'type': result[2],
                'code': result[3]
            }
        
        return None
    
    def detect_cwe_patterns(self, target):
        """Detect CWE weakness patterns"""
        patterns = []
        
        # Implement CWE pattern detection
        # This is a simplified example
        
        try:
            response = requests.get(target, timeout=10, verify=False)
            
            # Check for common weaknesses
            
            # CWE-89: SQL Injection
            if self.test_sqli(target):
                patterns.append({
                    'type': 'CWE',
                    'id': 'CWE-89',
                    'name': 'SQL Injection',
                    'severity': 'CRITICAL',
                    'description': 'Target is vulnerable to SQL injection'
                })
            
            # CWE-79: XSS
            if self.test_xss(target):
                patterns.append({
                    'type': 'CWE',
                    'id': 'CWE-79',
                    'name': 'Cross-Site Scripting (XSS)',
                    'severity': 'HIGH',
                    'description': 'Target is vulnerable to XSS'
                })
            
            # CWE-918: SSRF
            if self.test_ssrf(target):
                patterns.append({
                    'type': 'CWE',
                    'id': 'CWE-918',
                    'name': 'Server-Side Request Forgery (SSRF)',
                    'severity': 'HIGH',
                    'description': 'Target is vulnerable to SSRF'
                })
            
            # Add more CWE checks...
            
        except:
            pass
        
        return patterns
    
    def test_web_vulnerabilities(self, target):
        """Test for web vulnerabilities"""
        vulns = []
        
        # XSS
        if self.test_xss(target):
            vulns.append({
                'type': 'XSS',
                'severity': 'HIGH',
                'description': 'Cross-Site Scripting vulnerability detected',
                'url': target
            })
        
        # SQL Injection
        if self.test_sqli(target):
            vulns.append({
                'type': 'SQLi',
                'severity': 'CRITICAL',
                'description': 'SQL Injection vulnerability detected',
                'url': target
            })
        
        # SSRF
        if self.test_ssrf(target):
            vulns.append({
                'type': 'SSRF',
                'severity': 'HIGH',
                'description': 'Server-Side Request Forgery detected',
                'url': target
            })
        
        # Add more tests...
        
        return vulns
    
    def test_xss(self, target):
        """Test for XSS"""
        payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "';alert(1);//"
        ]
        
        try:
            for payload in payloads:
                if '?' in target:
                    test_url = target + '&xss=' + payload
                else:
                    test_url = target + '?xss=' + payload
                
                response = requests.get(test_url, timeout=5, verify=False)
                if payload in response.text:
                    return True
        except:
            pass
        
        return False
    
    def test_sqli(self, target):
        """Test for SQL Injection"""
        payloads = ["'", "1' OR '1'='1", "' OR '1'='1' --"]
        
        try:
            baseline = requests.get(target, timeout=5, verify=False)
            
            for payload in payloads:
                if '?' in target:
                    test_url = target + '&id=' + payload
                else:
                    test_url = target + '?id=' + payload
                
                response = requests.get(test_url, timeout=5, verify=False)
                
                # Check for SQL errors
                sql_errors = ['sql', 'mysql', 'sqlite', 'postgresql', 'oracle', 'syntax error']
                if any(error in response.text.lower() for error in sql_errors):
                    return True
        except:
            pass
        
        return False
    
    def test_ssrf(self, target):
        """Test for SSRF"""
        # Simplified SSRF test
        ssrf_payloads = [
            'http://169.254.169.254/latest/meta-data/',
            'http://localhost/admin',
            'http://127.
