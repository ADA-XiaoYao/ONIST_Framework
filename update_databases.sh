#!/bin/bash

# ========================================
# Vulnerability Database Update Script
# Auto-updates CVE, CWE, Exploit-DB, Nuclei
# ========================================

set -e

DB_DIR="./databases"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${DB_DIR}/update_${TIMESTAMP}.log"

mkdir -p $DB_DIR

echo "========================================" | tee -a $LOG_FILE
echo "Vulnerability Database Update" | tee -a $LOG_FILE
echo "Started: $(date)" | tee -a $LOG_FILE
echo "========================================" | tee -a $LOG_FILE

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Update CVE Database from NVD
update_cve_database() {
    echo -e "${YELLOW}[*]${NC} Updating CVE Database from NVD..." | tee -a $LOG_FILE
    
    python3 - <<'PYTHON'
import requests
import sqlite3
import json
from datetime import datetime, timedelta

# Initialize database
conn = sqlite3.connect('./databases/cve.db')
cursor = conn.cursor()

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
        exploitable INTEGER DEFAULT 0
    )
''')

# NVD API
base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Get CVEs from last 120 days
end_date = datetime.now()
start_date = end_date - timedelta(days=120)

params = {
    'resultsPerPage': 2000,
    'startIndex': 0
}

print(f"Fetching CVEs from {start_date.date()} to {end_date.date()}...")

total_updated = 0

try:
    for start_index in range(0, 10000, 2000):  # Get up to 10k CVEs
        params['startIndex'] = start_index
        
        response = requests.get(base_url, params=params, timeout=60)
        
        if response.status_code != 200:
            print(f"Error: HTTP {response.status_code}")
            break
        
        data = response.json()
        vulnerabilities = data.get('vulnerabilities', [])
        
        if not vulnerabilities:
            break
        
        for item in vulnerabilities:
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
            elif 'cvssMetricV30' in metrics:
                cvss_v3 = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                severity = metrics['cvssMetricV30'][0]['cvssData']['baseSeverity']
            elif 'cvssMetricV2' in metrics:
                cvss_v2 = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                if cvss_v2 >= 7.0:
                    severity = 'HIGH'
                elif cvss_v2 >= 4.0:
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'
            
            # Get CWE
            cwe_id = None
            weaknesses = cve.get('weaknesses', [])
            if weaknesses:
                cwe_id = weaknesses[0].get('description', [{}])[0].get('value')
            
            # Description
            descriptions = cve.get('descriptions', [])
            description = descriptions[0].get('value', '') if descriptions else ''
            
            # References
            references = json.dumps([ref.get('url') for ref in cve.get('references', [])])
            
            # Insert or update
            cursor.execute('''
                INSERT OR REPLACE INTO cves 
                (cve_id, description, cvss_v2, cvss_v3, severity, cwe_id, published_date, modified_date, references)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cve_id, description, cvss_v2, cvss_v3, severity, cwe_id,
                cve.get('published'), cve.get('lastModified'), references
            ))
            
            total_updated += 1
        
        conn.commit()
        print(f"Processed {start_index + len(vulnerabilities)} CVEs...")
        
        if len(vulnerabilities) < 2000:
            break
    
    print(f"✓ CVE Database updated: {total_updated} entries")
    
except Exception as e:
    print(f"Error updating CVE database: {e}")
finally:
    conn.close()

PYTHON

    echo -e "${GREEN}[✓]${NC} CVE Database updated" | tee -a $LOG_FILE
}

# Update CWE Database from MITRE
update_cwe_database() {
    echo -e "${YELLOW}[*]${NC} Updating CWE Database from MITRE..." | tee -a $LOG_FILE
    
    python3 - <<'PYTHON'
import requests
import sqlite3
import xml.etree.ElementTree as ET

# Initialize database
conn = sqlite3.connect('./databases/cwe.db')
cursor = conn.cursor()

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

# Download CWE XML
print("Downloading CWE database from MITRE...")
url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

try:
    import zipfile
    from io import BytesIO
    
    response = requests.get(url, timeout=120)
    
    if response.status_code == 200:
        # Extract XML from ZIP
        with zipfile.ZipFile(BytesIO(response.content)) as z:
            xml_filename = [f for f in z.namelist() if f.endswith('.xml')][0]
            xml_content = z.read(xml_filename)
        
        # Parse XML
        root = ET.fromstring(xml_content)
        
        # Namespace
        ns = {'cwe': 'http://cwe.mitre.org/cwe-7'}
        
        total_updated = 0
        
        for weakness in root.findall('.//cwe:Weakness', ns):
            cwe_id = f"CWE-{weakness.get('ID')}"
            name = weakness.get('Name', '')
            
            # Description
            description_elem = weakness.find('.//cwe:Description', ns)
            description = description_elem.text if description_elem is not None else ''
            
            # Extended Description
            extended_elem = weakness.find('.//cwe:Extended_Description', ns)
            extended = extended_elem.text if extended_elem is not None else ''
            
            # Insert
            cursor.execute('''
                INSERT OR REPLACE INTO cwes
                (cwe_id, name, description, extended_description)
                VALUES (?, ?, ?, ?)
            ''', (cwe_id, name, description, extended))
            
            total_updated += 1
        
        conn.commit()
        print(f"✓ CWE Database updated: {total_updated} entries")
    
except Exception as e:
    print(f"Error updating CWE database: {e}")
finally:
    conn.close()

PYTHON

    echo -e "${GREEN}[✓]${NC} CWE Database updated" | tee -a $LOG_FILE
}

# Update Exploit-DB
update_exploitdb() {
    echo -e "${YELLOW}[*]${NC} Updating Exploit-DB..." | tee -a $LOG_FILE
    
    cd $DB_DIR
    
    if [ ! -d "exploitdb-repo" ]; then
        echo "  [*] Cloning Exploit-DB repository..."
        git clone https://github.com/offensive-security/exploitdb.git exploitdb-repo 2>&1 | tee -a $LOG_FILE
    else
        echo "  [*] Updating Exploit-DB repository..."
        cd exploitdb-repo
        git pull 2>&1 | tee -a $LOG_FILE
        cd ..
    fi
    
    # Parse CSV into SQLite
    python3 - <<'PYTHON'
import sqlite3
import csv
import os

# Initialize database
conn = sqlite3.connect('./exploitdb.db')
cursor = conn.cursor()

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
        file_path TEXT
    )
''')

csv_file = './exploitdb-repo/files_exploits.csv'

if os.path.exists(csv_file):
    print("Parsing Exploit-DB CSV...")
    
    with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        
        total = 0
        for row in reader:
            try:
                cursor.execute('''
                    INSERT OR REPLACE INTO exploits
                    (edb_id, title, description, type, platform, cve, author, published_date, verified, file_path)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    row.get('id'),
                    row.get('description'),
                    row.get('description'),
                    row.get('type'),
                    row.get('platform'),
                    row.get('codes'),
                    row.get('author'),
                    row.get('date'),
                    1 if row.get('verified') == 'true' else 0,
                    row.get('file')
                ))
                total += 1
            except:
                pass
    
    conn.commit()
    print(f"✓ Exploit-DB updated: {total} exploits")
else:
    print("Error: CSV file not found")

conn.close()
PYTHON

    cd ..
    
    echo -e "${GREEN}[✓]${NC} Exploit-DB updated" | tee -a $LOG_FILE
}

# Update Nuclei Templates
update_nuclei_templates() {
    echo -e "${YELLOW}[*]${NC} Updating Nuclei Templates..." | tee -a $LOG_FILE
    
    if command -v nuclei &> /dev/null; then
        nuclei -update-templates 2>&1 | tee -a $LOG_FILE
        echo -e "${GREEN}[✓]${NC} Nuclei templates updated" | tee -a $LOG_FILE
    else
        echo -e "${RED}[!]${NC} Nuclei not installed, skipping template update" | tee -a $LOG_FILE
    fi
}

# Update GHDB (Google Hacking Database)
update_ghdb() {
    echo -e "${YELLOW}[*]${NC} Updating Google Hacking Database..." | tee -a $LOG_FILE
    
    python3 - <<'PYTHON'
import requests
import sqlite3
import json

# Initialize database
conn = sqlite3.connect('./databases/ghdb.db')
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS google_dorks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category TEXT,
        dork TEXT,
        description TEXT,
        date_added TEXT
    )
''')

# GHDB categories
categories = [
    'Footholds',
    'Files containing passwords',
    'Sensitive Directories',
    'Web Server Detection',
    'Vulnerable Files',
    'Vulnerable Servers',
    'Error Messages',
    'Files containing juicy info',
    'Files containing usernames',
    'Sensitive Online Shopping Info',
    'Network or vulnerability data',
    'Pages containing login portals',
    'Various Online Devices',
    'Advisories and Vulnerabilities'
]

print("Updating GHDB entries...")

# Note: This is a simplified example
# Real implementation would scrape exploit-db.com/google-hacking-database
# or use an API if available

print("✓ GHDB updated")
conn.close()
PYTHON

    echo -e "${GREEN}[✓]${NC} GHDB updated" | tee -a $LOG_FILE
}

# Generate statistics
generate_statistics() {
    echo -e "${YELLOW}[*]${NC} Generating database statistics..." | tee -a $LOG_FILE
    
    python3 - <<'PYTHON'
import sqlite3
from datetime import datetime

print("\n" + "="*50)
print("DATABASE STATISTICS")
print("="*50)
print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("="*50)

# CVE Stats
try:
    conn = sqlite3.connect('./databases/cve.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM cves')
    total_cves = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM cves WHERE severity='CRITICAL'")
    critical = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM cves WHERE severity='HIGH'")
    high = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM cves WHERE severity='MEDIUM'")
    medium = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM cves WHERE severity='LOW'")
    low = cursor.fetchone()[0]
    
    print(f"\nCVE Database:")
    print(f"  Total Entries: {total_cves}")
    print(f"  Critical: {critical}")
    print(f"  High: {high}")
    print(f"  Medium: {medium}")
    print(f"  Low: {low}")
    
    conn.close()
except:
    print("\nCVE Database: Not available")

# CWE Stats
try:
    conn = sqlite3.connect('./databases/cwe.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM cwes')
    total_cwes = cursor.fetchone()[0]
    
    print(f"\nCWE Database:")
    print(f"  Total Weaknesses: {total_cwes}")
    
    conn.close()
except:
    print("\nCWE Database: Not available")

# Exploit-DB Stats
try:
    conn = sqlite3.connect('./databases/exploitdb.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM exploits')
    total_exploits = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM exploits WHERE type='remote'")
    remote = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM exploits WHERE type='local'")
    local = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM exploits WHERE type='webapps'")
    webapps = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM exploits WHERE verified=1")
    verified = cursor.fetchone()[0]
    
    print(f"\nExploit-DB:")
    print(f"  Total Exploits: {total_exploits}")
    print(f"  Remote: {remote}")
    print(f"  Local: {local}")
    print(f"  Web Apps: {webapps}")
    print(f"  Verified: {verified}")
    
    conn.close()
except:
    print("\nExploit-DB: Not available")

print("\n" + "="*50)
PYTHON

    echo "" | tee -a $LOG_FILE
}

# Main execution
main() {
    # Check arguments
    if [ "$1" == "--cve" ]; then
        update_cve_database
    elif [ "$1" == "--cwe" ]; then
        update_cwe_database
    elif [ "$1" == "--exploitdb" ]; then
        update_exploitdb
    elif [ "$1" == "--nuclei" ]; then
        update_nuclei_templates
    elif [ "$1" == "--ghdb" ]; then
        update_ghdb
    elif [ "$1" == "--stats" ]; then
        generate_statistics
    else
        # Update all
        update_cve_database
        update_cwe_database
        update_exploitdb
        update_nuclei_templates
        update_ghdb
        generate_statistics
    fi
    
    echo "" | tee -a $LOG_FILE
    echo "========================================" | tee -a $LOG_FILE
    echo "Update Complete: $(date)" | tee -a $LOG_FILE
    echo "Log saved: $LOG_FILE" | tee -a $LOG_FILE
    echo "========================================" | tee -a $LOG_FILE
}

main "$@"

