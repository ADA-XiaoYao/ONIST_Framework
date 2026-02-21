#!/usr/bin/env python3
"""
高级OSINT情报收集引擎
集成SpiderFoot、Phantom、CertScope功能
支持多源情报关联分析
"""

import asyncio
import aiohttp
import json
import sys
import os
import argparse
import dns.resolver
import socket
import ssl
import whois
import requests
from datetime import datetime
from typing import Dict, List, Set
import hashlib
import re
from urllib.parse import urlparse
import concurrent.futures
import subprocess
import shodan
import censys.search

class OSINTEngine:
    def __init__(self, target: str, output_dir: str):
        self.target = target
        self.output_dir = output_dir
        self.results = {
            'domains': set(),
            'subdomains': set(),
            'ips': set(),
            'emails': set(),
            'social_media': {},
            'technologies': set(),
            'certificates': [],
            'whois_data': {},
            'dns_records': {},
            'ports': {},
            'vulnerabilities': [],
            'leaked_credentials': [],
            'github_repos': [],
            'pastebin_dumps': [],
            'shodan_data': {},
            'censys_data': {},
            'related_domains': set(),
            'phone_numbers': set(),
            'physical_addresses': set(),
            'employees': set(),
            'documents': [],
            'metadata': []
        }
        
        # API Keys (从环境变量读取)
        self.shodan_api = os.getenv('SHODAN_API_KEY', '')
        self.censys_api_id = os.getenv('CENSYS_API_ID', '')
        self.censys_api_secret = os.getenv('CENSYS_API_SECRET', '')
        self.virustotal_api = os.getenv('VIRUSTOTAL_API_KEY', '')
        self.securitytrails_api = os.getenv('SECURITYTRAILS_API_KEY', '')
        self.hunter_api = os.getenv('HUNTER_API_KEY', '')
        self.github_token = os.getenv('GITHUB_TOKEN', '')
        
        os.makedirs(output_dir, exist_ok=True)
        
    async def run_full_osint(self):
        """运行完整OSINT流程"""
        print(f"[*] 开始OSINT情报收集: {self.target}")
        
        tasks = [
            self.domain_intelligence(),
            self.subdomain_enumeration(),
            self.certificate_intelligence(),
            self.whois_intelligence(),
            self.dns_intelligence(),
            self.ip_intelligence(),
            self.email_intelligence(),
            self.social_media_intelligence(),
            self.employee_intelligence(),
            self.technology_intelligence(),
            self.port_intelligence(),
            self.vulnerability_intelligence(),
            self.dark_web_intelligence(),
            self.github_intelligence(),
            self.document_intelligence(),
            self.breach_intelligence(),
            self.threat_intelligence(),
            self.relationship_mapping()
        ]
        
        await asyncio.gather(*tasks, return_exceptions=True)
        
        # 生成关联分析
        self.correlate_intelligence()
        
        # 保存结果
        self.save_results()
        
        print(f"[✓] OSINT收集完成: {self.output_dir}")
    
    async def domain_intelligence(self):
        """域名情报收集"""
        print("[+] 域名情报收集...")
        
        # 基础域名信息
        try:
            ip = socket.gethostbyname(self.target)
            self.results['ips'].add(ip)
        except:
            pass
        
        # 反向DNS
        try:
            result = socket.gethostbyaddr(self.target)
            self.results['related_domains'].add(result[0])
        except:
            pass
        
        # 域名年龄和历史
        await self.check_domain_history()
        
    async def subdomain_enumeration(self):
        """子域名枚举 - 多源聚合"""
        print("[+] 子域名枚举...")
        
        sources = [
            self._crtsh_subdomains,
            self._certspotter_subdomains,
            self._virustotal_subdomains,
            self._securitytrails_subdomains,
            self._threatcrowd_subdomains,
            self._hackertarget_subdomains,
            self._dnsdumpster_subdomains,
            self._alienvault_subdomains,
            self._urlscan_subdomains,
            self._web_archive_subdomains
        ]
        
        results = await asyncio.gather(*[source() for source in sources], return_exceptions=True)
        
        for result in results:
            if isinstance(result, set):
                self.results['subdomains'].update(result)
    
    async def certificate_intelligence(self):
        """SSL证书情报"""
        print("[+] SSL证书分析...")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    
                    cert_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serialNumber': cert['serialNumber'],
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter'],
                        'subjectAltName': cert.get('subjectAltName', [])
                    }
                    
                    self.results['certificates'].append(cert_info)
                    
                    # 从SAN提取域名
                    for san_type, san_value in cert.get('subjectAltName', []):
                        if san_type == 'DNS':
                            self.results['subdomains'].add(san_value)
        except Exception as e:
            print(f"[!] 证书分析失败: {e}")
    
    async def whois_intelligence(self):
        """WHOIS情报"""
        print("[+] WHOIS信息收集...")
        
        try:
            w = whois.whois(self.target)
            self.results['whois_data'] = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'org': w.org,
                'registrant': w.get('registrant', 'N/A'),
                'admin': w.get('admin', 'N/A')
            }
            
            # 提取邮箱
            if w.emails:
                if isinstance(w.emails, list):
                    self.results['emails'].update(w.emails)
                else:
                    self.results['emails'].add(w.emails)
        except Exception as e:
            print(f"[!] WHOIS查询失败: {e}")
    
    async def dns_intelligence(self):
        """DNS情报收集"""
        print("[+] DNS记录分析...")
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                self.results['dns_records'][record_type] = [str(rdata) for rdata in answers]
                
                # 从TXT记录提取信息
                if record_type == 'TXT':
                    for rdata in answers:
                        txt_data = str(rdata)
                        # 提取SPF, DKIM, DMARC等
                        if 'v=spf' in txt_data:
                            self.extract_spf_ips(txt_data)
                
                # 从MX记录获取邮件服务器
                if record_type == 'MX':
                    for rdata in answers:
                        self.results['related_domains'].add(str(rdata.exchange))
            except:
                pass
    
    async def ip_intelligence(self):
        """IP情报收集"""
        print("[+] IP地址分析...")
        
        for ip in list(self.results['ips'])[:10]:  # 限制数量
            # GeoIP查询
            await self._geoip_lookup(ip)
            
            # ASN查询
            await self._asn_lookup(ip)
            
            # Shodan查询
            if self.shodan_api:
                await self._shodan_lookup(ip)
            
            # Censys查询
            if self.censys_api_id and self.censys_api_secret:
                await self._censys_lookup(ip)
    
    async def email_intelligence(self):
        """邮箱情报收集"""
        print("[+] 邮箱情报收集...")
        
        # Hunter.io API
        if self.hunter_api:
            await self._hunter_email_search()
        
        # Google Dorks for emails
        await self._google_dork_emails()
        
        # 从泄露数据库查询
        await self._check_email_breaches()
    
    async def social_media_intelligence(self):
        """社交媒体情报"""
        print("[+] 社交媒体分析...")
        
        platforms = {
            'twitter': f'https://twitter.com/{self.target.split(".")[0]}',
            'linkedin': f'https://www.linkedin.com/company/{self.target.split(".")[0]}',
            'facebook': f'https://www.facebook.com/{self.target.split(".")[0]}',
            'instagram': f'https://www.instagram.com/{self.target.split(".")[0]}',
            'github': f'https://github.com/{self.target.split(".")[0]}',
            'youtube': f'https://www.youtube.com/@{self.target.split(".")[0]}'
        }
        
        async with aiohttp.ClientSession() as session:
            for platform, url in platforms.items():
                try:
                    async with session.head(url, timeout=5) as resp:
                        if resp.status == 200:
                            self.results['social_media'][platform] = url
                except:
                    pass
    
    async def employee_intelligence(self):
        """员工信息收集"""
        print("[+] 员工信息收集...")
        
        # LinkedIn搜索
        await self._linkedin_employee_search()
        
        # GitHub组织成员
        if self.github_token:
            await self._github_org_members()
    
    async def technology_intelligence(self):
        """技术栈情报"""
        print("[+] 技术栈识别...")
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f'https://{self.target}', timeout=10) as resp:
                    headers = resp.headers
                    html = await resp.text()
                    
                    # 识别服务器
                    if 'Server' in headers:
                        self.results['technologies'].add(f"Server: {headers['Server']}")
                    
                    # 识别框架和库
                    tech_patterns = {
                        'WordPress': r'wp-content|wp-includes',
                        'Drupal': r'drupal|sites/default',
                        'Joomla': r'joomla|com_content',
                        'React': r'react|__REACT',
                        'Angular': r'ng-|angular',
                        'Vue': r'vue|v-app',
                        'jQuery': r'jquery',
                        'Bootstrap': r'bootstrap',
                        'Laravel': r'laravel',
                        'Django': r'django',
                        'Flask': r'flask'
                    }
                    
                    for tech, pattern in tech_patterns.items():
                        if re.search(pattern, html, re.I):
                            self.results['technologies'].add(tech)
        except:
            pass
    
    async def port_intelligence(self):
        """端口扫描情报"""
        print("[+] 端口扫描分析...")
        
        # 使用nmap进行端口扫描
        for ip in list(self.results['ips'])[:5]:
            try:
                result = subprocess.run(
                    ['nmap', '-sV', '-T4', '--top-ports', '1000', ip],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                self.results['ports'][ip] = result.stdout
            except:
                pass
    
    async def vulnerability_intelligence(self):
        """漏洞情报收集"""
        print("[+] 漏洞情报分析...")
        
        # CVE查询
        await self._cve_search()
        
        # Exploit-DB搜索
        await self._exploitdb_search()
    
    async def dark_web_intelligence(self):
        """暗网情报收集"""
        print("[+] 暗网/Paste站点监控...")
        
        # Pastebin监控
        await self._pastebin_search()
        
        # GitHub泄露搜索
        await self._github_leak_search()
    
    async def github_intelligence(self):
        """GitHub情报收集"""
        print("[+] GitHub代码仓库分析...")
        
        if self.github_token:
            await self._github_repo_search()
            await self._github_code_search()
    
    async def document_intelligence(self):
        """文档元数据收集"""
        print("[+] 文档元数据提取...")
        
        # Google Dorks搜索文档
        doc_types = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx']
        
        for doc_type in doc_types:
            await self._google_dork_documents(doc_type)
    
    async def breach_intelligence(self):
        """数据泄露情报"""
        print("[+] 数据泄露检查...")
        
        # Have I Been Pwned API
        await self._hibp_check()
        
        # DeHashed查询
        await self._dehashed_check()
    
    async def threat_intelligence(self):
        """威胁情报收集"""
        print("[+] 威胁情报分析...")
        
        # VirusTotal查询
        if self.virustotal_api:
            await self._virustotal_threat_check()
        
        # AlienVault OTX
        await self._alienvault_threat_check()
    
    async def relationship_mapping(self):
        """关系图谱构建"""
        print("[+] 构建实体关系图...")
        
        # 分析域名、IP、邮箱之间的关联
        relationships = {
            'domain_to_ip': {},
            'ip_to_domain': {},
            'email_to_domain': {},
            'subdomain_tree': {}
        }
        
        # 构建关系
        for subdomain in self.results['subdomains']:
            try:
                ip = socket.gethostbyname(subdomain)
                if subdomain not in relationships['domain_to_ip']:
                    relationships['domain_to_ip'][subdomain] = []
                relationships['domain_to_ip'][subdomain].append(ip)
                
                if ip not in relationships['ip_to_domain']:
                    relationships['ip_to_domain'][ip] = []
                relationships['ip_to_domain'][ip].append(subdomain)
            except:
                pass
        
        self.results['relationships'] = relationships
    
    def correlate_intelligence(self):
        """情报关联分析"""
        print("[+] 情报关联分析...")
        
        correlations = {
            'high_value_targets': [],
            'attack_surface': {},
            'risk_indicators': [],
            'intelligence_gaps': []
        }
        
        # 识别高价值目标
        for subdomain in self.results['subdomains']:
            if any(keyword in subdomain for keyword in ['admin', 'api', 'dev', 'staging', 'test', 'vpn', 'mail']):
                correlations['high_value_targets'].append(subdomain)
        
        # 攻击面分析
        correlations['attack_surface'] = {
            'total_subdomains': len(self.results['subdomains']),
            'total_ips': len(self.results['ips']),
            'exposed_ports': sum(len(ports) for ports in self.results['ports'].values()),
            'found_emails': len(self.results['emails']),
            'leaked_credentials': len(self.results['leaked_credentials'])
        }
        
        # 风险指标
        if self.results['leaked_credentials']:
            correlations['risk_indicators'].append('发现泄露凭证')
        if len(self.results['vulnerabilities']) > 0:
            correlations['risk_indicators'].append(f'发现{len(self.results["vulnerabilities"])}个漏洞')
        
        self.results['correlations'] = correlations
    
    # ==================== 辅助方法 ====================
    
    async def _crtsh_subdomains(self) -> Set[str]:
        """crt.sh子域名查询"""
        try:
            url = f'https://crt.sh/?q=%25.{self.target}&output=json'
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as resp:
                    data = await resp.json()
                    return {entry['name_value'].replace('*.', '') for entry in data}
        except:
            return set()
    
    async def _certspotter_subdomains(self) -> Set[str]:
        """Certspotter子域名查询"""
        try:
            url = f'https://api.certspotter.com/v1/issuances?domain={self.target}&include_subdomains=true&expand=dns_names'
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as resp:
                    data = await resp.json()
                    subdomains = set()
                    for entry in data:
                        subdomains.update(entry.get('dns_names', []))
                    return {d.replace('*.', '') for d in subdomains}
        except:
            return set()
    
    async def _virustotal_subdomains(self) -> Set[str]:
        """VirusTotal子域名查询"""
        if not self.virustotal_api:
            return set()
        
        try:
            url = f'https://www.virustotal.com/api/v3/domains/{self.target}/subdomains'
            headers = {'x-apikey': self.virustotal_api}
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=30) as resp:
                    data = await resp.json()
                    return {entry['id'] for entry in data.get('data', [])}
        except:
            return set()
    
    async def _securitytrails_subdomains(self) -> Set[str]:
        """SecurityTrails子域名查询"""
        if not self.securitytrails_api:
            return set()
        
        try:
            url = f'https://api.securitytrails.com/v1/domain/{self.target}/subdomains'
            headers = {'APIKEY': self.securitytrails_api}
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=30) as resp:
                    data = await resp.json()
                    return {f"{sub}.{self.target}" for sub in data.get('subdomains', [])}
        except:
            return set()
    
    async def _threatcrowd_subdomains(self) -> Set[str]:
        """ThreatCrowd子域名查询"""
        try:
            url = f'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.target}'
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as resp:
                    data = await resp.json()
                    return set(data.get('subdomains', []))
        except:
            return set()
    
    async def _hackertarget_subdomains(self) -> Set[str]:
        """HackerTarget子域名查询"""
        try:
            url = f'https://api.hackertarget.com/hostsearch/?q={self.target}'
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as resp:
                    text = await resp.text()
                    return {line.split(',')[0] for line in text.split('\n') if ',' in line}
        except:
            return set()
    
    async def _dnsdumpster_subdomains(self) -> Set[str]:
        """DNSDumpster子域名查询"""
        # 需要处理CSRF token，简化处理
        return set()
    
    async def _alienvault_subdomains(self) -> Set[str]:
        """AlienVault OTX子域名查询"""
        try:
            url = f'https://otx.alienvault.com/api/v1/indicators/domain/{self.target}/passive_dns'
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as resp:
                    data = await resp.json()
                    return {entry['hostname'] for entry in data.get('passive_dns', [])}
        except:
            return set()
    
    async def _urlscan_subdomains(self) -> Set[str]:
        """URLScan子域名查询"""
        try:
            url = f'https://urlscan.io/api/v1/search/?q=domain:{self.target}'
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as resp:
                    data = await resp.json()
                    
