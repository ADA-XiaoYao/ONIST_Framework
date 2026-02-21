#!/usr/bin/env python3
"""
GitHub高级情报收集模块
集成GitHub用户、组织、仓库的深度分析
"""

import requests
import json
import os
import sys
import argparse
from datetime import datetime
from typing import Dict, List, Set
import base64
import re
from concurrent.futures import ThreadPoolExecutor
import time

class GitHubIntelligence:
    def __init__(self, token: str = None, output_dir: str = "github_intel"):
        self.token = token or os.getenv('GITHUB_TOKEN')
        self.headers = {
            'Authorization': f'token {self.token}' if self.token else '',
            'Accept': 'application/vnd.github.v3+json'
        }
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        self.results = {
            'users': {},
            'organizations': {},
            'repositories': [],
            'commits': [],
            'secrets_found': [],
            'ssh_keys': [],
            'gpg_keys': [],
            'social_connections': {},
            'code_patterns': [],
            'leaked_data': []
        }
    
    def collect_user_intelligence(self, username: str):
        """收集GitHub用户完整情报"""
        print(f"[+] 收集用户情报: {username}")
        
        # 基础用户信息
        user_data = self._get_user_profile(username)
        if not user_data:
            print(f"[!] 用户 {username} 不存在")
            return
        
        self.results['users'][username] = user_data
        
        # 用户仓库
        repos = self._get_user_repos(username)
        self.results['repositories'].extend(repos)
        
        # SSH Keys
        ssh_keys = self._get_user_ssh_keys(username)
        self.results['ssh_keys'].extend(ssh_keys)
        
        # GPG Keys
        gpg_keys = self._get_user_gpg_keys(username)
        self.results['gpg_keys'].extend(gpg_keys)
        
        # 社交关系
        followers = self._get_user_followers(username)
        following = self._get_user_following(username)
        
        self.results['social_connections'][username] = {
            'followers': followers,
            'following': following,
            'followers_count': len(followers),
            'following_count': len(following)
        }
        
        # Gists
        gists = self._get_user_gists(username)
        
        # 贡献活动
        events = self._get_user_events(username)
        
        # 组织成员
        orgs = self._get_user_orgs(username)
        for org in orgs:
            self.collect_org_intelligence(org['login'])
        
        print(f"[✓] 用户 {username} 情报收集完成")
    
    def collect_org_intelligence(self, org_name: str):
        """收集组织情报"""
        print(f"[+] 收集组织情报: {org_name}")
        
        # 组织基础信息
        org_data = self._get_org_profile(org_name)
        if not org_data:
            return
        
        self.results['organizations'][org_name] = org_data
        
        # 组织成员
        members = self._get_org_members(org_name)
        org_data['members'] = members
        
        # 组织仓库
        repos = self._get_org_repos(org_name)
        self.results['repositories'].extend(repos)
        
        print(f"[✓] 组织 {org_name} 情报收集完成")
    
    def search_code_leaks(self, target_domain: str):
        """搜索代码泄露"""
        print(f"[+] 搜索代码泄露: {target_domain}")
        
        search_queries = [
            f'{target_domain} password',
            f'{target_domain} api_key',
            f'{target_domain} secret',
            f'{target_domain} token',
            f'{target_domain} credentials',
            f'{target_domain} private_key',
            f'{target_domain} aws_access',
            f'{target_domain} db_password',
            f'AKIA{target_domain}',  # AWS Access Key
            f'{target_domain} .env',
            f'{target_domain} config.json'
        ]
        
        for query in search_queries:
            results = self._search_code(query)
            
            for item in results:
                # 下载文件内容进行分析
                content = self._get_file_content(
                    item['repository']['full_name'],
                    item['path']
                )
                
                if content:
                    secrets = self._extract_secrets(content, item)
                    if secrets:
                        self.results['secrets_found'].extend(secrets)
        
        print(f"[✓] 发现 {len(self.results['secrets_found'])} 个潜在泄露")
    
    def analyze_repository(self, repo_full_name: str):
        """深度分析仓库"""
        print(f"[+] 分析仓库: {repo_full_name}")
        
        # 仓库信息
        repo_data = self._get_repo_info(repo_full_name)
        
        # 提交历史
        commits = self._get_repo_commits(repo_full_name)
        self.results['commits'].extend(commits)
        
        # 分析敏感文件
        sensitive_files = [
            '.env', '.env.example', 'config.json', 'config.yaml',
            'credentials.json', 'secrets.yaml', 'database.yml',
            'id_rsa', 'id_dsa', '.ssh/config', 'authorized_keys',
            'web.config', 'appsettings.json', '.aws/credentials'
        ]
        
        for file_path in sensitive_files:
            content = self._get_file_content(repo_full_name, file_path)
            if content:
                print(f"  [!] 发现敏感文件: {file_path}")
                self.results['leaked_data'].append({
                    'repo': repo_full_name,
                    'file': file_path,
                    'content': content[:500]  # 只保存前500字符
                })
        
        # Issues和Comments中的信息
        issues = self._get_repo_issues(repo_full_name)
        
        print(f"[✓] 仓库 {repo_full_name} 分析完成")
    
    def scan_commit_history(self, repo_full_name: str):
        """扫描提交历史中的敏感信息"""
        print(f"[+] 扫描提交历史: {repo_full_name}")
        
        commits = self._get_repo_commits(repo_full_name, per_page=100)
        
        sensitive_patterns = {
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'private_key': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'password': r'password[\s]*=[\s]*[\'"][^\'"]+[\'"]',
            'api_key': r'api[_-]?key[\s]*=[\s]*[\'"][^\'"]+[\'"]',
            'token': r'token[\s]*=[\s]*[\'"][^\'"]+[\'"]',
            'secret': r'secret[\s]*=[\s]*[\'"][^\'"]+[\'"]'
        }
        
        for commit in commits:
            commit_data = self._get_commit_details(repo_full_name, commit['sha'])
            
            # 检查commit message
            message = commit.get('commit', {}).get('message', '')
            for pattern_name, pattern in sensitive_patterns.items():
                if re.search(pattern, message, re.I):
                    self.results['secrets_found'].append({
                        'type': pattern_name,
                        'location': f"{repo_full_name}/commit/{commit['sha']}",
                        'message': message[:200]
                    })
        
        print(f"[✓] 提交历史扫描完成")
    
    # ==================== API调用方法 ====================
    
    def _api_request(self, endpoint: str, params: Dict = None):
        """统一API请求"""
        url = f"https://api.github.com{endpoint}"
        
        try:
            response = requests.get(
                url,
                headers=self.headers,
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 403:
                print(f"[!] API限流，等待...")
                time.sleep(60)
                return self._api_request(endpoint, params)
            else:
                print(f"[!] API请求失败: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"[!] 请求异常: {e}")
            return None
    
    def _get_user_profile(self, username: str):
        """获取用户资料"""
        data = self._api_request(f'/users/{username}')
        if data:
            return {
                'login': data.get('login'),
                'id': data.get('id'),
                'name': data.get('name'),
                'company': data.get('company'),
                'blog': data.get('blog'),
                'location': data.get('location'),
                'email': data.get('email'),
                'bio': data.get('bio'),
                'twitter_username': data.get('twitter_username'),
                'public_repos': data.get('public_repos'),
                'public_gists': data.get('public_gists'),
                'followers': data.get('followers'),
                'following': data.get('following'),
                'created_at': data.get('created_at'),
                'updated_at': data.get('updated_at')
            }
        return None
    
    def _get_user_repos(self, username: str):
        """获取用户仓库"""
        repos = []
        page = 1
        while True:
            data = self._api_request(
                f'/users/{username}/repos',
                {'page': page, 'per_page': 100}
            )
            if not data:
                break
            repos.extend(data)
            if len(data) < 100:
                break
            page += 1
        
        return [{
            'full_name': r['full_name'],
            'name': r['name'],
            'description': r.get('description'),
            'language': r.get('language'),
            'stargazers_count': r.get('stargazers_count'),
            'forks_count': r.get('forks_count'),
            'created_at': r.get('created_at'),
            'updated_at': r.get('updated_at'),
            'html_url': r.get('html_url')
        } for r in repos]
    
    def _get_user_ssh_keys(self, username: str):
        """获取用户SSH密钥"""
        data = self._api_request(f'/users/{username}/keys')
        if data:
            return [{
                'id': k['id'],
                'key': k['key'],
                'created_at': k.get('created_at')
            } for k in data]
        return []
    
    def _get_user_gpg_keys(self, username: str):
        """获取用户GPG密钥"""
        data = self._api_request(f'/users/{username}/gpg_keys')
        if data:
            return [{
                'id': k['id'],
                'key_id': k.get('key_id'),
                'raw_key': k.get('raw_key'),
                'created_at': k.get('created_at')
            } for k in data]
        return []
    
    def _get_user_followers(self, username: str):
        """获取用户关注者"""
        followers = []
        page = 1
        while True:
            data = self._api_request(
                f'/users/{username}/followers',
                {'page': page, 'per_page': 100}
            )
            if not data:
                break
            followers.extend([f['login'] for f in data])
            if len(data) < 100:
                break
            page += 1
        return followers[:1000]  # 限制数量
    
    def _get_user_following(self, username: str):
        """获取用户关注的人"""
        following = []
        page = 1
        while True:
            data = self._api_request(
                f'/users/{username}/following',
                {'page': page, 'per_page': 100}
            )
            if not data:
                break
            following.extend([f['login'] for f in data])
            if len(data) < 100:
                break
            page += 1
        return following[:1000]
    
    def _get_user_gists(self, username: str):
        """获取用户Gists"""
        data = self._api_request(f'/users/{username}/gists')
        return data if data else []
    
    def _get_user_events(self, username: str):
        """获取用户活动"""
        data = self._api_request(f'/users/{username}/events')
        return data if data else []
    
    def _get_user_orgs(self, username: str):
        """获取用户组织"""
        data = self._api_request(f'/users/{username}/orgs')
        return data if data else []
    
    def _get_org_profile(self, org_name: str):
        """获取组织资料"""
        data = self._api_request(f'/orgs/{org_name}')
        if data:
            return {
                'login': data.get('login'),
                'id': data.get('id'),
                'name': data.get('name'),
                'company': data.get('company'),
                'blog': data.get('blog'),
                'location': data.get('location'),
                'email': data.get('email'),
                'description': data.get('description'),
                'public_repos': data.get('public_repos'),
                'created_at': data.get('created_at'),
                'updated_at': data.get('updated_at')
            }
        return None
    
    def _get_org_members(self, org_name: str):
        """获取组织成员"""
        members = []
        page = 1
        while True:
            data = self._api_request(
                f'/orgs/{org_name}/members',
                {'page': page, 'per_page': 100}
            )
            if not data:
                break
            members.extend([m['login'] for m in data])
            if len(data) < 100:
                break
            page += 1
        return members
    
    def _get_org_repos(self, org_name: str):
        """获取组织仓库"""
        repos = []
        page = 1
        while True:
            data = self._api_request(
                f'/orgs/{org_name}/repos',
                {'page': page, 'per_page': 100}
            )
            if not data:
                break
            repos.extend(data)
            if len(data) < 100:
                break
            page += 1
        
        return [{
            'full_name': r['full_name'],
            'name': r['name'],
            'description': r.get('description'),
            'language': r.get('language'),
            'html_url': r.get('html_url')
        } for r in repos]
    
    def _search_code(self, query: str):
        """代码搜索"""
        results = []
        page = 1
        while page <= 10:  # 限制10页
            data = self._api_request(
                '/search/code',
                {'q': query, 'page': page, 'per_page': 100}
            )
            if not data or 'items' not in data:
                break
            results.extend(data['items'])
            if len(data['items']) < 100:
                break
            page += 1
            time.sleep(2)  # 避免限流
        return results
    
    def _get_file_content(self, repo_full_name: str, file_path: str):
        """获取文件内容"""
        data = self._api_request(f'/repos/{repo_full_name}/contents/{file_path}')
        if data and 'content' in data:
            try:
                return base64.b64decode(data['content']).decode('utf-8')
            except:
                return None
        return None
    
    def _get_repo_info(self, repo_full_name: str):
        """获取仓库信息"""
        return self._api_request(f'/repos/{repo_full_name}')
    
    def _get_repo_commits(self, repo_full_name: str, per_page: int = 30):
        """获取仓库提交"""
        data = self._api_request(
            f'/repos/{repo_full_name}/commits',
            {'per_page': per_page}
        )
        return data if data else []
    
    def _get_commit_details(self, repo_full_name: str, sha: str):
        """获取提交详情"""
        return self._api_request(f'/repos/{repo_full_name}/commits/{sha}')
    
    def _get_repo_issues(self, repo_full_name: str):
        """获取仓库Issues"""
        data = self._api_request(f'/repos/{repo_full_name}/issues')
        return data if data else []
    
    def _extract_secrets(self, content: str, item: Dict):
        """提取敏感信息"""
        secrets = []
        
        patterns = {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret_key': r'[\'"][0-9a-zA-Z/+]{40}[\'"]',
            'github_token': r'gh[pousr]_[0-9a-zA-Z]{36}',
            'slack_token': r'xox[baprs]-[0-9a-zA-Z-]{10,72}',
            'private_key': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'google_api': r'AIza[0-9A-Za-z\\-_]{35}',
            'password': r'(?:password|pwd|pass)[\s]*[=:][\s]*[\'"][^\'"]{6,}[\'"]',
            'api_key': r'(?:api[_-]?key)[\s]*[=:][\s]*[\'"][^\'"]+[\'"]',
            'database_url': r'(?:mongodb|mysql|postgresql)://[^\s]+',
            'jwt': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+'
        }
        
        for secret_type, pattern in patterns.items():
            matches = re.findall(pattern, content)
            for match in matches:
                secrets.append({
                    'type': secret_type,
                    'value': match,
                    'file': item['path'],
                    'repo': item['repository']['full_name'],
                    'url': item['html_url']
                })
        
        return secrets
    
    def save_results(self):
        """保存结果"""
        # JSON格式
        with open(f'{self.output_dir}/github_intelligence.json', 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        # 单独保存发现的秘密
        if self.results['secrets_found']:
            with open(f'{self.output_dir}/CRITICAL_SECRETS.json', 'w') as f:
                json.dump(self.results['secrets_found'], f, indent=2)
        
        # 生成报告
        self.generate_report()
        
        print(f"\n[✓] 结果已保存到: {self.output_dir}")
    
    def generate_report(self):
        """生成报告"""
        report = f"""# GitHub情报收集报告

**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 摘要统计

- **用户数量**: {len(self.results['users'])}
- **组织数量**: {len(self.results['organizations'])}
- **仓库数量**: {len(self.results['repositories'])}
- **SSH密钥**: {len(self.results['ssh_keys'])}
- **GPG密钥**: {len(self.results['gpg_keys'])}
- **发现的秘密**: {len(self.results['secrets_found'])} ⚠️
- **泄露数据**: {len(self.results['leaked_data'])} ⚠️

## ⚠️ 严重发现

### 泄露的秘密和凭证

{''.join([f"- **{s['type']}**: {s.get('file', 'N/A')} - {s.get('repo', 'N/A')}\n" for s in self.results['secrets_found'][:20]])}

### 敏感文件

{''.join([f"- **{d['file']}** in {d['repo']}\n" for d in self.results['leaked_data'][:20]])}

## 用户信息

{''.join([f"### {username}\n- **真名**: {user.get('name', 'N/A')}\n- **邮箱**: {user.get('email', 'N/A')}\n- **公司**: {user.get('company', 'N/A')}\n- **位置**: {user.get('location', 'N/A')}\n- **公开仓库**: {user.get('public_repos', 0)}\n\n" for username, user in list(self.results['users'].items())[:10]])}

## 建议措施

1. **立即轮换所有泄露的凭证和密钥**
2. 从GitHub删除包含敏感信息的提交历史
3. 启用GitHub Secret Scanning
4. 实施pre-commit hooks防止秘密提交
5. 定期审计组织成员和仓库权限

"""
        
        with open(f'{self.output_dir}/GITHUB_REPORT.md', 'w') as f:
            f.write(report)


def main():
    parser = argparse.ArgumentParser(description='GitHub Advanced Intelligence Collection')
    parser.add_argument('-u', '--user', help='GitHub username')
    parser.add_argument('-o', '--org', help='GitHub organization')
    parser.add_argument('-r', '--repo', help='Repository full name (owner/repo)')
    parser.add_argument('-d', '--domain', help='Search domain-related leaks')
    parser.add_argument('-t', '--token', help='GitHub Personal Access Token')
    parser.add_argument('--output', default='github_intel', help='Output directory')
    
    args = parser.parse_args()
    
    if not any([args.user, args.org, args.repo, args.domain]):
        parser.print_help()
        sys.exit(1)
    
    intel = GitHubIntelligence(args.token, args.output)
    
    if args.user:
        intel.collect_user_intelligence(args.user)
    
    if args.org:
        intel.collect_org_intelligence(args.org)
    
    if args.repo:
        intel.analyze_repository(args.repo)
        intel.scan_commit_history(args.repo)
    
    if args.domain:
        intel.search_code_leaks(args.domain)
    
    intel.save_results()


if __name__ == '__main__':
    main()
              
