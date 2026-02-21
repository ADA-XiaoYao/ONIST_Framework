#!/bin/bash

# ========================================
# 高级DNS枚举脚本
# 多种技术组合深度挖掘子域名
# ========================================

set -e

TARGET=""
OUTPUT_DIR="dns_enum_$(date +%Y%m%d_%H%M%S)"
THREADS=50
WORDLIST="$HOME/wordlists/dns-top1m.txt"
RESOLVERS="$HOME/wordlists/resolvers.txt"

# 参数解析
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--domain)
            TARGET="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -t|--threads)
            THREADS="$2"
            shift 2
            ;;
        -w|--wordlist)
            WORDLIST="$2"
            shift 2
            ;;
        -r|--resolvers)
            RESOLVERS="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

if [ -z "$TARGET" ]; then
    echo "Usage: $0 -d example.com [-o output_dir] [-t threads] [-w wordlist] [-r resolvers]"
    exit 1
fi

mkdir -p $OUTPUT_DIR

echo "======================================="
echo "高级DNS枚举"
echo "目标: $TARGET"
echo "输出: $OUTPUT_DIR"
echo "======================================="

# 1. 被动DNS收集
echo "[+] 被动DNS收集..."

# crt.sh
echo "  [*] crt.sh..."
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > $OUTPUT_DIR/crtsh.txt

# Certspotter
echo "  [*] Certspotter..."
curl -s "https://api.certspotter.com/v1/issuances?domain=$TARGET&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' | sed 's/\*\.//g' | sort -u > $OUTPUT_DIR/certspotter.txt

# HackerTarget
echo "  [*] HackerTarget..."
curl -s "https://api.hackertarget.com/hostsearch/?q=$TARGET" | awk -F',' '{print $1}' | sort -u > $OUTPUT_DIR/hackertarget.txt

# ThreatCrowd
echo "  [*] ThreatCrowd..."
curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$TARGET" | jq -r '.subdomains[]' 2>/dev/null | sort -u > $OUTPUT_DIR/threatcrowd.txt

# AlienVault
echo "  [*] AlienVault OTX..."
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$TARGET/passive_dns" | jq -r '.passive_dns[].hostname' 2>/dev/null | sort -u > $OUTPUT_DIR/alienvault.txt

# RapidDNS
echo "  [*] RapidDNS..."
curl -s "https://rapiddns.io/subdomain/$TARGET?full=1" | grep -oP '([a-zA-Z0-9.-]+\.'$TARGET')' | sort -u > $OUTPUT_DIR/rapiddns.txt

# DNSDumpster (需要解析HTML)
echo "  [*] DNSDumpster..."
curl -s "https://dnsdumpster.com/" > /tmp/csrf.html
CSRF_TOKEN=$(grep csrfmiddlewaretoken /tmp/csrf.html | head -1 | grep -oP "value='\K[^']+")
CSRF_COOKIE=$(curl -s -c - "https://dnsdumpster.com/" | grep csrftoken | awk '{print $7}')
curl -s "https://dnsdumpster.com/" \
    -H "Cookie: csrftoken=$CSRF_COOKIE" \
    --data "csrfmiddlewaretoken=$CSRF_TOKEN&targetip=$TARGET" \
    | grep -oP '([a-zA-Z0-9.-]+\.'$TARGET')' | sort -u > $OUTPUT_DIR/dnsdumpster.txt

# 合并被动结果
cat $OUTPUT_DIR/{crtsh,certspotter,hackertarget,threatcrowd,alienvault,rapiddns,dnsdumpster}.txt 2>/dev/null | sort -u > $OUTPUT_DIR/passive_all.txt

echo "[✓] 被动收集完成: $(wc -l < $OUTPUT_DIR/passive_all.txt) 个子域名"

# 2. 主动DNS枚举
echo "[+] 主动DNS枚举..."

# Subfinder
echo "  [*] Subfinder..."
subfinder -d $TARGET -all -silent -o $OUTPUT_DIR/subfinder.txt

# Amass枚举
echo "  [*] Amass枚举..."
amass enum -passive -d $TARGET -o $OUTPUT_DIR/amass_passive.txt
amass enum -active -d $TARGET -o $OUTPUT_DIR/amass_active.txt -brute -w $WORDLIST

# Assetfinder
echo "  [*] Assetfinder..."
assetfinder --subs-only $TARGET > $OUTPUT_DIR/assetfinder.txt

# Findomain
if command -v findomain &> /dev/null; then
    echo "  [*] Findomain..."
    findomain -t $TARGET -u $OUTPUT_DIR/findomain.txt
fi

# 合并主动结果
cat $OUTPUT_DIR/{subfinder,amass_passive,amass_active,assetfinder,findomain}.txt 2>/dev/null | sort -u > $OUTPUT_DIR/active_all.txt

echo "[✓] 主动枚举完成: $(wc -l < $OUTPUT_DIR/active_all.txt) 个子域名"

# 3. DNS爆破
echo "[+] DNS爆破..."

# 合并所有已知子域名
cat $OUTPUT_DIR/{passive_all,active_all}.txt | sort -u > $OUTPUT_DIR/all_discovered.txt

# 提取唯一前缀用于变异
cat $OUTPUT_DIR/all_discovered.txt | sed "s/\.$TARGET//" | sort -u > $OUTPUT_DIR/prefixes.txt

# Shuffledns爆破
if command -v shuffledns &> /dev/null; then
    echo "  [*] Shuffledns..."
    shuffledns -d $TARGET -w $WORDLIST -r $RESOLVERS -o $OUTPUT_DIR/shuffledns.txt -t $THREADS
fi

# Puredns爆破
if command -v puredns &> /dev/null; then
    echo "  [*] Puredns..."
    puredns bruteforce $WORDLIST $TARGET -r $RESOLVERS -w $OUTPUT_DIR/puredns.txt
fi

# Massdns爆破
if command -v massdns &> /dev/null; then
    echo "  [*] Massdns..."
    
    # 生成爆破列表
    while read prefix; do
        echo "$prefix.$TARGET"
    done < <(cat $WORDLIST | head -50000) > /tmp/massdns_input.txt
    
    massdns -r $RESOLVERS -t A -o S /tmp/massdns_input.txt | awk '{print $1}' | sed 's/\.$//' | sort -u > $OUTPUT_DIR/massdns.txt
    rm /tmp/massdns_input.txt
fi

# 合并爆破结果
cat $OUTPUT_DIR/{shuffledns,puredns,massdns}.txt 2>/dev/null | sort -u > $OUTPUT_DIR/bruteforce_all.txt

echo "[✓] DNS爆破完成: $(wc -l < $OUTPUT_DIR/bruteforce_all.txt) 个子域名"

# 4. 排列变异
echo "[+] 子域名排列变异..."

# 基于已知前缀生成变异
if command -v gotator &> /dev/null; then
    echo "  [*] Gotator排列..."
    gotator -sub $OUTPUT_DIR/prefixes.txt -depth 1 -numbers 3 -md | sed "s/$/.${TARGET}/" > $OUTPUT_DIR/permutations.txt
    
    # 验证变异结果
    puredns resolve $OUTPUT_DIR/permutations.txt -r $RESOLVERS -w $OUTPUT_DIR/permutations_valid.txt
else
    # 简单变异
    echo "  [*] 简单变异..."
    while read prefix; do
        echo "${prefix}-dev.$TARGET"
        echo "${prefix}-test.$TARGET"
        echo "${prefix}-prod.$TARGET"
        echo "${prefix}-stage.$TARGET"
        echo "${prefix}-staging.$TARGET"
        echo "${prefix}1.$TARGET"
        echo "${prefix}2.$TARGET"
        echo "dev-${prefix}.$TARGET"
        echo "test-${prefix}.$TARGET"
    done < <(head -1000 $OUTPUT_DIR/prefixes.txt) | sort -u > $OUTPUT_DIR/permutations.txt
    
    # 验证
    dnsx -l $OUTPUT_DIR/permutations.txt -silent -o $OUTPUT_DIR/permutations_valid.txt
fi

echo "[✓] 排列变异完成: $(wc -l < $OUTPUT_DIR/permutations_valid.txt 2>/dev/null || echo 0) 个有效子域名"

# 5. 递归枚举
echo "[+] 递归子域名枚举..."

cat $OUTPUT_DIR/all_discovered.txt | while read subdomain; do
    if [[ $subdomain == *"."*"."$TARGET ]]; then
        # 提取上一级域名
        parent=$(echo $subdomain | rev | cut -d'.' -f2- | rev)
        
        # 枚举该级别
        subfinder -d $parent -silent >> $OUTPUT_DIR/recursive.txt
    fi
done

sort -u $OUTPUT_DIR/recursive.txt -o $OUTPUT_DIR/recursive.txt 2>/dev/null

echo "[✓] 递归枚举完成: $(wc -l < $OUTPUT_DIR/recursive.txt 2>/dev/null || echo 0) 个子域名"

# 6. 合并所有结果
echo "[+] 合并所有结果..."

cat $OUTPUT_DIR/*.txt 2>/dev/null | grep "\.$TARGET$" | sort -u > $OUTPUT_DIR/all_subdomains_final.txt

echo "[✓] 总计发现: $(wc -l < $OUTPUT_DIR/all_subdomains_final.txt) 个唯一子域名"

# 7. DNS解析验证
echo "[+] DNS解析验证..."

dnsx -l $OUTPUT_DIR/all_subdomains_final.txt \
     -r $RESOLVERS \
     -a -aaaa -cname -mx -ns -txt -srv -ptr \
     -resp -json \
     -o $OUTPUT_DIR/dnsx_full.json

# 提取已解析域名
cat $OUTPUT_DIR/dnsx_full.json | jq -r '.host' | sort -u > $OUTPUT_DIR/resolved.txt

echo "[✓] 解析完成: $(wc -l < $OUTPUT_DIR/resolved.txt) 个可解析域名"

# 8. IP提取和分类
echo "[+] IP提取和分类..."

cat $OUTPUT_DIR/dnsx_full.json | jq -r '.a[]?' 2>/dev/null | sort -u > $OUTPUT_DIR/ips_a.txt
cat $OUTPUT_DIR/dnsx_full.json | jq -r '.aaaa[]?' 2>/dev/null | sort -u > $OUTPUT_DIR/ips_aaaa.txt

# 识别CDN和云服务
echo "  [*] 识别CDN/云服务..."

while read ip; do
    # 简单的CDN检测（可以扩展）
    if [[ $ip == 104.* ]] || [[ $ip == 172.* ]]; then
        echo "$ip - Cloudflare可能" >> $OUTPUT_DIR/cdn_analysis.txt
    fi
done < $OUTPUT_DIR/ips_a.txt

echo "[✓] IP分析完成"

# 9. 反向DNS
echo "[+] 反向DNS查询..."

hakrevdns -d $OUTPUT_DIR/ips_a.txt 2>/dev/null | grep $TARGET > $OUTPUT_DIR/reverse_dns.txt || true

echo "[✓] 反向DNS完成: $(wc -l < $OUTPUT_DIR/reverse_dns.txt 2>/dev/null || echo 0) 个结果"

# 10. 生成报告
echo "[+] 生成报告..."

cat > $OUTPUT_DIR/REPORT.txt << EOF
======================================
DNS枚举报告
======================================
目标: $TARGET
时间: $(date)
======================================

统计摘要:
---------
被动收集: $(wc -l < $OUTPUT_DIR/passive_all.txt 2>/dev/null || echo 0)
主动枚举: $(wc -l < $OUTPUT_DIR/active_all.txt 2>/dev/null || echo 0)
DNS爆破: $(wc -l < $OUTPUT_DIR/bruteforce_all.txt 2>/dev/null || echo 0)
排列变异: $(wc -l < $OUTPUT_DIR/permutations_valid.txt 2>/dev/null || echo 0)
递归枚举: $(wc -l < $OUTPUT_DIR/recursive.txt 2>/dev/null || echo 0)
---------
总计子域名: $(wc -l < $OUTPUT_DIR/all_subdomains_final.txt)
可解析: $(wc -l < $OUTPUT_DIR/resolved.txt)
唯一IP(A): $(wc -l < $OUTPUT_DIR/ips_a.txt 2>/dev/null || echo 0)
唯一IP(AAAA): $(wc -l < $OUTPUT_DIR/ips_aaaa.txt 2>/dev/null || echo 0)

输出文件:
---------
所有子域名: all_subdomains_final.txt
已解析域名: resolved.txt
完整DNS记录: dnsx_full.json
IP地址: ips_a.txt, ips_aaaa.txt

======================================
EOF

cat $OUTPUT_DIR/REPORT.txt

echo ""
echo "======================================="
echo "DNS枚举完成!"
echo "结果保存在: $OUTPUT_DIR"
echo "======================================="

