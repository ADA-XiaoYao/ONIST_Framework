#!/bin/bash

# ========================================
# Web资产深度发现和分析
# ========================================

set -e

TARGET_FILE=""
OUTPUT_DIR="web_recon_$(date +%Y%m%d_%H%M%S)"
THREADS=30

while [[ $# -gt 0 ]]; do
    case $1 in
        -l|--list)
            TARGET_FILE="$2"
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
        *)
            shift
            ;;
    esac
done

if [ -z "$TARGET_FILE" ]; then
    echo "Usage: $0 -l targets.txt [-o output_dir] [-t threads]"
    exit 1
fi

mkdir -p $OUTPUT_DIR/{httpx,tech,urls,js,params,endpoints,screenshots,wayback}

echo "======================================="
echo "Web资产深度分析"
echo "目标文件: $TARGET_FILE"
echo "输出目录: $OUTPUT_DIR"
echo "======================================="

# 1. HTTP探测和指纹识别
echo "[+] HTTP探测和技术栈识别..."

httpx -l $TARGET_FILE \
    -silent \
    -status-code \
    -title \
    -tech-detect \
    -server \
    -content-length \
    -content-type \
    -location \
    -web-server \
    -method \
    -ip \
    -cname \
    -cdn \
    -probe \
    -favicon \
    -jarm \
    -asn \
    -o $OUTPUT_DIR/httpx/httpx_full.txt \
    -json \
    -j $OUTPUT_DIR/httpx/httpx_full.json

# 提取存活URL
cat $OUTPUT_DIR/httpx/httpx_full.json | jq -r '.url' | sort -u > $OUTPUT_DIR/alive_urls.txt

echo "[✓] HTTP探测完成: $(wc -l < $OUTPUT_DIR/alive_urls.txt) 个存活URL"

# 2. 技术栈深度分析
echo "[+] 深度技术栈分析..."

# Wappalyzer风格检测
httpx -l $OUTPUT_DIR/alive_urls.txt \
    -tech-detect \
    -json \
    -o $OUTPUT_DIR/tech/technologies.json

# Webanalyze
if command -v webanalyze &> /dev/null; then
    webanalyze -hosts $OUTPUT_DIR/alive_urls.txt -output json > $OUTPUT_DIR/tech/webanalyze.json
fi

echo "[✓] 技术栈分析完成"

# 3. URL收集 - 多源聚合
echo "[+] URL收集 - 历史和爬虫..."

# Wayback Machine
echo "  [*] Wayback Machine..."
cat $OUTPUT_DIR/alive_urls.txt | waybackurls > $OUTPUT_DIR/wayback/waybackurls.txt

# Common Crawl (gau)
echo "  [*] Common Crawl..."
cat $OUTPUT_DIR/alive_urls.txt | gau --threads $THREADS --blacklist ttf,woff,svg,png,jpg,jpeg,gif,ico > $OUTPUT_DIR/wayback/gau.txt

# AlienVault
echo "  [*] AlienVault OTX..."
cat $OUTPUT_DIR/alive_urls.txt | while read url; do
    domain=$(echo $url | unfurl domains)
    curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$domain/url_list?limit=500" | jq -r '.url_list[].url' 2>/dev/null
done > $OUTPUT_DIR/wayback/alienvault_urls.txt

# VirusTotal (需要API key)
# echo "  [*] VirusTotal..."
# 这里可以添加VirusTotal API调用

# 合并历史URL
cat $OUTPUT_DIR/wayback/*.txt | sort -u > $OUTPUT_DIR/urls/historical_urls.txt

echo "[✓] 历史URL收集完成: $(wc -l < $OUTPUT_DIR/urls/historical_urls.txt) 个URL"

# 4. 主动爬虫
echo "[+] 主动Web爬虫..."

# GoSpider
echo "  [*] GoSpider..."
gospider -S $OUTPUT_DIR/alive_urls.txt \
    -o $OUTPUT_DIR/urls/gospider \
    -c 10 \
    -d 3 \
    --sitemap \
    --robots \
    -t $THREADS

# Hakrawler
echo "  [*] Hakrawler..."
cat $OUTPUT_DIR/alive_urls.txt | hakrawler -depth 3 -plain -usewayback > $OUTPUT_DIR/urls/hakrawler.txt

# Katana
if command -v katana &> /dev/null; then
    echo "  [*] Katana..."
    katana -list $OUTPUT_DIR/alive_urls.txt \
        -d 5 \
        -jc \
        -kf all \
        -aff \
        -o $OUTPUT_DIR/urls/katana.txt
fi

# 合并所有爬虫结果
cat $OUTPUT_DIR/urls/historical_urls.txt \
    $OUTPUT_DIR/urls/gospider/* \
    $OUTPUT_DIR/urls/hakrawler.txt \
    $OUTPUT_DIR/urls/katana.txt 2>/dev/null | \
    grep -Eo 'https?://[^"]+' | \
    sort -u > $OUTPUT_DIR/urls/all_urls.txt

echo "[✓] 爬虫完成: $(wc -l < $OUTPUT_DIR/urls/all_urls.txt) 个总URL"

# 5. URL分类
echo "[+] URL分类和过滤..."

# 提取JS文件
cat $OUTPUT_DIR/urls/all_urls.txt | grep -iE '\.js(\?|$)' | sort -u > $OUTPUT_DIR/js/js_files.txt

# 提取API端点
cat $OUTPUT_DIR/urls/all_urls.txt | grep -iE '(api|v[0-9]|graphql|rest|json|xml)' | sort -u > $OUTPUT_DIR/endpoints/api_endpoints.txt

# 提取参数化URL
cat $OUTPUT_DIR/urls/all_urls.txt | grep '?' | sort -u > $OUTPUT_DIR/params/parameterized_urls.txt

# 提取子域名
cat $OUTPUT_DIR/urls/all_urls.txt | unfurl domains | sort -u > $OUTPUT_DIR/discovered_domains.txt

echo "[✓] URL分类完成"
echo "  - JS文件: $(wc -l < $OUTPUT_DIR/js/js_files.txt)"
echo "  - API端点: $(wc -l < $OUTPUT_DIR/endpoints/api_endpoints.txt)"
echo "  - 参数化URL: $(wc -l < $OUTPUT_DIR/params/parameterized_urls.txt)"

# 6. JavaScript分析
echo "[+] JavaScript深度分析..."

# 下载JS文件
mkdir -p $OUTPUT_DIR/js/downloaded
cat $OUTPUT_DIR/js/js_files.txt | head -100 | while read js_url; do
    filename=$(echo $js_url | md5sum | cut -d' ' -f1)
    curl -s -L "$js_url" -o "$OUTPUT_DIR/js/downloaded/${filename}.js" 2>/dev/null || true
done

# LinkFinder - 提取端点
echo "  [*] LinkFinder分析..."
if command -v linkfinder &> /dev/null; then
    cat $OUTPUT_DIR/js/js_files.txt | head -50 | while read js_url; do
        python3 /usr/local/bin/linkfinder.py -i "$js_url" -o cli 2>/dev/null
    done | sort -u > $OUTPUT_DIR/js/linkfinder_endpoints.txt
fi

# SecretFinder - 提取敏感信息
echo "  [*] 搜索JS中的敏感信息..."
if [ -d "$OUTPUT_DIR/js/downloaded" ]; then
    grep -rEoh '(api[_-]?key|secret|password|token|auth|aws_access|private[_-]?key).*[=:]['\''"]?[a-zA-Z0-9_-]{10,}' \
        $OUTPUT_DIR/js/downloaded/ 2>/dev/null | sort -u > $OUTPUT_DIR/js/potential_secrets.txt || true
fi

# Subdomains from JS
echo "  [*] 从JS提取子域名..."
cat $OUTPUT_DIR/js/downloaded/*.js 2>/dev/null | \
    grep -Eo '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | \
    sort -u > $OUTPUT_DIR/js/domains_from_js.txt || true

echo "[✓] JavaScript分析完成"

# 7. API端点发现和测试
echo "[+] API端点发现..."

# Arjun - 参数发现
echo "  [*] Arjun参数发现..."
if command -v arjun &> /dev/null; then
    arjun -i $OUTPUT_DIR/endpoints/api_endpoints.txt \
        -o $OUTPUT_DIR/params/arjun_params.json \
        -t $THREADS \
        --stable 2>/dev/null || true
fi

# 提取唯一参数名
cat $OUTPUT_DIR/params/parameterized_urls.txt | \
    unfurl keys | \
    sort -u > $OUTPUT_DIR/params/parameter_names.txt

echo "[✓] 发现 $(wc -l < $OUTPUT_DIR/params/parameter_names.txt 2>/dev/null || echo 0) 个唯一参数"

# 8. 目录和文件爆破
echo "[+] 智能目录枚举..."

# 从已知路径提取模式
cat $OUTPUT_DIR/urls/all_urls.txt | unfurl paths | cut -d'/' -f2 | sort -u | head -1000 > /tmp/custom_wordlist.txt

# 对主域名进行目录爆破
cat $OUTPUT_DIR/alive_urls.txt | head -10 | while read url; do
    base_url=$(echo $url | unfurl format %s://%d)
    
    # Ffuf快速扫描
    if command -v ffuf &> /dev/null; then
        ffuf -u "$base_url/FUZZ" \
            -w /tmp/custom_wordlist.txt \
            -mc 200,204,301,302,307,401,403 \
            -o $OUTPUT_DIR/endpoints/ffuf_$(echo $base_url | md5sum | cut -d' ' -f1).json \
            -of json \
            -s \
            -t $THREADS 2>/dev/null || true
    fi
done

rm /tmp/custom_wordlist.txt

echo "[✓] 目录枚举完成"

# 9. 响应分析
echo "[+] HTTP响应分析..."

# 检查常见安全头
echo "  [*] 安全头检查..."
cat $OUTPUT_DIR/httpx/httpx_full.json | jq -r 'select(.header) | .url + " | " + (.header | tostring)' > $OUTPUT_DIR/security_headers.txt

# 检查CORS配置
echo "  [*] CORS配置检查..."
cat $OUTPUT_DIR/alive_urls.txt | while read url; do
    cors=$(curl -s -I -H "Origin: https://evil.com" "$url" | grep -i "access-control-allow-origin")
    if [ ! -z "$cors" ]; then
        echo "$url | $cors" >> $OUTPUT_DIR/cors_misconfig.txt
    fi
done

echo "[✓] 响应分析完成"

# 10. 截图
echo "[+] 生成Web截图..."

if command -v gowitness &> /dev/null; then
    gowitness file -f $OUTPUT_DIR/alive_urls.txt \
        -P $OUTPUT_DIR/screenshots/ \
        --threads $THREADS \
        --timeout 10 2>/dev/null || true
    
    echo "[✓] 截图完成: $(ls $OUTPUT_DIR/screenshots/*.png 2>/dev/null | wc -l) 张"
else
    echo "[!] gowitness 未安装，跳过截图"
fi

# 11. 漏洞特征匹配
echo "[+] 漏洞模式匹配..."

# 查找常见漏洞模式
echo "  [*] 搜索敏感路径..."
cat $OUTPUT_DIR/urls/all_urls.txt | grep -iE '(admin|login|dashboard|config|backup|test|debug|phpmyadmin|console)' > $OUTPUT_DIR/sensitive_paths.txt || true

# 查找可能的LFI/Path Traversal
cat $OUTPUT_DIR/urls/all_urls.txt | grep -E '(file|path|dir|folder|page)=' > $OUTPUT_DIR/potential_lfi.txt || true

# 查找可能的SSRF
cat $OUTPUT_DIR/urls/all_urls.txt | grep -E '(url|uri|redirect|link|src|dest|target)=' > $OUTPUT_DIR/potential_ssrf.txt || true

# 查找可能的SQL注入点
cat $OUTPUT_DIR/urls/all_urls.txt | grep -E '(id|user|product|category|search|query)=' > $OUTPUT_DIR/potential_sqli.txt || true

echo "[✓] 漏洞特征匹配完成"

# 12. 生成报告
echo "[+] 生成报告..."

cat > $OUTPUT_DIR/REPORT.md << EOF
# Web资产分析报告

**生成时间**: $(date)

## 统计摘要

### HTTP探测
- 存活URL: $(wc -l < $OUTPUT_DIR/alive_urls.txt)
- 唯一域名: $(wc -l < $OUTPUT_DIR/discovered_domains.txt)

### URL收集
- 历史URL: $(wc -l < $OUTPUT_DIR/urls/historical_urls.txt 2>/dev/null || echo 0)
- 总URL数: $(wc -l < $OUTPUT_DIR/urls/all_urls.txt)
- JS文件: $(wc -l < $OUTPUT_DIR/js/js_files.txt)
- API端点: $(wc -l < $OUTPUT_DIR/endpoints/api_endpoints.txt)

### 参数分析
- 参数化URL: $(wc -l < $OUTPUT_DIR/params/parameterized_urls.txt)
- 唯一参数名: $(wc -l < $OUTPUT_DIR/params/parameter_names.txt 2>/dev/null || echo 0)

### 潜在问题
- 敏感路径: $(wc -l < $OUTPUT_DIR/sensitive_paths.txt 2>/dev/null || echo 0)
- 潜在LFI: $(wc -l < $OUTPUT_DIR/potential_lfi.txt 2>/dev/null || echo 0)
- 潜在SSRF: $(wc -l < $OUTPUT_DIR/potential_ssrf.txt 2>/dev/null || echo 0)
- 潜在SQLi: $(wc -l < $OUTPUT_DIR/potential_sqli.txt 2>/dev/null || echo 0)
- CORS问题: $(wc -l < $OUTPUT_DIR/cors_misconfig.txt 2>/dev/null || echo 0)

## 关键文件

- 存活URL: \`alive_urls.txt\`
- 所有URL: \`urls/all_urls.txt\`
- JS文件: \`js/js_files.txt\`
- API端点: \`endpoints/api_endpoints.txt\`
- 敏感路径: \`sensitive_paths.txt\`
- 技术栈: \`tech/technologies.json\`
- HTTP详情: \`httpx/httpx_full.json\`

## 下一步建议

1. 审查敏感路径文件
2. 分析潜在漏洞点
3. 检查CORS配置问题
4. 审计JavaScript中的敏感信息
5. 对API端点进行深度测试

EOF

cat $OUTPUT_DIR/REPORT.md

echo ""
echo "======================================="
echo "Web资产分析完成!"
echo "结果保存在: $OUTPUT_DIR"
echo "======================================="

