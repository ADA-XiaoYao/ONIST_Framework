package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Config 配置结构
type Config struct {
	Target           string
	OutputDir        string
	Threads          int
	Timeout          int
	PassiveRecon     bool
	ActiveRecon      bool
	PortScan         bool
	VulnScan         bool
	WebCrawl         bool
	APIScan          bool
	JSAnalysis       bool
	ScreenshotMode   bool
	CloudEnum        bool
	DNSBruteforce    bool
	SubdomainTakeover bool
	
	// 工具参数
	SubfinderArgs    string
	AmassArgs        string
	NucleiArgs       string
	NaabuArgs        string
	HttpxArgs        string
	GoSpiderArgs     string
	
	// 高级选项
	ResolverFile     string
	Wordlist         string
	CustomScripts    []string
}

// Result 扫描结果
type Result struct {
	Timestamp  time.Time
	Type       string
	Data       interface{}
	Source     string
}

// ReconEngine 核心引擎
type ReconEngine struct {
	Config    *Config
	Results   chan Result
	Errors    chan error
	WaitGroup sync.WaitGroup
	Ctx       context.Context
	Cancel    context.CancelFunc
	Logger    *log.Logger
}

func main() {
	config := parseFlags()
	
	// 创建输出目录
	timestamp := time.Now().Format("20060102_150405")
	config.OutputDir = fmt.Sprintf("recon_%s_%s", config.Target, timestamp)
	
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		log.Fatalf("无法创建输出目录: %v", err)
	}
	
	// 初始化引擎
	engine := NewReconEngine(config)
	
	// 启动信息收集
	engine.Run()
}

func parseFlags() *Config {
	config := &Config{
		Threads: runtime.NumCPU() * 2,
		Timeout: 300,
		PassiveRecon: true,
		ActiveRecon: true,
		PortScan: true,
		VulnScan: true,
		WebCrawl: true,
		APIScan: true,
		JSAnalysis: true,
		ScreenshotMode: true,
		CloudEnum: true,
		DNSBruteforce: true,
		SubdomainTakeover: true,
	}
	
	flag.StringVar(&config.Target, "d", "", "目标域名 (必需)")
	flag.StringVar(&config.Target, "domain", "", "目标域名 (必需)")
	flag.IntVar(&config.Threads, "t", config.Threads, "并发线程数")
	flag.IntVar(&config.Timeout, "timeout", config.Timeout, "超时时间(秒)")
	
	flag.BoolVar(&config.PassiveRecon, "passive", true, "被动信息收集")
	flag.BoolVar(&config.ActiveRecon, "active", true, "主动信息收集")
	flag.BoolVar(&config.PortScan, "portscan", true, "端口扫描")
	flag.BoolVar(&config.VulnScan, "vulnscan", true, "漏洞扫描")
	flag.BoolVar(&config.WebCrawl, "webcrawl", true, "Web爬虫")
	flag.BoolVar(&config.APIScan, "apiscan", true, "API扫描")
	flag.BoolVar(&config.JSAnalysis, "jsanalysis", true, "JavaScript分析")
	flag.BoolVar(&config.ScreenshotMode, "screenshot", true, "网页截图")
	flag.BoolVar(&config.CloudEnum, "cloudenum", true, "云资源枚举")
	flag.BoolVar(&config.DNSBruteforce, "dnsbrute", true, "DNS爆破")
	flag.BoolVar(&config.SubdomainTakeover, "takeover", true, "子域名接管检测")
	
	flag.StringVar(&config.SubfinderArgs, "subfinder-args", "", "Subfinder额外参数")
	flag.StringVar(&config.AmassArgs, "amass-args", "", "Amass额外参数")
	flag.StringVar(&config.NucleiArgs, "nuclei-args", "", "Nuclei额外参数")
	flag.StringVar(&config.NaabuArgs, "naabu-args", "", "Naabu额外参数")
	flag.StringVar(&config.HttpxArgs, "httpx-args", "", "Httpx额外参数")
	flag.StringVar(&config.GoSpiderArgs, "gospider-args", "", "GoSpider额外参数")
	
	flag.StringVar(&config.ResolverFile, "resolvers", "", "自定义DNS解析器文件")
	flag.StringVar(&config.Wordlist, "wordlist", "", "自定义字典文件")
	
	flag.Parse()
	
	if config.Target == "" {
		flag.Usage()
		os.Exit(1)
	}
	
	return config
}

func NewReconEngine(config *Config) *ReconEngine {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.Timeout)*time.Second)
	
	logFile, _ := os.Create(filepath.Join(config.OutputDir, "recon.log"))
	logger := log.New(io.MultiWriter(os.Stdout, logFile), "[RECON] ", log.LstdFlags)
	
	return &ReconEngine{
		Config:  config,
		Results: make(chan Result, 10000),
		Errors:  make(chan error, 1000),
		Ctx:     ctx,
		Cancel:  cancel,
		Logger:  logger,
	}
}

func (e *ReconEngine) Run() {
	defer e.Cancel()
	
	e.Logger.Println("========================================")
	e.Logger.Printf("目标: %s\n", e.Config.Target)
	e.Logger.Printf("输出目录: %s\n", e.Config.OutputDir)
	e.Logger.Printf("线程数: %d\n", e.Config.Threads)
	e.Logger.Println("========================================")
	
	// 检查必需工具
	e.checkTools()
	
	// 启动结果收集器
	go e.collectResults()
	go e.collectErrors()
	
	// 阶段1: 被动信息收集
	if e.Config.PassiveRecon {
		e.phasePassive()
	}
	
	// 阶段2: 主动信息收集
	if e.Config.ActiveRecon {
		e.phaseActive()
	}
	
	// 阶段3: DNS解析与验证
	e.phaseDNSResolve()
	
	// 阶段4: 存活检测
	e.phaseAliveCheck()
	
	// 阶段5: 端口扫描
	if e.Config.PortScan {
		e.phasePortScan()
	}
	
	// 阶段6: Web信息收集
	e.phaseWebRecon()
	
	// 阶段7: 漏洞扫描
	if e.Config.VulnScan {
		e.phaseVulnScan()
	}
	
	// 阶段8: 高级扫描
	e.phaseAdvanced()
	
	// 等待所有任务完成
	e.WaitGroup.Wait()
	close(e.Results)
	close(e.Errors)
	
	// 生成报告
	e.generateReport()
	
	e.Logger.Println("========================================")
	e.Logger.Println("信息收集完成!")
	e.Logger.Printf("结果保存在: %s\n", e.Config.OutputDir)
	e.Logger.Println("========================================")
}

func (e *ReconEngine) checkTools() {
	e.Logger.Println("[*] 检查必需工具...")
	
	tools := []string{
		"subfinder", "assetfinder", "amass", "dnsx", "httpx", 
		"naabu", "nuclei", "waybackurls", "gau", "gospider",
		"subzy", "cloud_enum", "arjun", "dalfox", "hakrawler",
	}
	
	missing := []string{}
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}
	
	if len(missing) > 0 {
		e.Logger.Printf("[!] 缺少工具: %s\n", strings.Join(missing, ", "))
		e.Logger.Println("[*] 请运行安装脚本或手动安装")
	}
}

func (e *ReconEngine) phasePassive() {
	e.Logger.Println("\n[+] 阶段1: 被动信息收集")
	
	passiveDir := filepath.Join(e.Config.OutputDir, "01_passive")
	os.MkdirAll(passiveDir, 0755)
	
	tasks := []struct {
		name string
		fn   func(string) ([]string, error)
	}{
		{"subfinder", e.runSubfinder},
		{"assetfinder", e.runAssetfinder},
		{"amass_passive", e.runAmassPassive},
		{"crtsh", e.runCrtsh},
		{"certspotter", e.runCertspotter},
		{"hackertarget", e.runHackertarget},
		{"threatcrowd", e.runThreatcrowd},
		{"virustotal", e.runVirusTotal},
		{"alienvault", e.runAlienVault},
		{"shodan", e.runShodan},
	}
	
	allDomains := make(map[string]bool)
	var mu sync.Mutex
	
	for _, task := range tasks {
		e.WaitGroup.Add(1)
		go func(name string, fn func(string) ([]string, error)) {
			defer e.WaitGroup.Done()
			
			e.Logger.Printf("  [*] 运行 %s...\n", name)
			domains, err := fn(e.Config.Target)
			if err != nil {
				e.Errors <- fmt.Errorf("%s 失败: %v", name, err)
				return
			}
			
			// 保存结果
			outFile := filepath.Join(passiveDir, fmt.Sprintf("%s.txt", name))
			e.saveLines(outFile, domains)
			
			// 合并到总列表
			mu.Lock()
			for _, d := range domains {
				allDomains[d] = true
			}
			mu.Unlock()
			
			e.Logger.Printf("  [✓] %s 完成: 发现 %d 个域名\n", name, len(domains))
		}(task.name, task.fn)
	}
	
	e.WaitGroup.Wait()
	
	// 保存合并结果
	allFile := filepath.Join(e.Config.OutputDir, "all_subdomains.txt")
	var domains []string
	for d := range allDomains {
		domains = append(domains, d)
	}
	e.saveLines(allFile, domains)
	
	e.Logger.Printf("[✓] 被动收集完成: 总共发现 %d 个唯一子域名\n", len(domains))
}

func (e *ReconEngine) phaseActive() {
	e.Logger.Println("\n[+] 阶段2: 主动信息收集")
	
	activeDir := filepath.Join(e.Config.OutputDir, "02_active")
	os.MkdirAll(activeDir, 0755)
	
	// Amass主动枚举
	if e.Config.DNSBruteforce {
		e.Logger.Println("  [*] 运行 Amass 主动枚举...")
		domains, _ := e.runAmassActive(e.Config.Target)
		outFile := filepath.Join(activeDir, "amass_active.txt")
		e.saveLines(outFile, domains)
		e.Logger.Printf("  [✓] Amass 主动枚举完成: %d 个域名\n", len(domains))
	}
	
	// DNS爆破
	if e.Config.DNSBruteforce && e.Config.Wordlist != "" {
		e.Logger.Println("  [*] 运行 DNS 爆破...")
		domains, _ := e.runDNSBrute(e.Config.Target)
		outFile := filepath.Join(activeDir, "dnsbrute.txt")
		e.saveLines(outFile, domains)
		e.Logger.Printf("  [✓] DNS 爆破完成: %d 个域名\n", len(domains))
	}
}

func (e *ReconEngine) phaseDNSResolve() {
	e.Logger.Println("\n[+] 阶段3: DNS解析与验证")
	
	resolveDir := filepath.Join(e.Config.OutputDir, "03_resolve")
	os.MkdirAll(resolveDir, 0755)
	
	// 读取所有子域名
	allFile := filepath.Join(e.Config.OutputDir, "all_subdomains.txt")
	domains := e.readLines(allFile)
	
	// DNS解析
	e.Logger.Println("  [*] 解析域名...")
	resolved := e.runDNSX(domains)
	outFile := filepath.Join(resolveDir, "resolved.txt")
	e.saveLines(outFile, resolved)
	
	e.Logger.Printf("[✓] DNS解析完成: %d/%d 域名可解析\n", len(resolved), len(domains))
}

func (e *ReconEngine) phaseAliveCheck() {
	e.Logger.Println("\n[+] 阶段4: 存活检测")
	
	aliveDir := filepath.Join(e.Config.OutputDir, "04_alive")
	os.MkdirAll(aliveDir, 0755)
	
	resolveFile := filepath.Join(e.Config.OutputDir, "03_resolve", "resolved.txt")
	domains := e.readLines(resolveFile)
	
	e.Logger.Println("  [*] 检测存活主机...")
	alive := e.runHttpx(domains)
	outFile := filepath.Join(aliveDir, "alive.txt")
	e.saveLines(outFile, alive)
	
	e.Logger.Printf("[✓] 存活检测完成: %d/%d 主机存活\n", len(alive), len(domains))
}

func (e *ReconEngine) phasePortScan() {
	e.Logger.Println("\n[+] 阶段5: 端口扫描")
	
	portDir := filepath.Join(e.Config.OutputDir, "05_ports")
	os.MkdirAll(portDir, 0755)
	
	resolveFile := filepath.Join(e.Config.OutputDir, "03_resolve", "resolved.txt")
	targets := e.readLines(resolveFile)
	
	e.Logger.Println("  [*] 扫描端口...")
	ports := e.runNaabu(targets)
	outFile := filepath.Join(portDir, "ports.txt")
	e.saveLines(outFile, ports)
	
	e.Logger.Printf("[✓] 端口扫描完成: 发现 %d 个开放端口\n", len(ports))
}

func (e *ReconEngine) phaseWebRecon() {
	e.Logger.Println("\n[+] 阶段6: Web信息收集")
	
	webDir := filepath.Join(e.Config.OutputDir, "06_web")
	os.MkdirAll(webDir, 0755)
	
	aliveFile := filepath.Join(e.Config.OutputDir, "04_alive", "alive.txt")
	urls := e.readLines(aliveFile)
	
	// URL爬取
	if e.Config.WebCrawl {
		e.Logger.Println("  [*] 爬取URL...")
		
		allURLs := make(map[string]bool)
		var mu sync.Mutex
		
		sources := []struct{
			name string
			fn func([]string) []string
		}{
			{"waybackurls", e.runWaybackurls},
			{"gau", e.runGau},
			{"gospider", e.runGoSpider},
			{"hakrawler", e.runHakrawler},
		}
		
		for _, src := range sources {
			e.WaitGroup.Add(1)
			go func(name string, fn func([]string) []string) {
				defer e.WaitGroup.Done()
				results := fn(urls)
				
				mu.Lock()
				for _, u := range results {
					allURLs[u] = true
				}
				mu.Unlock()
				
				e.Logger.Printf("  [✓] %s: %d URLs\n", name, len(results))
			}(src.name, src.fn)
		}
		
		e.WaitGroup.Wait()
		
		var crawled []string
		for u := range allURLs {
			crawled = append(crawled, u)
		}
		
		outFile := filepath.Join(webDir, "all_urls.txt")
		e.saveLines(outFile, crawled)
		e.Logger.Printf("[✓] URL爬取完成: %d 个URL\n", len(crawled))
	}
	
	// JavaScript分析
	if e.Config.JSAnalysis {
		e.Logger.Println("  [*] 分析JavaScript文件...")
		e.runJSAnalysis(urls)
	}
	
	// API端点发现
	if e.Config.APIScan {
		e.Logger.Println("  [*] 扫描API端点...")
		e.runAPIScanner(urls)
	}
	
	// 截图
	if e.Config.ScreenshotMode {
		e.Logger.Println("  [*] 生成网页截图...")
		e.runScreenshot(urls)
	}
}

func (e *ReconEngine) phaseVulnScan() {
	e.Logger.Println("\n[+] 阶段7: 漏洞扫描")
	
	vulnDir := filepath.Join(e.Config.OutputDir, "07_vulns")
	os.MkdirAll(vulnDir, 0755)
	
	aliveFile := filepath.Join(e.Config.OutputDir, "04_alive", "alive.txt")
	targets := e.readLines(aliveFile)
	
	// Nuclei扫描
	e.Logger.Println("  [*] 运行 Nuclei...")
	vulns := e.runNuclei(targets)
	outFile := filepath.Join(vulnDir, "nuclei.txt")
	e.saveLines(outFile, vulns)
	
	e.Logger.Printf("[✓] 漏洞扫描完成: 发现 %d 个潜在漏洞\n", len(vulns))
}

func (e *ReconEngine) phaseAdvanced() {
	e.Logger.Println("\n[+] 阶段8: 高级扫描")
	
	advDir := filepath.Join(e.Config.OutputDir, "08_advanced")
	os.MkdirAll(advDir, 0755)
	
	// 子域名接管检测
	if e.Config.SubdomainTakeover {
		e.Logger.Println("  [*] 检测子域名接管...")
		allFile := filepath.Join(e.Config.OutputDir, "all_subdomains.txt")
		domains := e.readLines(allFile)
		takeovers := e.runSubzy(domains)
		outFile := filepath.Join(advDir, "takeovers.txt")
		e.saveLines(outFile, takeovers)
		e.Logger.Printf("  [✓] 发现 %d 个潜在接管\n", len(takeovers))
	}
	
	// 云资源枚举
	if e.Config.CloudEnum {
		e.Logger.Println("  [*] 枚举云资源...")
		e.runCloudEnum(e.Config.Target)
		e.Logger.Println("  [✓] 云枚举完成")
	}
	
	// 参数发现
	e.Logger.Println("  [*] 发现API参数...")
	aliveFile := filepath.Join(e.Config.OutputDir, "04_alive", "alive.txt")
	urls := e.readLines(aliveFile)
	e.runArjun(urls)
	
	// XSS扫描
	e.Logger.Println("  [*] 扫描XSS...")
	e.runDalfox(urls)
}

// ============================================
// 工具调用函数
// ============================================

func (e *ReconEngine) runSubfinder(target string) ([]string, error) {
	args := []string{"-d", target, "-silent"}
	if e.Config.SubfinderArgs != "" {
		args = append(args, strings.Fields(e.Config.SubfinderArgs)...)
	}
	return e.runCommand("subfinder", args...)
}

func (e *ReconEngine) runAssetfinder(target string) ([]string, error) {
	return e.runCommand("assetfinder", "--subs-only", target)
}

func (e *ReconEngine) runAmassPassive(target string) ([]string, error) {
	args := []string{"enum", "-passive", "-d", target}
	if e.Config.AmassArgs != "" {
		args = append(args, strings.Fields(e.Config.AmassArgs)...)
	}
	return e.runCommand("amass", args...)
}

func (e *ReconEngine) runAmassActive(target string) ([]string, error) {
	args := []string{"enum", "-active", "-d", target}
	if e.Config.AmassArgs != "" {
		args = append(args, strings.Fields(e.Config.AmassArgs)...)
	}
	return e.runCommand("amass", args...)
}

func (e *ReconEngine) runCrtsh(target string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", target)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var results []struct {
		NameValue string `json:"name_value"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}
	
	domains := make(map[string]bool)
	for _, r := range results {
		for _, d := range strings.Split(r.NameValue, "\n") {
			d = strings.TrimPrefix(d, "*.")
			d = strings.TrimSpace(d)
			if d != "" {
				domains[d] = true
			}
		}
	}
	
	var list []string
	for d := range domains {
		list = append(list, d)
	}
	
	return list, nil
}

func (e *ReconEngine) runCertspotter(target string) ([]string, error) {
	url := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", target)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var results []struct {
		DNSNames []string `json:"dns_names"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}
	
	domains := make(map[string]bool)
	for _, r := range results {
		for _, d := range r.DNSNames {
			d = strings.TrimPrefix(d, "*.")
			domains[d] = true
		}
	}
	
	var list []string
	for d := range domains {
		list = append(list, d)
	}
	
	return list, nil
}

func (e *ReconEngine) runHackertarget(target string) ([]string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", target)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var domains []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ",")
		if len(parts) > 0 {
			domains = append(domains, strings.TrimSpace(parts[0]))
		}
	}
	
	return domains, nil
}

func (e *ReconEngine) runThreatcrowd(target string) ([]string, error) {
	url := fmt.Sprintf("https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=%s", target)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var result struct {
		Subdomains []string `json:"subdomains"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	
	return result.Subdomains, nil
}

func (e *ReconEngine) runVirusTotal(target string) ([]string, error) {
	// 需要API Key，这里返回空
	return []string{}, nil
}

func (e *ReconEngine) runAlienVault(target string) ([]string, error) {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", target)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var result struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	
	var domains []string
	for _, entry := range result.PassiveDNS {
		domains = append(domains, entry.Hostname)
	}
	
	return domains, nil
}

func (e *ReconEngine) runShodan(target string) ([]string, error) {
	// 需要API Key，这里返回空
	return []string{}, nil
}

func (e *ReconEngine) runDNSBrute(target string) ([]string, error) {
	if e.Config.Wordlist == "" {
		return []string{}, nil
	}
	
	// 读取字典
	wordlist := e.readLines(e.Config.Wordlist)
	
	var domains []string
	var mu sync.Mutex
	
	sem := make(chan struct{}, e.Config.Threads)
	
	for _, word := range wordlist {
		sem <- struct{}{}
		e.WaitGroup.Add(1)
		
		go func(w string) {
			defer e.WaitGroup.Done()
			defer func() { <-sem }()
			
			subdomain := fmt.Sprintf("%s.%s", w, target)
			
			// 简单DNS查询
			_, err := net.LookupHost(subdomain)
			if err == nil {
				mu.Lock()
				domains = append(domains, subdomain)
				mu.Unlock()
			}
		}(word)
	}
	
	e.WaitGroup.Wait()
	
	return domains, nil
}

func (e *ReconEngine) runDNSX(domains []string) []string {
	tmpFile := filepath.Join(e.Config.OutputDir, "tmp_domains.txt")
	e.saveLines(tmpFile, domains)
	defer os.Remove(tmpFile)
	
	args := []string{"-l", tmpFile, "-silent"}
	if e.Config.ResolverFile != "" {
		args = append(args, "-r", e.Config.ResolverFile)
	}
	
	resolved, _ := e.runCommand("dnsx", args...)
	return resolved
}

func (e *ReconEngine) runHttpx(domains []string) []string {
	tmpFile := filepath.Join(e.Config.OutputDir, "tmp_domains.txt")
	e.saveLines(tmpFile, domains)
	defer os.Remove(tmpFile)
	
	args := []string{"-l", tmpFile, "-silent"}
	if e.Config.HttpxArgs != "" {
		args = append(args, strings.Fields(e.Config.HttpxArgs)...)
	}
	
	alive, _ := e.runCommand("httpx", args...)
	return alive
}

func (e *ReconEngine) runNaabu(targets []string) []string {
	tmpFile := filepath.Join(e.Config.OutputDir, "tmp_targets.txt")
	e.saveLines(tmpFile, targets)
	defer os.Remove(tmpFile)
	
	args := []string{"-l", tmpFile, "-silent"}
	if e.Config.NaabuArgs != "" {
		args = append(args, strings.Fields(e.Config.NaabuArgs)...)
	}
	
	ports, _ := e.runCommand("naabu", args...)
	return ports
}

func (e *ReconEngine) runNuclei(targets []string) []string {
	tmpFile := filepath.Join(e.Config.OutputDir, "tmp_targets.txt")
	e.saveLines(tmpFile, targets)
	defer os.Remove(tmpFile)
	
	args := []string{"-l", tmpFile, "-silent"}
	if e.Config.NucleiArgs != "" {
		args = append(args, strings.Fields(e.Config.NucleiArgs)...)
	}
	
	vulns, _ := e.runCommand("nuclei", args...)
	return vulns
}

func (e *ReconEngine) runWaybackurls(urls []string) []string {
	var allURLs []string
	for _, url := range urls {
		results, _ := e.runCommand("waybackurls", url)
		allURLs = append(allURLs, results...)
	}
	return allURLs
}

func (e *ReconEngine) runGau(urls []string) []string {
	var allURLs []string
	for _, url := range urls {
		results, _ := e.runCommand("gau", url)
		allURLs = append(allURLs, results...)
	}
	return allURLs
}

func (e *ReconEngine) runGoSpider(urls []string) []string {
	tmpFile := filepath.Join(e.Config.OutputDir, "tmp_urls.txt")
	e.saveLines(tmpFile, urls)
	defer os.Remove(tmpFile)
	
	args := []string{"-s", tmpFile, "-o", filepath.Join(e.Config.OutputDir, "06_web", "gospider")}
	if e.Config.GoSpiderArgs != "" {
		args = append(args, strings.Fields(e.Config.GoSpiderArgs)...)
	}
	
	e.runCommand("gospider", args...)
	
	// 读取结果
	resultsFile := filepath.Join(e.Config.OutputDir, "06_web", "gospider", "output.txt")
	return e.readLines(resultsFile)
}

func (e *ReconEngine) runHakrawler(urls []string) []string {
	var allURLs []string
	for _, u
