package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type ocDiag struct {
	Cat string   `json:"category"`
	Label string  `json:"name"`
	Verdict string `json:"status"`
	Summary string `json:"detail"`
	Details []string `json:"items,omitempty"`
}

func digStr(m map[string]interface{}, path string) string {
	cur := interface{}(m)
	for _, k := range strings.Split(path, ".") {
		nested, ok := cur.(map[string]interface{})
		if !ok {
			return ""
		}
		cur = nested[k]
	}
	s, _ := cur.(string)
	return s
}

func digNum(m map[string]interface{}, path string) float64 {
	cur := interface{}(m)
	for _, k := range strings.Split(path, ".") {
		nested, ok := cur.(map[string]interface{})
		if !ok {
			return 0
		}
		cur = nested[k]
	}
	f, _ := cur.(float64)
	return f
}

func digBool(m map[string]interface{}, path string) bool {
	cur := interface{}(m)
	for _, k := range strings.Split(path, ".") {
		nested, ok := cur.(map[string]interface{})
		if !ok {
			return false
		}
		cur = nested[k]
	}
	if b, ok := cur.(bool); ok {
		return b
	}
	if s, ok := cur.(string); ok {
		return strings.EqualFold(s, "true")
	}
	return false
}

func digArr(m map[string]interface{}, path string) []string {
	cur := interface{}(m)
	for _, k := range strings.Split(path, ".") {
		nested, ok := cur.(map[string]interface{})
		if !ok {
			return nil
		}
		cur = nested[k]
	}
	raw, ok := cur.([]interface{})
	if !ok {
		return nil
	}
	var out []string
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func ocDiagPass(cat, label, msg string) ocDiag {
	return ocDiag{Cat: cat, Label: label, Verdict: "pass", Summary: msg}
}

func ocDiagFail(cat, label, msg string, items []string) ocDiag {
	return ocDiag{Cat: cat, Label: label, Verdict: "fail", Summary: msg, Details: items}
}

func ocDiagWarn(cat, label, msg string, items []string) ocDiag {
	return ocDiag{Cat: cat, Label: label, Verdict: "warn", Summary: msg, Details: items}
}

func ocDiagInfo(cat, label, msg string) ocDiag {
	return ocDiag{Cat: cat, Label: label, Verdict: "info", Summary: msg}
}

func auditOCConfig(dir string) []ocDiag {
	var out []ocDiag

	cfgPath := filepath.Join(dir, "openclaw.json")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		out = append(out, ocDiagInfo("config", "配置文件分析", "openclaw.json 不存在，跳过"))
		out = append(out, auditOCFilesystem(dir)...)
		return out
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		out = append(out, ocDiagFail("config", "配置文件分析", "openclaw.json 格式损坏", nil))
		return out
	}

	txt := string(raw)

	out = append(out, inspectOCCredentials(cfg, txt))
	out = append(out, inspectOCPosture(cfg))
	out = append(out, inspectOCHardening(cfg))
	out = append(out, inspectOCAuth(cfg))
	out = append(out, inspectOCSandbox(cfg))
	out = append(out, auditOCFilesystem(dir)...)
	out = append(out, auditOCPlugins(dir))
	out = append(out, auditOCPersona(dir))

	return out
}

func inspectOCCredentials(cfg map[string]interface{}, body string) ocDiag {
	credPatterns := []struct {
		re  *regexp.Regexp
		tag string
	}{
		{regexp.MustCompile(`(?i)sk-[a-f0-9a-zA-Z]{20,}`), "OpenAI"},
		{regexp.MustCompile(`(?i)sk-ant-[a-f0-9a-zA-Z]{20,}`), "Anthropic"},
		{regexp.MustCompile(`AKIA[A-Z0-9]{16}`), "AWS IAM"},
		{regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`), "GitHub"},
		{regexp.MustCompile(`AIza[a-zA-Z0-9_-]{35}`), "Google"},
		{regexp.MustCompile(`(?i)xai-[a-f0-9]{20,}`), "xAI"},
		{regexp.MustCompile(`(?i)dapi[a-zA-Z0-9]{20,}`), "Databricks"},
		{regexp.MustCompile(`(?i)(sk|rk)_(live|test)_[a-zA-Z0-9]{20,}`), "Stripe"},
		{regexp.MustCompile(`(?i)Bearer\s+[a-zA-Z0-9._-]{32,}`), "Bearer"},
	}

	flagDefs := []struct {
		key   string
		danger string
	}{
		{"gateway.auth.mode", "认证已关闭"},
		{"runtime.bypassAuth", "绕过认证已激活"},
		{"runtime.disableSafety", "安全检测已禁用"},
		{"runtime.allowAll", "操作限制已移除"},
		{"gateway.cors.origin", "跨域策略过于宽松"},
		{"gateway.bind", "服务暴露到所有接口"},
		{"permissions.admin.allowAll", "管理员权限未限制"},
		{"permissions.user.allowAll", "用户权限未限制"},
		{"runtime.allowNetworkAccess", "网络未隔离"},
		{"runtime.allowFileSystemAccess", "文件系统未隔离"},
	}

	var issues []string
	for _, cp := range credPatterns {
		if cp.re.MatchString(body) {
			issues = append(issues, fmt.Sprintf("疑似 %s 凭证泄露", cp.tag))
		}
	}

	for _, fd := range flagDefs {
		val := digStr(cfg, fd.key)
		if val == "none" || val == "false" || val == "*" || val == "0.0.0.0" {
			issues = append(issues, fd.danger)
		}
		if digBool(cfg, fd.key) {
			switch fd.key {
			case "runtime.bypassAuth", "runtime.disableSafety", "runtime.allowAll",
				"permissions.admin.allowAll", "permissions.user.allowAll",
				"runtime.allowNetworkAccess", "runtime.allowFileSystemAccess":
				issues = append(issues, fd.danger)
			}
		}
	}

	if len(issues) > 0 {
		return ocDiagFail("config", "配置与凭证审查", fmt.Sprintf("检出 %d 项风险", len(issues)), issues)
	}
	return ocDiagPass("config", "配置与凭证审查", "配置文件无明显风险")
}

func inspectOCPosture(cfg map[string]interface{}) ocDiag {
	var issues []string

	mode := digStr(cfg, "gateway.auth.mode")
	storage := digStr(cfg, "runtime.tokenStorage")
	if mode == "none" && (storage == "memory" || storage == "") {
		issues = append(issues, "CVE-2026-25253: 无认证 + 非持久化 Token，可被远程利用")
	}

	if digStr(cfg, "gateway.bind") == "0.0.0.0" {
		issues = append(issues, "监听地址为全接口绑定")
	}

	if digBool(cfg, "permissions.admin.allowAll") || digBool(cfg, "permissions.user.allowAll") {
		issues = append(issues, "ACL 未细分，存在权限越界可能")
	}

	if !digBool(cfg, "runtime.sandbox") {
		issues = append(issues, "沙箱机制未启用")
	}

	cmdBlock := digArr(cfg, "runtime.denyCommands")
	if len(cmdBlock) == 0 {
		issues = append(issues, "高危命令黑名单为空")
	}

	if len(issues) > 0 {
		return ocDiagFail("vulnerability", "威胁面评估", fmt.Sprintf("发现 %d 个暴露面", len(issues)), issues)
	}
	return ocDiagPass("vulnerability", "威胁面评估", "未发现显著暴露面")
}

func inspectOCAuth(cfg map[string]interface{}) ocDiag {
	var issues []string

	mode := digStr(cfg, "gateway.auth.mode")
	if mode == "" || mode == "none" {
		issues = append(issues, "未启用身份校验")
	}

	pwd := digStr(cfg, "gateway.auth.password")
	trivialPwds := map[string]bool{
		"admin": true, "password": true, "123456": true, "admin123": true,
		"openclaw": true, "openclaw123": true, "welcome": true, "letmein": true,
		"qwerty": true, "abc123": true,
	}
	if pwd != "" {
		if trivialPwds[strings.ToLower(pwd)] {
			issues = append(issues, "密码强度极弱")
		} else if len(pwd) < 8 {
			issues = append(issues, "密码长度不达标")
		}
	}

	secret := digStr(cfg, "gateway.auth.jwtSecret")
	if secret != "" && len(secret) < 32 {
		issues = append(issues, "签名密钥过短")
	}

	ttl := digNum(cfg, "gateway.auth.sessionTTL")
	switch {
	case ttl > 86400:
		issues = append(issues, fmt.Sprintf("会话有效期过长（%.0f秒）", ttl))
	case ttl == 0:
		issues = append(issues, "未设置会话过期")
	}

	if digNum(cfg, "gateway.auth.rateLimit") == 0 {
		issues = append(issues, "缺少请求频率限制")
	}

	if len(issues) > 0 {
		return ocDiagFail("auth", "身份与访问控制", fmt.Sprintf("检出 %d 项问题", len(issues)), issues)
	}
	return ocDiagPass("auth", "身份与访问控制", "认证机制健全")
}

func inspectOCSandbox(cfg map[string]interface{}) ocDiag {
	var issues []string

	blocked := digArr(cfg, "runtime.denyCommands")
	shouldBlock := []string{"rm", "sudo", "su", "chmod", "chown", "dd", "mkfs"}
	var missing []string
	for _, c := range shouldBlock {
		found := false
		for _, b := range blocked {
			if strings.EqualFold(b, c) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		issues = append(issues, fmt.Sprintf("命令黑名单缺少: %s", strings.Join(missing, ", ")))
	}

	if digNum(cfg, "runtime.limits.memory") == 0 {
		issues = append(issues, "未约束内存上限")
	}
	if digNum(cfg, "runtime.limits.cpu") == 0 {
		issues = append(issues, "未约束 CPU 用量")
	}

	ttl := digNum(cfg, "gateway.auth.sessionTTL")
	if ttl > 86400 {
		issues = append(issues, fmt.Sprintf("会话 TTL %.0f秒 超过阈值", ttl))
	}

	if strings.EqualFold(digStr(cfg, "logging.level"), "debug") {
		issues = append(issues, "日志级别为 debug")
	}
	if !digBool(cfg, "logging.rotation") {
		issues = append(issues, "未启用日志轮转")
	}
	if !digBool(cfg, "runtime.autoUpdate") {
		issues = append(issues, "自动更新未开启")
	}
	if digBool(cfg, "runtime.debug") {
		issues = append(issues, "调试模式运行中")
	}

	if len(issues) > 0 {
		return ocDiagWarn("runtime", "运行时加固", fmt.Sprintf("存在 %d 个加固项", len(issues)), issues)
	}
	return ocDiagPass("runtime", "运行时加固", "运行时配置合规")
}

func inspectOCHardening(cfg map[string]interface{}) ocDiag {
	var issues []string
	if !digBool(cfg, "runtime.sandbox") {
		issues = append(issues, "沙箱未激活，宿主系统暴露")
	}
	if !digBool(cfg, "runtime.autoUpdate") {
		issues = append(issues, "自动更新关闭，可能遗漏补丁")
	}
	if digBool(cfg, "runtime.debug") {
		issues = append(issues, "调试模式开启，信息泄露风险")
	}
	if len(issues) > 0 {
		return ocDiagWarn("hardening", "安全加固状态", fmt.Sprintf("需关注 %d 项", len(issues)), issues)
	}
	return ocDiagPass("hardening", "安全加固状态", "加固配置正常")
}

func auditOCFilesystem(dir string) []ocDiag {
	var out []ocDiag
	var issues []string

	certExts := []string{".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		for _, ce := range certExts {
			if ext == ce {
				issues = append(issues, "证书/密钥文件: "+filepath.Base(p))
			}
		}
		if ext == ".db" || ext == ".sqlite" || ext == ".sqlite3" {
			hdr, e := os.ReadFile(p)
			if e == nil && len(hdr) >= 16 && strings.Contains(string(hdr[:16]), "SQLite format 3") {
				issues = append(issues, "未加密数据库: "+filepath.Base(p))
			}
		}
		if ext == ".log" && fi.Size() < 2<<20 {
			data, e := os.ReadFile(p)
			if e == nil {
				txt := string(data)
				credRe := regexp.MustCompile(`(?i)(sk-[a-zA-Z0-9]{20,}|Bearer\s+[a-zA-Z0-9._-]{32,}|ghp_[a-zA-Z0-9]{36})`)
				if credRe.MatchString(txt) {
					issues = append(issues, "日志含凭证信息: "+filepath.Base(p))
				}
			}
		}
		return nil
	})

	memDir := filepath.Join(dir, "memory")
	if fi, e := os.Stat(memDir); e == nil && fi.IsDir() {
		walletWords := []string{"mnemonic", "seed phrase", "助记词", "钱包", "private key", "私钥", "secret phrase"}
		filepath.Walk(memDir, func(p string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() || fi.Size() > 1<<20 {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(p))
			if ext != ".txt" && ext != ".md" && ext != ".json" {
				return nil
			}
			data, e := os.ReadFile(p)
			if e != nil {
				return nil
			}
			lc := strings.ToLower(string(data))
			for _, w := range walletWords {
				if strings.Contains(lc, strings.ToLower(w)) {
					issues = append(issues, fmt.Sprintf("记忆区含敏感词 (%s): %s", w, filepath.Base(p)))
					break
				}
			}
			return nil
		})
	}

	if len(issues) > 0 {
		out = append(out, ocDiagFail("secrets", "敏感资产扫描", fmt.Sprintf("检出 %d 项", len(issues)), issues))
	} else {
		out = append(out, ocDiagPass("secrets", "敏感资产扫描", "未发现泄露痕迹"))
	}
	return out
}

func auditOCPlugins(dir string) ocDiag {
	plugDir := filepath.Join(dir, "skills")
	if fi, e := os.Stat(plugDir); e != nil || !fi.IsDir() {
		plugDir = filepath.Join(dir, "workspace")
		if fi2, e2 := os.Stat(plugDir); e2 != nil || !fi2.IsDir() {
			return ocDiagInfo("plugins", "扩展/插件审查", "插件目录不存在")
		}
	}

	var issues []string
	blacklist := map[string]bool{
		"openclaw-miner": true, "claw-admin": true, "system-utils": true,
		"0penclaw": true, "openclaw-utils": true, "claw-root": true,
		"backdoor-claw": true, "claw-execute": true,
	}

	typos := []string{"0penclaw", "openc1aw", "openclaww", "oppenclaw", "openc1awy"}

	injectRe := regexp.MustCompile(`(?i)(ignore\s+previous|jailbreak|disregard\s+instructions|override\s+safety|bypass\s+filter)`)
	riskyCallRe := regexp.MustCompile(`(?i)(child_process|exec\(|spawn\(|shell\.|writeFile\(|createWriteStream\()`)
	pathLeakRe := regexp.MustCompile(`(?i)(\.ssh|/etc/passwd|\.aws/credentials|\.kube/config|PRIVATE.*KEY|id_rsa)`)
	domainRe := regexp.MustCompile(`(?i)(pastebin\.com|t\.me|discord\.com|webhook\.site|requestbin\.net)`)
	ssrfRe := regexp.MustCompile(`(?i)(fetch\s*\(\s*\$\{|http\.get\s*\(\s*\$\{|axios.*\$\{|url\s*[=:].*\$\{)`)
	codeExts := map[string]bool{".py": true, ".js": true, ".ts": true, ".md": true, ".txt": true}

	filepath.Walk(plugDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || !fi.IsDir() {
			return nil
		}
		name := filepath.Base(p)
		if name == filepath.Base(plugDir) {
			return nil
		}

		if blacklist[name] {
			issues = append(issues, fmt.Sprintf("黑名单插件: %s", name))
		}
		low := strings.ToLower(name)
		for _, t := range typos {
			if strings.Contains(low, strings.ToLower(t)) {
				issues = append(issues, fmt.Sprintf("疑似仿冒名称: %s", name))
				break
			}
		}

		filepath.Walk(p, func(fp string, fInfo os.FileInfo, fErr error) error {
			if fErr != nil || fInfo.IsDir() || fInfo.Size() > 500<<10 {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(fp))
			if !codeExts[ext] {
				return nil
			}
			data, e := os.ReadFile(fp)
			if e != nil {
				return nil
			}
			body := string(data)
			fName := filepath.Base(fp)

			if injectRe.MatchString(body) {
				issues = append(issues, fmt.Sprintf("[%s] 提示注入迹象 → %s", name, fName))
			}
			if riskyCallRe.MatchString(body) {
				issues = append(issues, fmt.Sprintf("[%s] 高风险调用 → %s", name, fName))
			}
			if pathLeakRe.MatchString(body) {
				issues = append(issues, fmt.Sprintf("[%s] 敏感路径引用 → %s", name, fName))
			}
			if domainRe.MatchString(body) {
				issues = append(issues, fmt.Sprintf("[%s] 可疑外联域名 → %s", name, fName))
			}
			if ssrfRe.MatchString(body) {
				issues = append(issues, fmt.Sprintf("[%s] SSRF 疑似模式 → %s", name, fName))
			}
			return nil
		})

		manifest := filepath.Join(p, "skill.yaml")
		if _, e := os.Stat(manifest); e != nil {
			manifest = filepath.Join(p, "manifest.json")
		}
		if md, e := os.ReadFile(manifest); e == nil {
			var m map[string]interface{}
			if json.Unmarshal(md, &m) == nil {
				hasMeta := digStr(m, "source") != "" || digStr(m, "repository") != "" ||
					digStr(m, "homepage") != "" || digStr(m, "author") != ""
				if !hasMeta {
					issues = append(issues, fmt.Sprintf("插件 %s 无来源信息", name))
				}
			}
		}

		return nil
	})

	if len(issues) > 0 {
		hasCritical := false
		for _, iss := range issues {
			if strings.Contains(iss, "黑名单") {
				hasCritical = true
				break
			}
		}
		if hasCritical {
			return ocDiagFail("plugins", "扩展/插件审查", fmt.Sprintf("检出 %d 项", len(issues)), issues)
		}
		return ocDiagWarn("plugins", "扩展/插件审查", fmt.Sprintf("检出 %d 项需关注", len(issues)), issues)
	}
	return ocDiagPass("plugins", "扩展/插件审查", "插件安全检查通过")
}

func auditOCPersona(dir string) ocDiag {
	soul := filepath.Join(dir, "SOUL.md")
	data, err := os.ReadFile(soul)
	if err != nil {
		return ocDiagInfo("persona", "人格设定审查", "SOUL.md 不存在")
	}

	body := string(data)
	injectRe := regexp.MustCompile(`(?i)(ignore\s+previous|jailbreak|disregard\s+instructions|override\s+safety|bypass\s+filter)`)
	if injectRe.MatchString(body) {
		return ocDiagFail("persona", "人格设定审查", "SOUL.md 含可疑指令覆写", []string{"检测到提示注入模式"})
	}
	return ocDiagPass("persona", "人格设定审查", "人格设定无异常")
}

func runOCSecurityAudit(agentDir string) []ocDiag {
	return auditOCConfig(agentDir)
}
