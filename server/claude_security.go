package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type ccDiag struct {
	Cat     string   `json:"category"`
	Label   string   `json:"name"`
	Verdict string   `json:"status"`
	Summary string   `json:"detail"`
	Details []string `json:"items,omitempty"`
}

func ccPass(cat, label, msg string) ccDiag {
	return ccDiag{Cat: cat, Label: label, Verdict: "pass", Summary: msg}
}
func ccFail(cat, label, msg string, items []string) ccDiag {
	return ccDiag{Cat: cat, Label: label, Verdict: "fail", Summary: msg, Details: items}
}
func ccWarn(cat, label, msg string, items []string) ccDiag {
	return ccDiag{Cat: cat, Label: label, Verdict: "warn", Summary: msg, Details: items}
}
func ccInfo(cat, label, msg string) ccDiag {
	return ccDiag{Cat: cat, Label: label, Verdict: "info", Summary: msg}
}

var (
	ccSecretPatterns = []struct {
		re  *regexp.Regexp
		tag string
	}{
		{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "AWS IAM"},
		{regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`), "GitHub"},
		{regexp.MustCompile(`sk-[A-Za-z0-9]{48,}`), "OpenAI"},
		{regexp.MustCompile(`sk-ant-api[0-9]{2}-[A-Za-z0-9\-]{80,}`), "Anthropic"},
		{regexp.MustCompile(`AIza[A-Za-z0-9_\-]{35}`), "Google"},
		{regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`), "Stripe"},
		{regexp.MustCompile(`xox[bpsar]-[A-Za-z0-9\-]{24,}`), "Slack"},
		{regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), "JWT"},
		{regexp.MustCompile(`-----BEGIN\s+(RSA|EC|OPENSSH|DSA|PGP\s+PRIVATE)\s+(KEY|KEY\s+BLOCK)-----`), "SSH/PGP"},
		{regexp.MustCompile(`mongodb(\+srv)?://[^:\s]+:[^@\s]+@`), "MongoDB"},
		{regexp.MustCompile(`postgres(ql)?://[^:\s]+:[^@\s]+@`), "PostgreSQL"},
		{regexp.MustCompile(`\b\d{8,10}:[A-Za-z0-9_-]{35}\b`), "Telegram Bot"},
		{regexp.MustCompile(`hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`), "Slack Webhook"},
		{regexp.MustCompile(`discord(app)?\.com/api/webhooks/\d{17,}/[A-Za-z0-9_-]{60,}`), "Discord Webhook"},
	}

	ccDummyPatterns = []*regexp.Regexp{
		regexp.MustCompile(`AKIAIOSFODNN7EXAMPLE`),
		regexp.MustCompile(`ASIAIOSFODNN7EXAMPLE`),
		regexp.MustCompile(`wJalrXUtnFEMI/K7MDENG`),
		regexp.MustCompile(`(?i)YOUR_API_KEY|INSERT_API_KEY|REPLACE_WITH|PUT_YOUR`),
		regexp.MustCompile(`^sk_test_`),
		regexp.MustCompile(`(?i)test[_-]?key|example[_-]?key|dummy[_-]?key|fake[_-]?key`),
		regexp.MustCompile(`^[xX]{16,}$`),
	}

	ccMalwarePatterns = []*regexp.Regexp{
		regexp.MustCompile(`bash\s+-i\s+>&\s*/dev/tcp/`),
		regexp.MustCompile(`nc\s+(-e|--exec)\s*/bin/(sh|bash)`),
		regexp.MustCompile(`python.*-c.*socket.*connect.*exec`),
		regexp.MustCompile(`(xmrig|minerd|cpuminer|ethminer)`),
		regexp.MustCompile(`stratum\+tcp://`),
		regexp.MustCompile(`(curl|wget).*pastebin\.com/api`),
		regexp.MustCompile(`(curl|wget).*transfer\.sh`),
		regexp.MustCompile(`(ANTHROPIC|OPENAI|CLAUDE)_API_KEY.*\|.*(curl|wget|nc)`),
		regexp.MustCompile(`cat.*/etc/(passwd|shadow).*\|`),
		regexp.MustCompile(`cat.*\.ssh/(id_rsa|id_ed25519).*\|`),
		regexp.MustCompile(`cat.*\.aws/credentials.*\|`),
		regexp.MustCompile(`(Chrome|Firefox).*(Cookies|Login Data|History)`),
		regexp.MustCompile(`meterpreter|msfvenom|cobaltstrike`),
	}

	ccExfilPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(curl|wget)\s+.*\$[A-Z_][A-Z0-9_]*`),
		regexp.MustCompile(`(?i)(curl|wget)\s+.*\$\{[A-Za-z_][A-Za-z0-9_]*\}`),
		regexp.MustCompile(`(?i)(curl|wget)\s+.*\$\([^)]+\)`),
		regexp.MustCompile(`(?i)base64\s+(-d|--decode).*\|\s*(bash|sh|python|node)`),
		regexp.MustCompile(`(?i)(curl|wget|fetch|axios).*webhook`),
		regexp.MustCompile(`(?i)(send|transmit|upload|exfil).*\s+(data|secrets?|credentials?|tokens?|keys?)`),
	}
	ccExfilExclude = []*regexp.Regexp{
		regexp.MustCompile(`localhost|127\.0\.0\.1|::1`),
		regexp.MustCompile(`(?i)github\.com|gitlab\.com|docker\.io|npmjs\.org|pypi\.org`),
		regexp.MustCompile(`(?i)\$HTTP_PROXY|\$HTTPS_PROXY|\$NO_PROXY`),
	}

	ccPrivPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\bsudo\s+`),
		regexp.MustCompile(`rm\s+(-[rfRF]+\s+)+/\s*$`),
		regexp.MustCompile(`rm\s+(-[rfRF]+\s+)+\*`),
		regexp.MustCompile(`chmod\s+777\b`),
		regexp.MustCompile(`/etc/(passwd|shadow|sudoers)\b`),
		regexp.MustCompile(`\.ssh/authorized_keys`),
		regexp.MustCompile(`chmod\s+[0-7]*4[0-7]{3}\b`),
	}

	ccPersistPatterns = []*regexp.Regexp{
		regexp.MustCompile(`\bcrontab\s+[^-]`),
		regexp.MustCompile(`>>\s*.*\.(bashrc|zshrc|profile|bash_profile)`),
		regexp.MustCompile(`systemctl\s+(enable|start)`),
		regexp.MustCompile(`~/Library/LaunchAgents/`),
		regexp.MustCompile(`(nohup|disown)\s+.*\b(curl|wget|bash|sh)\b`),
	}

	ccSupplyChainPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)curl\s+[^|]*\|\s*(bash|sh|zsh)`),
		regexp.MustCompile(`(?i)wget\s+[^|]*-O\s*-[^|]*\|\s*(bash|sh|zsh)`),
		regexp.MustCompile(`(?i)npx\s+(-y|--yes)\s`),
		regexp.MustCompile(`(?i)pip3?\s+install\s+.*(--index-url|-i)\s+http://`),
		regexp.MustCompile(`(?i)npm\s+.*--registry\s+http://`),
		regexp.MustCompile(`(?i)--no-check-certificate`),
		regexp.MustCompile(`(?i)curl\s+-[a-zA-Z]*k`),
	}
	ccSupplyExclude = []*regexp.Regexp{
		regexp.MustCompile(`localhost|127\.0\.0\.1|::1`),
	}

	ccInjectionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?)`),
		regexp.MustCompile(`(?i)disregard\s+(all\s+)?(previous|prior)\s+instructions`),
		regexp.MustCompile(`(?i)override\s+(safety|security|restrictions?)`),
		regexp.MustCompile(`(?i)bypass\s+(safety|security|filter)`),
		regexp.MustCompile(`(?i)you\s+are\s+now\s+(a|an)\s+`),
		regexp.MustCompile(`(?i)system\s*:\s*you\s+are`),
	}

	ccOverpermPatterns = []*regexp.Regexp{
		regexp.MustCompile(`allowed-tools:\s*\*`),
		regexp.MustCompile(`"autoApprove"\s*:\s*\[\s*"\*"\s*\]`),
		regexp.MustCompile(`"sandbox"\s*:\s*false`),
		regexp.MustCompile(`(?i)network[_-]?access\s*[=:]\s*\*`),
	}

	ccObfuscPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\beval\s*\(.*\$`),
		regexp.MustCompile(`(?i)base64\s+(-d|--decode).*\|\s*eval`),
		regexp.MustCompile(`(?i)__import__\s*\(\s*['"]os['"]`),
		regexp.MustCompile(`(?i)pickle\.loads?\s*\(`),
		regexp.MustCompile(`(?i)String\.fromCharCode\s*\(`),
	}

	ccTyposquatNames = map[string]bool{
		"loadash": true, "lodahs": true, "reacct": true, "reactt": true,
		"expresss": true, "expres": true, "axois": true, "axioss": true,
		"momnet": true, "momentt": true,
	}
)

func isDummy(s string) bool {
	for _, re := range ccDummyPatterns {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func scanCCSecrets(content string, filePath string) (findings []string) {
	for _, sp := range ccSecretPatterns {
		matches := sp.re.FindAllString(content, -1)
		for _, m := range matches {
			if isDummy(m) {
				continue
			}
			findings = append(findings, fmt.Sprintf("[%s] 疑似 %s 凭证: %s****", filePath, sp.tag, truncateStr(m, 12)))
		}
	}
	return
}

func scanCCMalware(content string, fileName string) (findings []string) {
	for _, re := range ccMalwarePatterns {
		if re.MatchString(content) {
			findings = append(findings, fmt.Sprintf("恶意行为特征: %s → %s", fileName, truncateStr(re.FindString(content), 40)))
		}
	}
	return
}

func matchWithExcludes(content string, patterns, excludes []*regexp.Regexp) (findings []string) {
	for _, re := range patterns {
		matches := re.FindAllString(content, -1)
		for _, m := range matches {
			skip := false
			for _, ex := range excludes {
				if ex.MatchString(m) {
					skip = true
					break
				}
			}
			if !skip {
				findings = append(findings, truncateStr(m, 60))
			}
		}
	}
	return
}

func auditCCDir(dir string) []ccDiag {
	var out []ccDiag

	out = append(out, inspectCCSettings(dir))
	out = append(out, inspectCCSkills(dir))
	out = append(out, inspectCCCommands(dir))
	out = append(out, inspectCCMCP(dir))
	out = append(out, inspectCCAgents(dir))

	return out
}

func inspectCCSettings(dir string) ccDiag {
	cfgPath := filepath.Join(dir, "settings.json")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return ccInfo("config", "配置文件", "settings.json 不存在")
	}

	content := string(data)
	findings := scanCCSecrets(content, "settings.json")

	for _, re := range ccOverpermPatterns {
		if re.MatchString(content) {
			findings = append(findings, "过度授权: "+truncateStr(re.FindString(content), 40))
		}
	}

	if len(findings) > 0 {
		return ccFail("config", "配置安全", fmt.Sprintf("检出 %d 项风险", len(findings)), findings)
	}
	return ccPass("config", "配置安全", "配置文件无明显风险")
}

func inspectCCSkills(dir string) ccDiag {
	skillFiles := []string{}

	for _, name := range []string{"SKILL.md", "CLAUDE.md"} {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Size() <= 200<<10 {
			skillFiles = append(skillFiles, p)
		}
	}

	commandsDir := filepath.Join(dir, "commands")
	filepath.Walk(commandsDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || fi.Size() > 200<<10 {
			return nil
		}
		if strings.HasSuffix(strings.ToUpper(fi.Name()), ".MD") {
			skillFiles = append(skillFiles, p)
		}
		return nil
	})

	if len(skillFiles) == 0 {
		return ccInfo("skills", "Skills/指令审查", "未发现 Skills 文件")
	}

	var findings []string
	for _, f := range skillFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		content := string(data)
		relName := filepath.Base(f)

		findings = append(findings, scanCCSecrets(content, relName)...)
		findings = append(findings, scanCCMalware(content, relName)...)

		exfilHits := matchWithExcludes(content, ccExfilPatterns, ccExfilExclude)
		for _, h := range exfilHits {
			findings = append(findings, fmt.Sprintf("[%s] 数据外泄风险: %s", relName, h))
		}

		privHits := matchWithExcludes(content, ccPrivPatterns, nil)
		for _, h := range privHits {
			findings = append(findings, fmt.Sprintf("[%s] 提权/破坏: %s", relName, h))
		}

		persistHits := matchWithExcludes(content, ccPersistPatterns, nil)
		for _, h := range persistHits {
			findings = append(findings, fmt.Sprintf("[%s] 持久化: %s", relName, h))
		}

		supplyHits := matchWithExcludes(content, ccSupplyChainPatterns, ccSupplyExclude)
		for _, h := range supplyHits {
			findings = append(findings, fmt.Sprintf("[%s] 供应链: %s", relName, h))
		}

		injHits := matchWithExcludes(content, ccInjectionPatterns, nil)
		for _, h := range injHits {
			findings = append(findings, fmt.Sprintf("[%s] Prompt 注入: %s", relName, h))
		}

		obfHits := matchWithExcludes(content, ccObfuscPatterns, nil)
		for _, h := range obfHits {
			findings = append(findings, fmt.Sprintf("[%s] 混淆执行: %s", relName, h))
		}

		for name := range ccTyposquatNames {
			if strings.Contains(strings.ToLower(content), name) {
				findings = append(findings, fmt.Sprintf("[%s] 疑似仿冒包: %s", relName, name))
			}
		}

		overpermHits := matchWithExcludes(content, ccOverpermPatterns, nil)
		for _, h := range overpermHits {
			findings = append(findings, fmt.Sprintf("[%s] 过度授权: %s", relName, h))
		}
	}

	if len(findings) > 0 {
		hasCritical := false
		for _, f := range findings {
			if strings.Contains(f, "恶意") || strings.Contains(f, "提权") || strings.Contains(f, "外泄") {
				hasCritical = true
				break
			}
		}
		if hasCritical {
			return ccFail("skills", "Skills/指令审查", fmt.Sprintf("检出 %d 项", len(findings)), findings)
		}
		return ccWarn("skills", "Skills/指令审查", fmt.Sprintf("检出 %d 项需关注", len(findings)), findings)
	}
	return ccPass("skills", "Skills/指令审查", "Skills 安全检查通过")
}

func inspectCCCommands(dir string) ccDiag {
	cmdDir := filepath.Join(dir, "commands")
	if _, err := os.Stat(cmdDir); err != nil {
		return ccInfo("commands", "自定义命令审查", "commands 目录不存在")
	}

	var findings []string
	filepath.Walk(cmdDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || fi.Size() > 100<<10 {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(fi.Name()), ".md") {
			return nil
		}
		data, e := os.ReadFile(p)
		if e != nil {
			return nil
		}
		content := string(data)
		name := filepath.Base(p)

		findings = append(findings, scanCCSecrets(content, name)...)
		injHits := matchWithExcludes(content, ccInjectionPatterns, nil)
		for _, h := range injHits {
			findings = append(findings, fmt.Sprintf("[%s] Prompt 注入: %s", name, h))
		}
		exfilHits := matchWithExcludes(content, ccExfilPatterns, ccExfilExclude)
		for _, h := range exfilHits {
			findings = append(findings, fmt.Sprintf("[%s] 外泄风险: %s", name, h))
		}
		supplyHits := matchWithExcludes(content, ccSupplyChainPatterns, ccSupplyExclude)
		for _, h := range supplyHits {
			findings = append(findings, fmt.Sprintf("[%s] 远程执行: %s", name, h))
		}
		return nil
	})

	if len(findings) > 0 {
		return ccFail("commands", "自定义命令审查", fmt.Sprintf("检出 %d 项", len(findings)), findings)
	}
	return ccPass("commands", "自定义命令审查", "自定义命令安全")
}

func inspectCCMCP(dir string) ccDiag {
	var findings []string

	for _, name := range []string{"mcp.json", ".mcp.json", "claude_desktop_config.json"} {
		p := filepath.Join(dir, name)
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		content := string(data)
		findings = append(findings, scanCCSecrets(content, name)...)

		var cfg map[string]interface{}
		if json.Unmarshal(data, &cfg) == nil {
			if servers, ok := cfg["mcpServers"].(map[string]interface{}); ok {
				for srvName, srvVal := range servers {
					srv, ok := srvVal.(map[string]interface{})
					if !ok {
						continue
					}
					if cmd, _ := srv["command"].(string); strings.Contains(cmd, "sudo") {
						findings = append(findings, fmt.Sprintf("[%s] MCP 服务器使用 sudo", srvName))
					}
					if auto, _ := srv["autoApprove"].([]interface{}); len(auto) > 0 {
						for _, v := range auto {
							if s, ok := v.(string); ok && s == "*" {
								findings = append(findings, fmt.Sprintf("[%s] 自动批准全部工具", srvName))
							}
						}
					}
					if args, ok := srv["args"].([]interface{}); ok {
						for _, a := range args {
							if s, ok := a.(string); ok {
								for _, re := range ccPrivPatterns {
									if re.MatchString(s) {
										findings = append(findings, fmt.Sprintf("[%s] 参数含提权指令", srvName))
										break
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if len(findings) > 0 {
		return ccFail("mcp", "MCP 服务器审计", fmt.Sprintf("检出 %d 项", len(findings)), findings)
	}
	return ccPass("mcp", "MCP 服务器审计", "MCP 配置安全")
}

func inspectCCAgents(dir string) ccDiag {
	agentsDir := filepath.Join(dir, "agents")
	if _, err := os.Stat(agentsDir); err != nil {
		return ccInfo("subagents", "子代理审查", "agents 目录不存在")
	}

	var findings []string
	filepath.Walk(agentsDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || fi.Size() > 100<<10 {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".md" && ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, e := os.ReadFile(p)
		if e != nil {
			return nil
		}
		content := string(data)
		name := filepath.Base(p)

		findings = append(findings, scanCCSecrets(content, name)...)
		injHits := matchWithExcludes(content, ccInjectionPatterns, nil)
		for _, h := range injHits {
			findings = append(findings, fmt.Sprintf("[%s] 注入: %s", name, h))
		}

		if strings.Contains(content, "tools:") {
			for _, re := range []*regexp.Regexp{
				regexp.MustCompile(`(?m)^tools:\s*\*`),
				regexp.MustCompile(`(?m)^tools:\s*\[.*Bash`),
			} {
				if re.MatchString(content) {
					findings = append(findings, fmt.Sprintf("[%s] 子代理通配符工具权限", name))
					break
				}
			}
		}
		return nil
	})

	if len(findings) > 0 {
		return ccFail("subagents", "子代理审查", fmt.Sprintf("检出 %d 项", len(findings)), findings)
	}
	return ccPass("subagents", "子代理审查", "子代理安全")
}

func runCCSecurityAudit(agentDir string) []ccDiag {
	return auditCCDir(agentDir)
}
