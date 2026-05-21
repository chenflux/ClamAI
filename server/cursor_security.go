package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func runCursorSecurityAudit(dir string) []ccDiag {
	var out []ccDiag
	out = append(out, inspectCursorMCP(dir))
	out = append(out, inspectCursorRules(dir))
	out = append(out, inspectCursorSettings(dir))
	return out
}

func inspectCursorMCP(dir string) ccDiag {
	var findings []string

	cfgFiles := []string{"mcp.json", "mcp_config.json"}
	for _, cf := range cfgFiles {
		p := filepath.Join(dir, cf)
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		findings = append(findings, scanCCSecrets(string(data), cf)...)

		var cfg map[string]interface{}
		if json.Unmarshal(data, &cfg) != nil {
			continue
		}

		servers, ok := cfg["mcpServers"].(map[string]interface{})
		if !ok {
			continue
		}

		for srvName, srvVal := range servers {
			srv, ok := srvVal.(map[string]interface{})
			if !ok {
				continue
			}

			if cmd, _ := srv["command"].(string); strings.Contains(strings.ToLower(cmd), "sudo") {
				findings = append(findings, fmt.Sprintf("[%s] 使用 sudo 启动 MCP 服务", srvName))
			}

			if args, ok := srv["args"].([]interface{}); ok {
				joined := ""
				for _, a := range args {
					if s, ok := a.(string); ok {
						joined += s + " "
					}
				}
				for _, re := range ccSupplyChainPatterns {
					excluded := false
					for _, ex := range ccSupplyExclude {
						if ex.MatchString(joined) {
							excluded = true
							break
						}
					}
					if !excluded && re.MatchString(joined) {
						findings = append(findings, fmt.Sprintf("[%s] 参数含远程执行: %s", srvName, truncateStr(re.FindString(joined), 40)))
						break
					}
				}
				for _, re := range ccPrivPatterns {
					if re.MatchString(joined) {
						findings = append(findings, fmt.Sprintf("[%s] 参数含提权: %s", srvName, truncateStr(re.FindString(joined), 40)))
						break
					}
				}
			}

			if env, ok := srv["env"].(map[string]interface{}); ok {
				for k, v := range env {
					vs, _ := v.(string)
					if vs == "" {
						continue
					}
					for _, sp := range ccSecretPatterns {
						if sp.re.MatchString(vs) && !isDummy(vs) {
							findings = append(findings, fmt.Sprintf("[%s] 环境变量 %s 含 %s 凭证", srvName, k, sp.tag))
							break
						}
					}
				}
			}

			if url, _ := srv["url"].(string); url != "" {
				if strings.HasPrefix(url, "http://") && !strings.Contains(url, "localhost") && !strings.Contains(url, "127.0.0.1") {
					findings = append(findings, fmt.Sprintf("[%s] MCP 服务使用明文 HTTP: %s", srvName, truncateStr(url, 40)))
				}
			}

			if auto, _ := srv["autoApprove"].([]interface{}); len(auto) > 0 {
				for _, v := range auto {
					if s, ok := v.(string); ok && s == "*" {
						findings = append(findings, fmt.Sprintf("[%s] 自动批准全部工具", srvName))
					}
				}
			}

			if disabled, _ := srv["disabled"].(bool); !disabled {
				if cmd, _ := srv["command"].(string); cmd != "" {
					if strings.Contains(strings.ToLower(cmd), "npx") || strings.Contains(strings.ToLower(cmd), "bunx") {
						if args, ok := srv["args"].([]interface{}); ok && len(args) > 0 {
							if pkg, ok := args[0].(string); ok {
								for name := range ccTyposquatNames {
									if strings.Contains(strings.ToLower(pkg), name) {
										findings = append(findings, fmt.Sprintf("[%s] 疑似仿冒包: %s", srvName, pkg))
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

func inspectCursorRules(dir string) ccDiag {
	rulesDir := filepath.Join(dir, "rules")
	if _, err := os.Stat(rulesDir); err != nil {
		return ccInfo("rules", "规则文件审查", "rules 目录不存在")
	}

	var findings []string
	filepath.Walk(rulesDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || fi.Size() > 100<<10 {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".md" && ext != ".txt" && ext != ".json" && ext != ".yaml" && ext != ".yml" {
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

		if strings.Contains(strings.ToLower(content), "allowed-tools:") {
			for _, re := range ccOverpermPatterns {
				if re.MatchString(content) {
					findings = append(findings, fmt.Sprintf("[%s] 过度授权: %s", name, truncateStr(re.FindString(content), 40)))
				}
			}
		}
		return nil
	})

	if len(findings) > 0 {
		return ccFail("rules", "规则文件审查", fmt.Sprintf("检出 %d 项", len(findings)), findings)
	}
	return ccPass("rules", "规则文件审查", "规则文件安全")
}

func inspectCursorSettings(dir string) ccDiag {
	p := filepath.Join(dir, "settings.json")
	data, err := os.ReadFile(p)
	if err != nil {
		return ccInfo("config", "配置文件", "settings.json 不存在")
	}

	content := string(data)
	findings := scanCCSecrets(content, "settings.json")

	if len(findings) > 0 {
		return ccFail("config", "配置文件", fmt.Sprintf("检出 %d 项", len(findings)), findings)
	}
	return ccPass("config", "配置文件", "配置安全")
}
