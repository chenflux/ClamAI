package main

import (
	"context"
	"net/http"
	"strings"
)

type ctxKey string

var providerSpecCtxKey ctxKey = "providerRouteSpec"
var requestBodyCtxKey ctxKey = "requestBody"
var isStreamCtxKey ctxKey = "isStream"

type ProviderRouteSpec struct {
	Name            string             `json:"name"`
	PathPrefix      string             `json:"path_prefix"`
	UpstreamBase    string             `json:"upstream_base"`
	UpstreamRewrite string             `json:"upstream_rewrite"`
	AuthType        string             `json:"auth_type"`
	Security        SecurityExtraction `json:"security"`
	Usage           UsageExtraction    `json:"usage"`
}

type SecurityExtraction struct {
	TextPaths []string `json:"text_paths"`
}

type UsageExtraction struct {
	ModelPath   string `json:"model_path"`
	UsagePath   string `json:"usage_path"`
	InputField  string `json:"input_field"`
	OutputField string `json:"output_field"`
}

func specFromContext(r *http.Request) *ProviderRouteSpec {
	v, _ := r.Context().Value(providerSpecCtxKey).(*ProviderRouteSpec)
	return v
}

func withSpec(r *http.Request, spec *ProviderRouteSpec) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), providerSpecCtxKey, spec))
}

func bodyFromContext(r *http.Request) []byte {
	v, _ := r.Context().Value(requestBodyCtxKey).([]byte)
	return v
}

func withBody(r *http.Request, body []byte) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), requestBodyCtxKey, body))
}

func isStreamFromContext(r *http.Request) bool {
	v, _ := r.Context().Value(isStreamCtxKey).(bool)
	return v
}

func withStreamFlag(r *http.Request, isStream bool) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), isStreamCtxKey, isStream))
}

func (p *ProxyServer) matchRoute(path string) *ProviderRouteSpec {
	for i := range p.providerRoutes {
		pp := p.providerRoutes[i].PathPrefix
		if strings.HasPrefix(path, pp+"/") || path == pp {
			return &p.providerRoutes[i]
		}
	}
	return nil
}

func buildUpstreamURL(requestPath string, spec *ProviderRouteSpec) string {
	suffix := strings.TrimPrefix(requestPath, spec.PathPrefix)
	if spec.UpstreamRewrite != "" {
		return spec.UpstreamBase + spec.UpstreamRewrite + suffix
	}
	return spec.UpstreamBase + suffix
}

var DefaultProviderRoutes = []ProviderRouteSpec{
	{
		Name: "openai", PathPrefix: "/openai/v1",
		UpstreamBase: "https://api.openai.com", UpstreamRewrite: "/v1",
		AuthType: "bearer",
		Security: SecurityExtraction{TextPaths: []string{"messages[*].content", "system"}},
		Usage:    UsageExtraction{ModelPath: "model", UsagePath: "usage", InputField: "prompt_tokens", OutputField: "completion_tokens"},
	},
	{
		Name: "anthropic", PathPrefix: "/anthropic/v1",
		UpstreamBase: "https://api.anthropic.com", UpstreamRewrite: "/v1",
		AuthType: "x-api-key",
		Security: SecurityExtraction{TextPaths: []string{"messages[*].content", "system"}},
		Usage:    UsageExtraction{ModelPath: "model", UsagePath: "usage", InputField: "input_tokens", OutputField: "output_tokens"},
	},
	{
		Name: "siliconflow", PathPrefix: "/siliconflow/v1",
		UpstreamBase: "https://api.siliconflow.cn", UpstreamRewrite: "/v1",
		AuthType: "bearer",
		Security: SecurityExtraction{TextPaths: []string{"messages[*].content"}},
		Usage:    UsageExtraction{ModelPath: "model", UsagePath: "usage", InputField: "prompt_tokens", OutputField: "completion_tokens"},
	},
	{
		Name: "deepseek", PathPrefix: "/deepseek/v1",
		UpstreamBase: "https://api.deepseek.com", UpstreamRewrite: "/v1",
		AuthType: "bearer",
		Security: SecurityExtraction{TextPaths: []string{"messages[*].content"}},
		Usage:    UsageExtraction{ModelPath: "model", UsagePath: "usage", InputField: "prompt_tokens", OutputField: "completion_tokens"},
	},
	{
		Name: "minimax", PathPrefix: "/minimax/v1",
		UpstreamBase: "https://api.minimax.chat", UpstreamRewrite: "/v1",
		AuthType: "bearer",
		Security: SecurityExtraction{TextPaths: []string{"messages[*].content"}},
		Usage:    UsageExtraction{ModelPath: "model", UsagePath: "usage", InputField: "prompt_tokens", OutputField: "completion_tokens"},
	},
	{
		Name: "minimax-tokenplan", PathPrefix: "/minimax-tokenplan/v1",
		UpstreamBase: "https://api.minimaxi.com/anthropic", UpstreamRewrite: "/v1",
		AuthType: "x-api-key",
		Security: SecurityExtraction{TextPaths: []string{"messages[*].content", "system"}},
		Usage:    UsageExtraction{ModelPath: "model", UsagePath: "usage", InputField: "input_tokens", OutputField: "output_tokens"},
	},
	{
		Name: "glm", PathPrefix: "/glm/v1",
		UpstreamBase: "https://open.bigmodel.cn/api/paas/v4", UpstreamRewrite: "",
		AuthType: "bearer",
		Security: SecurityExtraction{TextPaths: []string{"messages[*].content"}},
		Usage:    UsageExtraction{ModelPath: "model", UsagePath: "usage", InputField: "prompt_tokens", OutputField: "completion_tokens"},
	},
	{
		Name: "glm-coding", PathPrefix: "/glm-coding/v1",
		UpstreamBase: "https://open.bigmodel.cn/api/coding/paas/v4", UpstreamRewrite: "",
		AuthType: "bearer",
		Security: SecurityExtraction{TextPaths: []string{"messages[*].content"}},
		Usage:    UsageExtraction{ModelPath: "model", UsagePath: "usage", InputField: "prompt_tokens", OutputField: "completion_tokens"},
	},
	{
		Name: "doubao", PathPrefix: "/doubao/v1",
		UpstreamBase: "https://ark.cn-beijing.volces.com/api/v3", UpstreamRewrite: "",
		AuthType: "bearer",
		Security: SecurityExtraction{TextPaths: []string{"messages[*].content"}},
		Usage:    UsageExtraction{ModelPath: "model", UsagePath: "usage", InputField: "prompt_tokens", OutputField: "completion_tokens"},
	},
	{
		Name: "arkcode", PathPrefix: "/arkcode/v1",
		UpstreamBase: "https://ark.cn-beijing.volces.com/api/coding/v3", UpstreamRewrite: "",
		AuthType: "bearer",
		Security: SecurityExtraction{TextPaths: []string{"messages[*].content"}},
		Usage:    UsageExtraction{ModelPath: "model", UsagePath: "usage", InputField: "prompt_tokens", OutputField: "completion_tokens"},
	},
	{
		Name: "qwen", PathPrefix: "/qwen/v1",
		UpstreamBase: "https://dashscope.aliyuncs.com/compatible-mode", UpstreamRewrite: "/v1",
		AuthType: "bearer",
		Security: SecurityExtraction{TextPaths: []string{"messages[*].content"}},
		Usage:    UsageExtraction{ModelPath: "model", UsagePath: "usage", InputField: "prompt_tokens", OutputField: "completion_tokens"},
	},
	{
		Name: "moonshot", PathPrefix: "/moonshot/v1",
		UpstreamBase: "https://api.moonshot.cn", UpstreamRewrite: "/v1",
		AuthType: "bearer",
		Security: SecurityExtraction{TextPaths: []string{"messages[*].content"}},
		Usage:    UsageExtraction{ModelPath: "model", UsagePath: "usage", InputField: "prompt_tokens", OutputField: "completion_tokens"},
	},
	{
		Name: "yi", PathPrefix: "/yi/v1",
		UpstreamBase: "https://api.lingyiwanwu.com", UpstreamRewrite: "/v1",
		AuthType: "bearer",
		Security: SecurityExtraction{TextPaths: []string{"messages[*].content"}},
		Usage:    UsageExtraction{ModelPath: "model", UsagePath: "usage", InputField: "prompt_tokens", OutputField: "completion_tokens"},
	},
	{
		Name: "openrouter", PathPrefix: "/openrouter/v1",
		UpstreamBase: "https://openrouter.ai/api", UpstreamRewrite: "/v1",
		AuthType: "bearer",
		Security: SecurityExtraction{TextPaths: []string{"messages[*].content"}},
		Usage:    UsageExtraction{ModelPath: "model", UsagePath: "usage", InputField: "prompt_tokens", OutputField: "completion_tokens"},
	},
}
