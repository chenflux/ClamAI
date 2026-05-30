package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
)

func getWorkingDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return "unknown"
	}
	return dir
}

func parseFlags() *Config {
	config := &Config{}
	flag.StringVar(&config.Port, "port", "8080", "model proxy port (default 8080)")
	flag.StringVar(&config.AdminPort, "admin-port", "8081", "management API port (default 8081)")
	flag.StringVar(&config.Host, "host", "127.0.0.1", "listen address")
	flag.StringVar(&config.LogLevel, "log-level", "info", "log level")
	flag.StringVar(&config.ConfigPath, "config", "", "config file path")
	flag.StringVar(&config.ProxyURL, "proxy", "", "HTTP/SOCKS5 proxy URL")
	flag.BoolVar(&config.EnableTLS, "ssl", false, "enable TLS/HTTPS (use --ssl to enable)")
	flag.StringVar(&config.TLSCert, "tls-cert", "", "TLS cert file path")
	flag.StringVar(&config.TLSKey, "tls-key", "", "TLS private key file path")
	flag.Parse()

	if config.Host == "0.0.0.0" && config.AdminPort == "8081" {
		log.Printf("[MAIN] Running as server mode (0.0.0.0), WebUI available at http://%s:%s/admin/", config.Host, config.AdminPort)
	}
	if config.APIKey != "" {
		log.Printf("[MAIN] API key: %s", maskAPIKey(config.APIKey))
	} else {
		log.Printf("[MAIN] API key: (not set, using dynamic API keys from DB)")
	}
	log.Printf("[MAIN] Flags parsed: port=%s admin_port=%s host=%s ssl=%v",
		config.Port, config.AdminPort, config.Host, config.EnableTLS)
	return config
}

func NewProxyServer(config *Config) (*ProxyServer, error) {
	proxy := &ProxyServer{
		config:      config,
		router:      mux.NewRouter(),
		adminRouter: mux.NewRouter(),
		providers:   make(map[string]Provider),
		stats:       NewRequestStats(),
		logBuffer:   NewLogBuffer(maxLogEntries),
	}

	if err := initDB(); err != nil {
		return nil, fmt.Errorf("failed to init database: %w", err)
	}

	loadSystemAccessConfig()
	initSystemAccessCleanup()

	if err := proxy.initProviders(); err != nil {
		return nil, fmt.Errorf("failed to initialize providers: %w", err)
	}

	if config.ProxyURL != "" {
		if err := setProxy(config.ProxyURL); err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		log.Printf("[INFO] Proxy configured: %s", config.ProxyURL)
	} else {
		dbProxyURL := dbGetStringSetting("advanced.proxy_url", "")
		if dbProxyURL != "" {
			if err := setProxy(dbProxyURL); err != nil {
				log.Printf("[WARN] failed to apply DB proxy: %v", err)
			} else {
				log.Printf("[INFO] Proxy loaded from DB: %s", dbProxyURL)
			}
		}
	}

	initJWTSecret()

	rlCfg := dbLoadRateLimitConfig()
	rateLimitManager = newRateLimiterManager(rlCfg)

	loadedKeys, loadedByID := dbLoadAPIKeys()
	apiKeysMu.Lock()
	apiKeys = loadedKeys
	apiKeysByID = loadedByID
	apiKeysMu.Unlock()

	dbLoadStats(proxy.stats)
	dbLoadLogs(proxy.logBuffer)
	secConfigMu.Lock()
	secConfig = dbLoadSecurityConfig()
	secConfigMu.Unlock()
	if err := initVectorDB(); err != nil {
		log.Printf("[WARN] initVectorDB failed (non-fatal): %v", err)
	}
	setProxyServer(proxy)
	proxy.setupRoutes()
	go proxy.periodicSave()
	proxy.startPeriodicTaskScheduler()
	initSystemAnalysis()
	return proxy, nil
}

func (p *ProxyServer) initProviders() error {
	if apiKey := os.Getenv("OPENAI_API_KEY"); apiKey != "" {
		p.providers["openai"] = NewOpenAIProvider(apiKey)
		log.Printf("OpenAI provider initialized")
	}
	if apiKey := os.Getenv("ANTHROPIC_API_KEY"); apiKey != "" {
		p.providers["anthropic"] = NewAnthropicProvider(apiKey)
		log.Printf("Anthropic provider initialized")
	}
	if apiKey := os.Getenv("DEEPSEEK_API_KEY"); apiKey != "" {
		p.providers["deepseek"] = NewDeepSeekProvider(apiKey)
		log.Printf("DeepSeek provider initialized")
	}
	if apiKey := os.Getenv("MINIMAX_API_KEY"); apiKey != "" {
		p.providers["minimax"] = NewMiniMaxProvider(apiKey, os.Getenv("MINIMAX_GROUP_ID"))
		log.Printf("MiniMax provider initialized")
	}
	if apiKey := os.Getenv("SILICONFLOW_API_KEY"); apiKey != "" {
		p.providers["siliconflow"] = NewSiliconFlowProvider(apiKey)
		log.Printf("SiliconFlow provider initialized")
	}
	if apiKey := os.Getenv("GLM_API_KEY"); apiKey != "" {
		p.providers["glm"] = NewGLMProvider(apiKey)
		log.Printf("GLM provider initialized")
	}
	if apiKey := os.Getenv("DOUBAO_API_KEY"); apiKey != "" {
		p.providers["doubao"] = NewDoubaoProvider(apiKey)
		log.Printf("Doubao provider initialized")
	}
	if apiKey := os.Getenv("QWEN_API_KEY"); apiKey != "" {
		p.providers["qwen"] = NewQwenProvider(apiKey)
		log.Printf("Qwen provider initialized")
	}
	if apiKey := os.Getenv("MOONSHOT_API_KEY"); apiKey != "" {
		p.providers["moonshot"] = NewMoonshotProvider(apiKey)
		log.Printf("Moonshot provider initialized")
	}
	if apiKey := os.Getenv("YI_API_KEY"); apiKey != "" {
		p.providers["yi"] = NewYiProvider(apiKey)
		log.Printf("Yi provider initialized")
	}
	if apiKey := os.Getenv("OPENROUTER_API_KEY"); apiKey != "" {
		p.providers["openrouter"] = NewOpenRouterProvider(apiKey)
		log.Printf("OpenRouter provider initialized")
	}

	for _, pr := range dbListProviders() {
		ptype, _ := pr["provider_type"].(string)
		name, _ := pr["name"].(string)
		if ptype == "" || name == "" {
			continue
		}
		var apiKey string
		var baseURL string
		if keys, ok := pr["api_keys"].([]map[string]interface{}); ok && len(keys) > 0 {
			apiKey, _ = keys[0]["key_value"].(string)
		}
		if v, ok := pr["base_url"].(string); ok && v != "" {
			baseURL = v
		}
		if apiKey == "" {
			continue
		}
		if _, exists := p.providers[ptype]; exists {
			continue
		}
		log.Printf("[Init] Loading provider %s (%s) from database", name, ptype)
		if err := p.SetProviderKeyWithBaseURL(ptype, apiKey, baseURL); err != nil {
			log.Printf("[Init] Failed to load provider %s: %v", ptype, err)
		}
	}

	if len(p.providers) == 0 {
		log.Printf("Warning: No providers initialized. Set API keys in environment variables.")
	}

	for name, provider := range p.providers {
		go func(n string, pr Provider) {
			log.Printf("[FetchModels] Fetching models for %s...", n)
			pr.FetchModels()
		}(name, provider)
	}

	return nil
}

func (p *ProxyServer) setupRoutes() {
	log.Printf("[SETUP] setupRoutes called, host=%s adminPort=%s", p.config.Host, p.config.AdminPort)

	p.providerRoutes = make([]ProviderRouteSpec, len(DefaultProviderRoutes))
	copy(p.providerRoutes, DefaultProviderRoutes)

	log.Printf("[SETUP] Registering proxy routes on p.router (port %s)", p.config.Port)

	p.router.MethodNotAllowedHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowedOrigin := resolveAllowOrigin(r)
		if allowedOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, x-api-key, X-Requested-With")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	for i := range p.providerRoutes {
		spec := &p.providerRoutes[i]
		p.router.PathPrefix(spec.PathPrefix + "/").Handler(http.HandlerFunc(p.handleTransparentProxy))
		p.router.PathPrefix(spec.PathPrefix).Handler(http.HandlerFunc(p.handleTransparentProxy))
		log.Printf("[SETUP] Registered proxy route: %s → %s (auth: %s)", spec.PathPrefix, spec.UpstreamBase, spec.AuthType)
	}
	p.router.HandleFunc("/v1/models", p.handleListAllModels).Methods("GET")

	p.router.Use(p.corsMiddleware)
	p.router.Use(p.providerMatchMiddleware)
	p.router.Use(p.bodyReadMiddleware)
	p.router.Use(p.apiLoggingMiddleware)
	p.router.Use(p.rateLimitMiddleware)
	p.router.Use(p.securityMiddleware)
	p.router.Use(p.requestTrackingMiddleware)
	p.router.Use(p.authMiddleware)

	log.Printf("[SETUP] Registering admin routes on p.adminRouter (admin port %s)", p.config.AdminPort)

	p.adminRouter.MethodNotAllowedHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowedOrigin := resolveAllowOrigin(r)
		if allowedOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, x-api-key, X-Requested-With")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	p.adminRouter.HandleFunc("/health", p.handleHealth).Methods("GET")
	p.adminRouter.HandleFunc("/oauth/callback", p.handleOAuthCallback).Methods("GET")

	api := p.adminRouter.PathPrefix("/api/v1").Subrouter()

	api.HandleFunc("/config", p.handleGetConfig).Methods("GET")
	api.HandleFunc("/config", p.handleSaveConfig).Methods("PUT")
	api.HandleFunc("/config/reset", p.handleResetConfig).Methods("POST")
	api.HandleFunc("/config/backup", p.handleConfigBackup).Methods("GET")
	api.HandleFunc("/config/restore", p.handleConfigRestore).Methods("POST")
	api.HandleFunc("/profiles", p.handleListProfiles).Methods("GET")
	api.HandleFunc("/profiles", p.handleSaveAsProfile).Methods("POST")
	api.HandleFunc("/profiles/{id}", p.handleProfileAction).Methods("PUT")
	api.HandleFunc("/profiles/{id}", p.handleDeleteProfile).Methods("DELETE")
	api.HandleFunc("/app/info", p.handleAppInfo).Methods("GET")
	api.HandleFunc("/app/restart", p.handleAppRestart).Methods("POST")

	api.HandleFunc("/providers", p.handleListProviders).Methods("GET")
	api.HandleFunc("/providers", p.handleAddProvider).Methods("POST")
	api.HandleFunc("/providers/test", p.handleTestProvider).Methods("POST")
	api.HandleFunc("/providers/{name}/key", p.handleSetProviderKey).Methods("PUT")
	api.HandleFunc("/providers/{id}", p.handleUpdateProviderByID).Methods("PUT")
	api.HandleFunc("/providers/{id}", p.handleDeleteProviderByID).Methods("DELETE")
	api.HandleFunc("/api-keys", p.handleListAPIKeys).Methods("GET")
	api.HandleFunc("/api-keys", p.handleCreateAPIKey).Methods("POST")
	api.HandleFunc("/api-keys/{id}", p.handleDeleteAPIKey).Methods("DELETE")
	api.HandleFunc("/keys", p.handleListAPIKeys).Methods("GET")
	api.HandleFunc("/keys", p.handleCreateAPIKey).Methods("POST")
	api.HandleFunc("/keys/{id}", p.handleUpdateAPIKey).Methods("PUT")
	api.HandleFunc("/keys/{id}/toggle", p.handleToggleAPIKey).Methods("PUT")
	api.HandleFunc("/keys/{id}", p.handleDeleteAPIKey).Methods("DELETE")
	api.HandleFunc("/keys/{id}/reveal", p.handleRevealAPIKey).Methods("GET")
	api.HandleFunc("/stats/usage", p.handleStatsUsage).Methods("GET")
	api.HandleFunc("/stats/logs", p.handleStatsLogs).Methods("GET")
	api.HandleFunc("/stats/service-logs", p.handleServiceLogs).Methods("GET")
	api.HandleFunc("/stats/alerts", p.handleAlertStats).Methods("GET")
	api.HandleFunc("/stats/alert-severity", p.handleAlertSeverityStats).Methods("GET")
	api.HandleFunc("/stats/callers", p.handleCallerTop10).Methods("GET")
	api.HandleFunc("/stats/security-tokens", p.handleSecurityTokenStats).Methods("GET")
	api.HandleFunc("/proxy/test", p.handleProxyTest).Methods("GET")
	api.HandleFunc("/proxy/test-chat", p.handleProxyTestChat).Methods("POST")
	api.HandleFunc("/providers/sync-all", p.handleSyncAllProviders).Methods("POST")
	api.HandleFunc("/security/check", p.handleContentCheck).Methods("POST")
	api.HandleFunc("/skills/history", p.handleSkillsHistory).Methods("GET")
	api.HandleFunc("/profile/history", p.handleProfileAnalysisHistory).Methods("GET")
	api.HandleFunc("/analysis/tasks", p.handleCreateAnalysisTask).Methods("POST")
	api.HandleFunc("/analysis/tasks", p.handleListAnalysisTasks).Methods("GET")
	api.HandleFunc("/analysis/tasks/{id}", p.handleDeleteAnalysisTask).Methods("DELETE")
	api.HandleFunc("/analysis/tasks/{id}", p.handleUpdateAnalysisTask).Methods("PUT")
	api.HandleFunc("/analysis/tasks/{id}/start", p.handleStartAnalysisTask).Methods("POST")
	api.HandleFunc("/analysis/tasks/{id}/stop", p.handleStopAnalysisTask).Methods("POST")
	api.HandleFunc("/analysis/tasks/{id}/history", p.handleAnalysisTaskHistory).Methods("GET")
	api.HandleFunc("/skills/tasks", p.handleCreateSkillsTask).Methods("POST")
	api.HandleFunc("/skills/tasks", p.handleListSkillsTasks).Methods("GET")
	api.HandleFunc("/skills/tasks/{id}", p.handleDeleteSkillsTask).Methods("DELETE")
	api.HandleFunc("/skills/tasks/{id}", p.handleUpdateSkillsTask).Methods("PUT")
	api.HandleFunc("/skills/tasks/{id}/start", p.handleStartSkillsTask).Methods("POST")
	api.HandleFunc("/skills/tasks/{id}/stop", p.handleStopSkillsTask).Methods("POST")
	api.HandleFunc("/skills/tasks/{id}/history", p.handleSkillsTaskHistory).Methods("GET")
	api.HandleFunc("/agent/scan-logs", p.handleAgentLogScan).Methods("POST")
	api.HandleFunc("/agent/env-check", p.handleAgentEnvCheck).Methods("POST")
	api.HandleFunc("/agent/discover", p.handleAgentDiscover).Methods("GET")
	api.HandleFunc("/agent/deep-check", p.handleAgentDeepCheck).Methods("POST")
	api.HandleFunc("/agent/push-skills", p.handleAgentPushSkills).Methods("POST")

	p.setupAgentSecurityRoutes(api)
	log.Printf("[SETUP] Agent Security routes registered")

	p.adminRouter.HandleFunc("/analysis/v1/chat/completions", p.handleAnalysisChat).Methods("POST")

	p.setupSecurityRoutes(api)
	log.Printf("[SETUP] Security routes registered")
	p.setupThreatRoutes(api)
	log.Printf("[SETUP] Threat routes registered")
	p.setupVectorRoutes(api)
	log.Printf("[SETUP] Vector routes registered")
	p.setupSystemAnalysisRoutes(api)
	log.Printf("[SETUP] SystemAnalysis routes registered")
	p.setupRateLimitRoutes(api)
	log.Printf("[SETUP] RateLimit routes registered")
	p.setupAuthRoutes(api)
	log.Printf("[SETUP] Auth routes registered")
	p.setupUserRoutes(api)
	log.Printf("[SETUP] User routes registered")
	p.setupAuditRoutes(api)
	log.Printf("[SETUP] Audit routes registered")
	p.setupSystemAccessRoutes(api)
	log.Printf("[SETUP] System access routes registered")
	p.setupFrontendRoutes()
	log.Printf("[SETUP] Frontend routes registered (or skipped if not server mode)")

	p.adminRouter.Use(p.corsMiddleware)
	p.adminRouter.Use(p.requestIDMiddleware)
	p.adminRouter.Use(p.ipAccessMiddleware)
	p.adminRouter.Use(p.honeypotMiddleware)
	p.adminRouter.Use(p.apiLoggingMiddleware)
	p.adminRouter.Use(p.rateLimitMiddleware)
	p.adminRouter.Use(p.adminAuthMiddleware)
	p.adminRouter.Use(p.securityMiddleware)
	p.adminRouter.Use(p.requestTrackingMiddleware)
	p.adminRouter.Use(p.authMiddleware)
	log.Printf("[SETUP] All admin middleware registered (order: stripInternal, cors, apiLog, rateLimit, adminAuth, security, tracking, auth)")
}

func (p *ProxyServer) periodicSave() {
	saveTicker := time.NewTicker(10 * time.Second)
	cleanTicker := time.NewTicker(1 * time.Hour)
	oauthCleanTicker := time.NewTicker(5 * time.Minute)
	defer saveTicker.Stop()
	defer cleanTicker.Stop()
	defer oauthCleanTicker.Stop()
	for {
		select {
		case <-saveTicker.C:
			dbSaveStats(p.stats)
		case <-cleanTicker.C:
			dbCleanupLogs()
		case <-oauthCleanTicker.C:
			cleanupOAuthStates()
		}
	}
}
