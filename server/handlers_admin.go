package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

func (p *ProxyServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	total := p.stats.TotalRequests.Load()
	active := p.stats.ActiveRequests.Load()
	success := p.stats.SuccessRequests.Load()
	errCount := p.stats.ErrorRequests.Load()

	health := map[string]interface{}{
		"status":  "healthy",
		"version": "1.0.0",
		"stats": map[string]interface{}{
			"total_requests":   total,
			"active_requests":  active,
			"success_requests": success,
			"error_requests":   errCount,
		},
	}
	jsonBytes, _ := json.Marshal(health)
	w.Write(jsonBytes)
}

func (p *ProxyServer) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	provider := r.URL.Query().Get("provider")

	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	log.Printf("OAuth callback: provider=%s, state=%s", provider, state)

	tauriURL := "http://127.0.0.1:1420/oauth/callback"
	callbackData := map[string]string{
		"provider": provider,
		"code":     code,
		"state":    state,
	}
	jsonData, _ := json.Marshal(callbackData)

	safeGo(func() {
		req, _ := http.NewRequest("POST", tauriURL, bytes.NewReader(jsonData))
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 5 * time.Second}
		client.Do(req)
	})

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`<!DOCTYPE html><html><head><title>Authentication Successful</title><meta http-equiv="refresh" content="3;url=http://127.0.0.1:1420"><style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#1a1a2e;color:#e0e0e0}.container{text-align:center;background:#16213e;padding:3rem;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,.3)}h1{color:#4ade80;margin-bottom:1rem}p{color:#9ca3af;margin-bottom:1rem}.spinner{width:40px;height:40px;border:3px solid #374151;border-top-color:#4ade80;border-radius:50%;animation:spin 1s linear infinite;margin:1rem auto}@keyframes spin{to{transform:rotate(360deg)}}</style></head><body><div class="container"><h1>Authentication Successful</h1><p>Returning to ClamAI...</p><div class="spinner"></div></div></body></html>`))
}

func (p *ProxyServer) handleStartOAuth(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider    string `json:"provider"`
		RedirectURI string `json:"redirect_uri"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	state := generateOAuthState()
	oauthStatesMu.Lock()
	oauthStates[state] = &OAuthStateInfo{
		Provider:    req.Provider,
		RedirectURI: req.RedirectURI,
		CreatedAt:   time.Now(),
	}
	oauthStatesMu.Unlock()

	authURL := buildAuthURL(req.Provider, state, req.RedirectURI)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"state":    state,
		"auth_url": authURL,
	})
}

func generateOAuthState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func buildAuthURL(provider, state, redirectURI string) string {
	switch provider {
	case "gemini":
		return fmt.Sprintf("https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=https://www.googleapis.com/auth/generative-language.tts&state=%s",
			os.Getenv("GEMINI_CLIENT_ID"), redirectURI, state)
	case "qwen":
		return fmt.Sprintf("https://qwen.aliyun.com/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=api_access&state=%s",
			os.Getenv("QWEN_CLIENT_ID"), redirectURI, state)
	default:
		return ""
	}
}

func getProviderNames(providers map[string]Provider) []string {
	names := make([]string, 0, len(providers))
	for k := range providers {
		names = append(names, k)
	}
	return names
}

func maskProviderKeys(providers []map[string]interface{}) []map[string]interface{} {
	masked := make([]map[string]interface{}, len(providers))
	for i, pr := range providers {
		m := make(map[string]interface{}, len(pr))
		for k, v := range pr {
			m[k] = v
		}
		if keys, ok := pr["api_keys"].([]map[string]interface{}); ok {
			newKeys := make([]map[string]interface{}, len(keys))
			for j, km := range keys {
				nkm := make(map[string]interface{}, len(km))
				for k2, v2 := range km {
					nkm[k2] = v2
				}
				if kv, ok := nkm["key_value"].(string); ok && len(kv) > 8 {
					nkm["key_value"] = kv[:4] + "..." + kv[len(kv)-4:]
				}
				newKeys[j] = nkm
			}
			m["api_keys"] = newKeys
		}
		masked[i] = m
	}
	return masked
}

func (p *ProxyServer) handleListProviders(w http.ResponseWriter, r *http.Request) {
	providers := maskProviderKeys(dbListProviders())
	userID, isAdmin := getUserAndRole(r)
	if !isAdmin && userID != "" {
		filtered := make([]map[string]interface{}, 0, len(providers))
		for _, pr := range providers {
			cb, _ := pr["created_by"].(string)
			if cb == userID {
				filtered = append(filtered, pr)
			}
		}
		providers = filtered
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"providers": providers,
	})
}

func (p *ProxyServer) handleTestProvider(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider        string `json:"provider"`
		APIKey          string `json:"api_key"`
		ProviderID      string `json:"provider_id"`
		FetchModelsOnly bool   `json:"fetch_models_only"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.ProviderID != "" {
		var found map[string]interface{}
		for _, pr := range dbListProviders() {
			if pr["id"] == req.ProviderID {
				found = pr
				break
			}
		}
		if found == nil {
			http.Error(w, "provider not found", http.StatusNotFound)
			return
		}
		providerType, _ := found["provider_type"].(string)
		apiKey := ""
		if keys, ok := found["api_keys"].([]map[string]interface{}); ok && len(keys) > 0 {
			apiKey, _ = keys[0]["key_value"].(string)
		}
		provider, err := NewProvider(providerType, apiKey)
		if err != nil {
			log.Printf("[ERROR] handleTestProvider: NewProvider failed: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		if req.FetchModelsOnly {
			models := provider.FetchModels()
			modelsJSON, _ := json.Marshal(models)
			gormDB.Model(&DBProvider{}).Where("id = ?", req.ProviderID).Updates(map[string]interface{}{
				"models":    string(modelsJSON),
				"updated_at": time.Now().UTC(),
			})
			invalidateProviderCache()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"models": models,
			})
			return
		}
		if err := provider.TestConnection(); err != nil {
			log.Printf("[ERROR] handleTestProvider: TestConnection failed: %v", err)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   "Connection test failed",
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Connection successful",
		})
		return
	}

	if req.Provider == "" {
		http.Error(w, "missing provider or provider_id", http.StatusBadRequest)
		return
	}
	provider, err := NewProvider(req.Provider, req.APIKey)
	if err != nil {
		log.Printf("[ERROR] handleTestProvider: NewProvider failed: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if err := provider.TestConnection(); err != nil {
		log.Printf("[ERROR] handleTestProvider: TestConnection failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Connection test failed",
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Connection successful",
	})
}

func (p *ProxyServer) handleSetProviderKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	var req struct {
		APIKey string `json:"api_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	log.Printf("[DEBUG] handleSetProviderKey: name=%s, has_api_key=%v", name, req.APIKey != "")

	if err := p.SetProviderKey(name, req.APIKey); err != nil {
		log.Printf("[ERROR] handleSetProviderKey: failed to set provider key: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Provider key set successfully",
	})
}

func (p *ProxyServer) SetProviderKey(name, apiKey string) error {
	return p.SetProviderKeyWithBaseURL(name, apiKey, "")
}

func (p *ProxyServer) SetProviderKeyWithBaseURL(name, apiKey, baseURL string) error {
	log.Printf("[INFO] SetProviderKey called: name=%s, apiKey length=%d, baseURL=%s", name, len(apiKey), baseURL)
	provider, err := NewProvider(name, apiKey)
	if err != nil {
		log.Printf("[ERROR] SetProviderKey: NewProvider failed: %v", err)
		return err
	}
	if baseURL != "" {
		provider.SetBaseURL(baseURL)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.providers[name] = provider
	log.Printf("[INFO] SetProviderKey: provider %s registered (baseURL=%s), total providers=%d", name, provider.GetBaseURL(), len(p.providers))

	models := provider.FetchModels()
	if len(models) > 0 {
		dbUpdateProviderModels(name, models)
	}
	log.Printf("[INFO] SetProviderKey: FetchModels done for %s, models=%d", name, len(models))

	var existing DBProvider
	err = gormDB.Where("provider_type = ?", name).First(&existing).Error
	now := time.Now().UTC()
	if err == nil {
		gormDB.Model(&DBProvider{}).Where("provider_type = ?", name).Updates(map[string]interface{}{
			"api_key":    apiKey,
			"updated_at": now,
		})
	} else {
		gormDB.Create(&DBProvider{
			ID:           fmt.Sprintf("%d", time.Now().UnixMilli()),
			Name:         name,
			ProviderType: name,
			AuthType:     "apikey",
			Enabled:      true,
			BaseURL:      baseURL,
			APIKey:       apiKey,
			Models:       "[]",
			DisabledModels: "[]",
			Priority:     0,
			CreatedAt:    now,
			UpdatedAt:    now,
		})
	}
	return nil
}

func (p *ProxyServer) GetProvider(name string) (Provider, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	provider, exists := p.providers[name]
	log.Printf("[DEBUG] GetProvider: name=%s, found=%v", name, exists)
	return provider, exists
}

func (p *ProxyServer) handleStatsUsage(w http.ResponseWriter, r *http.Request) {
	period := 60 * 24 * 7
	if p := r.URL.Query().Get("period"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			period = parsed
		}
	}

	userID, isAdmin := getUserAndRole(r)
	var dbStats *DBUsageStats
	if isAdmin {
		dbStats = dbGetUsageStats(period)
	} else {
		dbStats = dbGetUsageStatsForUser(period, userID)
	}
	totalReqs := dbStats.TotalRequests
	successReqs := dbStats.SuccessRequests
	inputTok := dbStats.InputTokens
	outputTok := dbStats.OutputTokens
	totalLat := dbStats.TotalLatencyMs

	log.Printf("[DEBUG] handleStatsUsage: totalReqs=%d, successReqs=%d", totalReqs, successReqs)

	byProvider := make(map[string]map[string]interface{})
	for k, v := range dbStats.ByProvider {
		reqs := int64(0)
		if r, ok := v["requests"].(int64); ok {
			reqs = r
		}
		succ := int64(0)
		if s, ok := v["success"].(int64); ok {
			succ = s
		}
		sr := 1.0
		if reqs > 0 {
			sr = float64(succ) / float64(reqs)
		}
		byProvider[k] = map[string]interface{}{
			"requests":     v["requests"],
			"tokens":       v["tokens"],
			"success_rate": sr,
		}
	}

	byModel := make(map[string]map[string]interface{})
	for k, v := range dbStats.ByModel {
		byModel[k] = map[string]interface{}{
			"requests": v["requests"],
			"tokens":   v["tokens"],
		}
	}

	dailyStats := make(map[string]*DailyStat)
	for k, v := range dbStats.DailyBreakdown {
		ds := *v
		dailyStats[k] = &ds
	}

	hourlyStats := make(map[string]*DailyStat)
	for k, v := range dbStats.HourlyBreakdown {
		ds := *v
		hourlyStats[k] = &ds
	}

	minuteStats := make(map[string]*DailyStat)
	for k, v := range dbStats.MinuteBreakdown {
		ds := *v
		minuteStats[k] = &ds
	}

	var successRate float64
	if totalReqs > 0 {
		successRate = float64(successReqs) / float64(totalReqs) * 100
	}
	var avgLatency float64
	if totalReqs > 0 {
		avgLatency = float64(totalLat) / float64(totalReqs)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_requests":     totalReqs,
		"input_tokens":       inputTok,
		"output_tokens":      outputTok,
		"total_tokens":       inputTok + outputTok,
		"success_requests":   successReqs,
		"error_requests":     totalReqs - successReqs,
		"success_rate":       successRate,
		"average_latency_ms": avgLatency,
		"by_provider":        byProvider,
		"by_model":           byModel,
		"daily_breakdown":    dailyStats,
		"hourly_breakdown":   hourlyStats,
		"minute_breakdown":   minuteStats,
		"granularity":        dbStats.Granularity,
	})
}

func (p *ProxyServer) handleAlertStats(w http.ResponseWriter, r *http.Request) {
	period := 60 * 24 * 7
	if d := r.URL.Query().Get("period"); d != "" {
		if parsed, err := strconv.Atoi(d); err == nil && parsed > 0 {
			period = parsed
		}
	}

	cutoff := time.Now().Add(-time.Duration(period) * time.Minute).UTC()

	granularity := "hour"
	if period <= 60 {
		granularity = "minute"
	} else if period > 60*24 {
		granularity = "day"
	}

	userID, isAdmin := getUserAndRole(r)

	type AlertItem struct {
		Date        string `json:"date"`
		Total       int    `json:"total"`
		InputBlock  int    `json:"input_block"`
		OutputBlock int    `json:"output_block"`
		Keyword     int    `json:"keyword"`
		Semantic    int    `json:"semantic"`
	}

	daily := make(map[string]*AlertItem)
	hourly := make(map[string]*AlertItem)
	minutely := make(map[string]*AlertItem)

	var alerts []DBSecurityAlert
	q := gormDB.Select("timestamp, direction, trigger_type").Where("timestamp >= ?", cutoff)
	if !isAdmin && userID != "" {
		q = q.Where("user_id = ?", userID)
	}
	if err := q.Order("timestamp ASC").Find(&alerts).Error; err != nil {
		log.Printf("[ERROR] handleAlertStats: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"daily": []interface{}{}, "hourly": []interface{}{}, "minute": []interface{}{}})
		return
	}

	for _, a := range alerts {
		localTS := a.Timestamp.In(getUserLocation())
		dateKey := localTS.Format("2006-01-02")
		hourKey := localTS.Format("2006-01-02 15") + ":00"
		minuteKey := localTS.Format("2006-01-02 15:04")

		if _, ok := daily[dateKey]; !ok {
			daily[dateKey] = &AlertItem{Date: dateKey}
		}
		daily[dateKey].Total++
		if a.Direction == "input" {
			daily[dateKey].InputBlock++
		} else if a.Direction == "output" {
			daily[dateKey].OutputBlock++
		}
		if a.TriggerType == "keyword" {
			daily[dateKey].Keyword++
		} else if a.TriggerType == "semantic" {
			daily[dateKey].Semantic++
		}

		if _, ok := hourly[hourKey]; !ok {
			hourly[hourKey] = &AlertItem{Date: hourKey}
		}
		hourly[hourKey].Total++
		if a.Direction == "input" {
			hourly[hourKey].InputBlock++
		} else if a.Direction == "output" {
			hourly[hourKey].OutputBlock++
		}
		if a.TriggerType == "keyword" {
			hourly[hourKey].Keyword++
		} else if a.TriggerType == "semantic" {
			hourly[hourKey].Semantic++
		}

		if _, ok := minutely[minuteKey]; !ok {
			minutely[minuteKey] = &AlertItem{Date: minuteKey}
		}
		minutely[minuteKey].Total++
		if a.Direction == "input" {
			minutely[minuteKey].InputBlock++
		} else if a.Direction == "output" {
			minutely[minuteKey].OutputBlock++
		}
		if a.TriggerType == "keyword" {
			minutely[minuteKey].Keyword++
		} else if a.TriggerType == "semantic" {
			minutely[minuteKey].Semantic++
		}
	}

	dailyResult := make([]*AlertItem, 0, len(daily))
	for _, v := range daily {
		dailyResult = append(dailyResult, v)
	}
	sort.Slice(dailyResult, func(i, j int) bool { return dailyResult[i].Date < dailyResult[j].Date })

	hourlyResult := make([]*AlertItem, 0, len(hourly))
	for _, v := range hourly {
		hourlyResult = append(hourlyResult, v)
	}
	sort.Slice(hourlyResult, func(i, j int) bool { return hourlyResult[i].Date < hourlyResult[j].Date })

	minuteResult := make([]*AlertItem, 0, len(minutely))
	for _, v := range minutely {
		minuteResult = append(minuteResult, v)
	}
	sort.Slice(minuteResult, func(i, j int) bool { return minuteResult[i].Date < minuteResult[j].Date })

	log.Printf("[DEBUG] handleAlertStats: daily=%d entries, hourly=%d entries, granularity=%s", len(dailyResult), len(hourlyResult), granularity)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"daily":       dailyResult,
		"hourly":      hourlyResult,
		"minute":      minuteResult,
		"granularity": granularity,
	})
}

func (p *ProxyServer) handleAlertSeverityStats(w http.ResponseWriter, r *http.Request) {
	period := 60 * 24 * 7
	if d := r.URL.Query().Get("period"); d != "" {
		if parsed, err := strconv.Atoi(d); err == nil && parsed > 0 {
			period = parsed
		}
	}
	cutoff := time.Now().Add(-time.Duration(period) * time.Minute).UTC()

	userID, isAdmin := getUserAndRole(r)
	query := `SELECT severity, COUNT(*) FROM security_alerts WHERE timestamp >= ?`
	args := []interface{}{cutoff}
	if !isAdmin && userID != "" {
		query += ` AND user_id = ?`
		args = append(args, userID)
	}
	query += ` AND (severity IS NOT NULL AND severity != '') GROUP BY severity`

	rows, err := gormDB.Raw(query, args...).Rows()
	if err != nil {
		log.Printf("[ERROR] handleAlertSeverityStats: %v", err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"by_severity": map[string]int{}})
		return
	}
	defer rows.Close()

	bySeverity := make(map[string]int)
	for rows.Next() {
		var sev string
		var cnt int
		if rows.Scan(&sev, &cnt) == nil && sev != "" {
			bySeverity[sev] = cnt
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"by_severity": bySeverity})
}

func (p *ProxyServer) handleCallerTop10(w http.ResponseWriter, r *http.Request) {
	period := 60 * 24 * 7
	if p := r.URL.Query().Get("period"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			period = parsed
		}
	}
	userID, isAdmin := getUserAndRole(r)
	callers := dbGetCallerTop10(period, userID, isAdmin)
	ips := dbGetIPTop10(period, userID, isAdmin)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"callers": callers,
		"ips":     ips,
	})
}

func (p *ProxyServer) handleSecurityTokenStats(w http.ResponseWriter, r *http.Request) {
	period := 60 * 24 * 7
	if p := r.URL.Query().Get("period"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			period = parsed
		}
	}
	userID, isAdmin := getUserAndRole(r)
	stats := dbGetSecurityTokenStats(period, userID, isAdmin)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (p *ProxyServer) handleSyncAllProviders(w http.ResponseWriter, r *http.Request) {
	synced := 0
	for _, pr := range dbListProviders() {
		ptype, _ := pr["provider_type"].(string)
		name, _ := pr["name"].(string)
		if ptype == "" {
			continue
		}
		var apiKey string
		var baseURL string
		if keys, ok := pr["api_keys"].([]map[string]interface{}); ok && len(keys) > 0 {
			apiKey, _ = keys[0]["key_value"].(string)
			baseURL, _ = pr["base_url"].(string)
		}
		if apiKey == "" {
			continue
		}
		p.mu.Lock()
		provider, err := NewProvider(ptype, apiKey)
		if err != nil {
			p.mu.Unlock()
			continue
		}
		if baseURL != "" {
			provider.SetBaseURL(baseURL)
		}
		p.providers[ptype] = provider
		p.mu.Unlock()

		models := provider.FetchModels()
		if len(models) > 0 {
			dbUpdateProviderModels(ptype, models)
			log.Printf("[Sync] provider %s (name=%s): fetched %d models from upstream, saved to DB", ptype, name, len(models))
		} else {
			log.Printf("[Sync] provider %s (name=%s): upstream returned no models, keeping DB models", ptype, name)
		}
		synced++
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"synced": synced, "total_providers": len(p.providers),
	})
}

func (p *ProxyServer) handleStatsLogs(w http.ResponseWriter, r *http.Request) {
	log.Printf("[DEBUG] handleStatsLogs called, path=%s", r.URL.Path)
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			if l > 1000 {
				l = 1000
			}
			limit = l
		}
	}
	userID := userIDForQuery(r)

	logs, totalCount := dbGetRecentLogs(limit, userID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total": len(logs),
		"count": totalCount,
		"logs":  logs,
	})
}

func (p *ProxyServer) handleServiceLogs(w http.ResponseWriter, r *http.Request) {
	level := r.URL.Query().Get("level")
	keyword := r.URL.Query().Get("keyword")
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	limit := 200
	offset := 0
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 2000 {
		limit = l
	}
	if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
		offset = o
	}

	logFilePath := getLogFilePath()
	f, err := os.Open(logFilePath)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"lines": []string{}, "total": 0, "error": err.Error()})
		return
	}
	defer f.Close()

	const maxReadSize = 2 * 1024 * 1024
	var data []byte
	fi, _ := f.Stat()
	if fi.Size() > maxReadSize {
		f.Seek(-maxReadSize, 2)
		buf := make([]byte, maxReadSize)
		n, _ := f.Read(buf)
		data = buf[:n]
		if idx := bytes.IndexByte(data, '\n'); idx >= 0 {
			data = data[idx+1:]
		}
	} else {
		data, _ = io.ReadAll(f)
	}

	lines := bytes.Split(data, []byte("\n"))
	var filtered []string
	for _, line := range lines {
		lineStr := string(line)
		if lineStr == "" {
			continue
		}
		if level != "" {
			levelUpper := "[" + strings.ToUpper(level) + "]"
			if !bytes.Contains(line, []byte(levelUpper)) && !bytes.Contains(line, []byte(`"level":"`+strings.ToUpper(level)+`"`)) {
				continue
			}
		}
		if keyword != "" && !strings.Contains(strings.ToLower(lineStr), strings.ToLower(keyword)) {
			continue
		}
		filtered = append(filtered, lineStr)
	}

	total := len(filtered)
	end := len(filtered) - offset
	if end > limit {
		end = offset + limit
	}
	start := offset
	if start > len(filtered) {
		start = len(filtered)
	}

	if end < start {
		end = start
	}

	var result []string
	if start < len(filtered) {
		reversed := make([]string, 0, end-start)
		for i := len(filtered) - 1 - start; i >= 0 && len(reversed) < limit; i-- {
			reversed = append(reversed, filtered[i])
		}
		result = reversed
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"lines": result,
		"total": total,
	})
}
