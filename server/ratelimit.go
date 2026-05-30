package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/time/rate"
)

type RateLimitConfig struct {
	GlobalRPM   int            `json:"global_rpm"`
	KeyRPM      int            `json:"key_rpm"`
	ModelRPM    map[string]int `json:"model_rpm"`
	ProviderRPM map[string]int `json:"provider_rpm"`
}

type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type RateLimiterManager struct {
	mu         sync.RWMutex
	config     RateLimitConfig
	global     *rate.Limiter
	byKey      map[string]*rateLimiterEntry
	byModel    map[string]*rateLimiterEntry
	byProvider map[string]*rateLimiterEntry
}

var rateLimitManager *RateLimiterManager

func newRateLimiterManager(cfg RateLimitConfig) *RateLimiterManager {
	m := &RateLimiterManager{
		config:     cfg,
		byKey:      make(map[string]*rateLimiterEntry),
		byModel:    make(map[string]*rateLimiterEntry),
		byProvider: make(map[string]*rateLimiterEntry),
	}
	if cfg.GlobalRPM > 0 {
		m.global = rate.NewLimiter(rate.Limit(cfg.GlobalRPM)/60, cfg.GlobalRPM/60+1)
	}
	safeGo(func() { m.cleanupLoop() })
	return m
}

func (m *RateLimiterManager) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		m.cleanup()
	}
}

func (m *RateLimiterManager) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-10 * time.Minute)
	for k, v := range m.byKey {
		if v.lastSeen.Before(cutoff) {
			delete(m.byKey, k)
		}
	}
	for k, v := range m.byModel {
		if v.lastSeen.Before(cutoff) {
			delete(m.byModel, k)
		}
	}
	for k, v := range m.byProvider {
		if v.lastSeen.Before(cutoff) {
			delete(m.byProvider, k)
		}
	}
}

func (m *RateLimiterManager) getLimiter(category string, name string, rpm int) *rate.Limiter {
	if rpm <= 0 {
		return nil
	}
	m.mu.RLock()
	var store map[string]*rateLimiterEntry
	switch category {
	case "key":
		store = m.byKey
	case "model":
		store = m.byModel
	case "provider":
		store = m.byProvider
	default:
		m.mu.RUnlock()
		return nil
	}
	if entry, ok := store[name]; ok {
		entry.lastSeen = time.Now()
		m.mu.RUnlock()
		return entry.limiter
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	switch category {
	case "key":
		store = m.byKey
	case "model":
		store = m.byModel
	case "provider":
		store = m.byProvider
	}
	if entry, ok := store[name]; ok {
		entry.lastSeen = time.Now()
		return entry.limiter
	}

	rps := rate.Limit(rpm) / 60
	burst := rpm/60 + 1
	if burst < 1 {
		burst = 1
	}
	limiter := rate.NewLimiter(rps, burst)
	store[name] = &rateLimiterEntry{limiter: limiter, lastSeen: time.Now()}
	return limiter
}

func (m *RateLimiterManager) Allow(apiKey, model, provider string) (bool, string) {
	if m.global != nil {
		if !m.global.Allow() {
			return false, "global"
		}
	}
	if m.config.KeyRPM > 0 && apiKey != "" {
		limiter := m.getLimiter("key", apiKey, m.config.KeyRPM)
		if limiter != nil && !limiter.Allow() {
			return false, "api_key"
		}
	}
	if model != "" {
		if modelRPM, ok := m.config.ModelRPM[model]; ok && modelRPM > 0 {
			limiter := m.getLimiter("model", model, modelRPM)
			if limiter != nil && !limiter.Allow() {
				return false, "model:" + model
			}
		}
	}
	if provider != "" {
		if providerRPM, ok := m.config.ProviderRPM[provider]; ok && providerRPM > 0 {
			limiter := m.getLimiter("provider", provider, providerRPM)
			if limiter != nil && !limiter.Allow() {
				return false, "provider:" + provider
			}
		}
	}
	return true, ""
}

func (m *RateLimiterManager) UpdateConfig(cfg RateLimitConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = cfg
	if cfg.GlobalRPM > 0 {
		rps := rate.Limit(cfg.GlobalRPM) / 60
		burst := cfg.GlobalRPM/60 + 1
		if burst < 1 {
			burst = 1
		}
		m.global = rate.NewLimiter(rps, burst)
	} else {
		m.global = nil
	}
	m.byKey = make(map[string]*rateLimiterEntry)
	m.byModel = make(map[string]*rateLimiterEntry)
	m.byProvider = make(map[string]*rateLimiterEntry)
}

func (p *ProxyServer) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/") {
			next.ServeHTTP(w, r)
			return
		}
		if rateLimitManager == nil {
			next.ServeHTTP(w, r)
			return
		}

		apiKey := extractAPIKeyFromRequest(r)
		model := ""
		provider := ""

		if bodyBytes := bodyFromContext(r); len(bodyBytes) > 0 {
			var reqMap map[string]interface{}
			if json.Unmarshal(bodyBytes, &reqMap) == nil {
				if m, ok := reqMap["model"].(string); ok {
					model = m
					if parts := strings.SplitN(model, ":", 2); len(parts) == 2 {
						provider = parts[0]
					} else if parts := strings.SplitN(model, "/", 2); len(parts) == 2 {
						provider = parts[0]
					}
				}
			}
		}

		allowed, scope := rateLimitManager.Allow(apiKey, model, provider)
		if !allowed {
			retryAfter := 1
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]interface{}{
					"message": fmt.Sprintf("Rate limit exceeded for %s. Please retry after %d second.", scope, retryAfter),
					"type":    "rate_limit_error",
					"code":    "rate_limit_exceeded",
				},
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ==================== Rate Limit Config Handlers ====================

func dbLoadRateLimitConfig() RateLimitConfig {
	var cfg RateLimitConfig
	var record DBRateLimitConfig
	if err := gormDB.Where("id = 1").First(&record).Error; err != nil {
		return RateLimitConfig{}
	}
	json.Unmarshal([]byte(record.ConfigJSON), &cfg)
	if cfg.ModelRPM == nil {
		cfg.ModelRPM = make(map[string]int)
	}
	if cfg.ProviderRPM == nil {
		cfg.ProviderRPM = make(map[string]int)
	}
	return cfg
}

func dbSaveRateLimitConfig(cfg *RateLimitConfig) {
	configJSON, _ := json.Marshal(cfg)
	gormDB.Save(&DBRateLimitConfig{ID: 1, ConfigJSON: string(configJSON)})
}

func (p *ProxyServer) setupRateLimitRoutes(api *mux.Router) {
	api.HandleFunc("/ratelimit/config", p.handleGetRateLimitConfig).Methods("GET")
	api.HandleFunc("/ratelimit/config", p.handleUpdateRateLimitConfig).Methods("PUT")
}

func (p *ProxyServer) handleGetRateLimitConfig(w http.ResponseWriter, r *http.Request) {
	if rateLimitManager != nil {
		rateLimitManager.mu.Lock()
		cfg := rateLimitManager.config
		rateLimitManager.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RateLimitConfig{})
}

func (p *ProxyServer) handleUpdateRateLimitConfig(w http.ResponseWriter, r *http.Request) {
	var cfg RateLimitConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		log.Printf("[ERROR] handleUpdateRateLimitConfig: decode failed: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if cfg.ModelRPM == nil {
		cfg.ModelRPM = make(map[string]int)
	}
	if cfg.ProviderRPM == nil {
		cfg.ProviderRPM = make(map[string]int)
	}
	log.Printf("[INFO] handleUpdateRateLimitConfig: global=%d key=%d models=%v providers=%v",
		cfg.GlobalRPM, cfg.KeyRPM, cfg.ModelRPM, cfg.ProviderRPM)
	if rateLimitManager == nil {
		rateLimitManager = newRateLimiterManager(cfg)
	} else {
		rateLimitManager.UpdateConfig(cfg)
	}
	dbSaveRateLimitConfig(&cfg)
	log.Printf("[INFO] handleUpdateRateLimitConfig: saved to DB")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}
