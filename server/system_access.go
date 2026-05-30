package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

type IPAccessConfig struct {
	Whitelist      []string `json:"whitelist"`
	Blacklist      []string `json:"blacklist"`
	GreyDuration   int      `json:"grey_duration_minutes"`
	HoneypotPaths  []string `json:"honeypot_paths"`
	Enabled        bool     `json:"enabled"`
}

type LoginGuardConfig struct {
	MaxAttempts   int `json:"max_attempts"`
	WindowMinutes int `json:"window_minutes"`
	BlockMinutes  int `json:"block_minutes"`
}

type SystemAccessConfig struct {
	IP    IPAccessConfig `json:"ip_access"`
	Login LoginGuardConfig `json:"login_guard"`
}

type greyEntry struct {
	Expiry  time.Time
	Source  string
}

var (
	accessCfgMu    sync.RWMutex
	accessCfg      SystemAccessConfig
	greyList       = make(map[string]greyEntry)
	greyListMu     sync.Mutex
)

func loadSystemAccessConfig() {
	accessCfgMu.Lock()
	defer accessCfgMu.Unlock()
	raw := dbGetSetting("system_access_config")
	if raw == "" {
		accessCfg = SystemAccessConfig{
			IP: IPAccessConfig{
				Whitelist:     []string{},
				Blacklist:     []string{},
				GreyDuration:  30,
				HoneypotPaths: []string{},
				Enabled:       false,
			},
			Login: LoginGuardConfig{
				MaxAttempts:   5,
				WindowMinutes: 15,
				BlockMinutes:  30,
			},
		}
		return
	}
	json.Unmarshal([]byte(raw), &accessCfg)
	if accessCfg.IP.Whitelist == nil {
		accessCfg.IP.Whitelist = []string{}
	}
	if accessCfg.IP.Blacklist == nil {
		accessCfg.IP.Blacklist = []string{}
	}
	if accessCfg.IP.HoneypotPaths == nil {
		accessCfg.IP.HoneypotPaths = []string{}
	}
	if accessCfg.Login.MaxAttempts <= 0 {
		accessCfg.Login.MaxAttempts = 5
	}
	if accessCfg.Login.WindowMinutes <= 0 {
		accessCfg.Login.WindowMinutes = 15
	}
	if accessCfg.Login.BlockMinutes <= 0 {
		accessCfg.Login.BlockMinutes = 30
	}
	if accessCfg.IP.GreyDuration <= 0 {
		accessCfg.IP.GreyDuration = 30
	}
}

func saveSystemAccessConfig(cfg SystemAccessConfig) {
	accessCfgMu.Lock()
	defer accessCfgMu.Unlock()
	if cfg.IP.Whitelist == nil {
		cfg.IP.Whitelist = []string{}
	}
	if cfg.IP.Blacklist == nil {
		cfg.IP.Blacklist = []string{}
	}
	if cfg.IP.HoneypotPaths == nil {
		cfg.IP.HoneypotPaths = []string{}
	}
	accessCfg = cfg
	data, _ := json.Marshal(cfg)
	dbSetSetting("system_access_config", string(data))
}

func getSystemAccessConfig() SystemAccessConfig {
	accessCfgMu.RLock()
	defer accessCfgMu.RUnlock()
	return accessCfg
}

func getLoginGuardConfig() LoginGuardConfig {
	accessCfgMu.RLock()
	defer accessCfgMu.RUnlock()
	return accessCfg.Login
}

func ipInList(ip string, list []string) bool {
	parsedIP := net.ParseIP(ip)
	for _, entry := range list {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if entry == ip {
			return true
		}
		if strings.Contains(entry, "/") {
			_, cidr, err := net.ParseCIDR(entry)
			if err == nil && cidr.Contains(parsedIP) {
				return true
			}
		}
	}
	return false
}

func addGreyList(ip string) {
	addGreyListWithSource(ip, "honeypot")
}

func addGreyListWithSource(ip string, source string) {
	accessCfgMu.RLock()
	dur := accessCfg.IP.GreyDuration
	accessCfgMu.RUnlock()
	if dur <= 0 {
		dur = 30
	}
	expiry := time.Now().Add(time.Duration(dur) * time.Minute)
	greyListMu.Lock()
	greyList[ip] = greyEntry{Expiry: expiry, Source: source}
	greyListMu.Unlock()
	log.Printf("[GREYLIST] IP %s 已加入灰名单（来源：%s），%d 分钟后解除", ip, source, dur)
}

func isGreyListed(ip string) bool {
	greyListMu.Lock()
	defer greyListMu.Unlock()
	entry, ok := greyList[ip]
	if !ok {
		return false
	}
	if time.Now().After(entry.Expiry) {
		delete(greyList, ip)
		return false
	}
	return true
}

func cleanGreyList() {
	greyListMu.Lock()
	defer greyListMu.Unlock()
	now := time.Now()
	for ip, entry := range greyList {
		if now.After(entry.Expiry) {
			delete(greyList, ip)
		}
	}
}

func (p *ProxyServer) ipAccessMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := getSystemAccessConfig()
		if !cfg.IP.Enabled {
			next.ServeHTTP(w, r)
			return
		}
		ip := getClientIP(r)
		if isLocalhost(r) {
			next.ServeHTTP(w, r)
			return
		}
		if len(cfg.IP.Whitelist) > 0 && ipInList(ip, cfg.IP.Whitelist) {
			next.ServeHTTP(w, r)
			return
		}
		if len(cfg.IP.Blacklist) > 0 && ipInList(ip, cfg.IP.Blacklist) {
			log.Printf("[ACCESS] IP %s 在黑名单中，拒绝访问 %s", ip, r.URL.Path)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if isGreyListed(ip) {
			log.Printf("[ACCESS] IP %s 在灰名单中，拒绝访问 %s", ip, r.URL.Path)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (p *ProxyServer) honeypotMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := getSystemAccessConfig()
		if !cfg.IP.Enabled || len(cfg.IP.HoneypotPaths) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		if isLocalhost(r) {
			next.ServeHTTP(w, r)
			return
		}
		path := strings.ToLower(r.URL.Path)
		for _, hp := range cfg.IP.HoneypotPaths {
			if path == strings.ToLower(strings.TrimSpace(hp)) {
				ip := getClientIP(r)
				log.Printf("[HONEYPOT] IP %s 访问了蜜罐路径 %s，加入灰名单", ip, path)
				addGreyList(ip)
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (p *ProxyServer) handleGetSystemAccessConfig(w http.ResponseWriter, r *http.Request) {
	cfg := getSystemAccessConfig()
	greyListMu.Lock()
	type greyItem struct {
		IP       string `json:"ip"`
		Expiry   string `json:"expiry"`
		Source   string `json:"source"`
		Expired  bool   `json:"expired"`
	}
	var items []greyItem
	now := time.Now()
	for ip, entry := range greyList {
		items = append(items, greyItem{
			IP:      ip,
			Expiry:  entry.Expiry.UTC().Format(time.RFC3339),
			Source:  entry.Source,
			Expired: now.After(entry.Expiry),
		})
	}
	if items == nil {
		items = []greyItem{}
	}
	greyListMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"config":      cfg,
		"grey_active": items,
	})
}

func (p *ProxyServer) handleUpdateSystemAccessConfig(w http.ResponseWriter, r *http.Request) {
	var cfg SystemAccessConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if cfg.Login.MaxAttempts <= 0 {
		cfg.Login.MaxAttempts = 5
	}
	if cfg.Login.WindowMinutes <= 0 {
		cfg.Login.WindowMinutes = 15
	}
	if cfg.Login.BlockMinutes <= 0 {
		cfg.Login.BlockMinutes = 30
	}
	if cfg.IP.GreyDuration <= 0 {
		cfg.IP.GreyDuration = 30
	}
	saveSystemAccessConfig(cfg)
	auditLog(r, "system_access", "系统访问控制", fmt.Sprintf(
		"IP控制=%v 白名单=%d条 黑名单=%d条 灰名单时长=%dmin 蜜罐路径=%d条 登录防护=%d次/%dmin 封禁%dmin",
		cfg.IP.Enabled, len(cfg.IP.Whitelist), len(cfg.IP.Blacklist),
		cfg.IP.GreyDuration, len(cfg.IP.HoneypotPaths),
		cfg.Login.MaxAttempts, cfg.Login.WindowMinutes, cfg.Login.BlockMinutes))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (p *ProxyServer) handleRemoveGreyIP(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "missing ip", http.StatusBadRequest)
		return
	}
	greyListMu.Lock()
	delete(greyList, ip)
	greyListMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func initSystemAccessCleanup() {
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			cleanGreyList()
		}
	}()
}

func (p *ProxyServer) setupSystemAccessRoutes(api *mux.Router) {
	api.HandleFunc("/system/access", p.handleGetSystemAccessConfig).Methods("GET")
	api.HandleFunc("/system/access", p.handleUpdateSystemAccessConfig).Methods("PUT")
	api.HandleFunc("/system/access/grey", p.handleRemoveGreyIP).Methods("DELETE")
}
