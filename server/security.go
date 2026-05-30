package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	"github.com/gorilla/mux"
)

func (p *ProxyServer) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secConfigMu.Lock()
		cfg := secConfig
		secConfigMu.Unlock()

		if !cfg.Enabled {
			next.ServeHTTP(w, r)
			return
		}
		spec := specFromContext(r)
		isProviderRoute := spec != nil
		isV1Route := strings.HasPrefix(r.URL.Path, "/v1/")
		if !isV1Route && !isProviderRoute {
			next.ServeHTTP(w, r)
			return
		}

		bodyBytes := bodyFromContext(r)
		if bodyBytes == nil {
			bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, 50<<20))
			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		var reqMap map[string]interface{}
		isStream := false
		sonic.Unmarshal(bodyBytes, &reqMap)
		if reqMap != nil {
			if s, ok := reqMap["stream"].(bool); ok && s {
				isStream = true
			}
		}

		apiKey := extractAPIKeyFromRequest(r)
		clientIP := getClientIP(r)
		reqModel := getStr(reqMap, "model")
		reqProvider := ""
		if reqModel != "" {
			if idx := strings.Index(reqModel, ":"); idx > 0 {
				reqProvider = reqModel[:idx]
			}
		}
		inputContent := ""
		if reqMap != nil {
			inputContent = extractContentFromRequest(reqMap)
		}

		// ---- Input check ----
		if cfg.Input.Enabled && inputContent != "" {
			if cfg.Input.KeywordEnabled {
				matched, cat, level, kw := checkKeywords(inputContent)
				if matched {
					catLabel := keywordCategoryLabels[cat]
					if catLabel == "" {
						catLabel = cat
					}
					log.Printf("[SECURITY] input keyword %s: cat=%s level=%s keyword=%s", cfg.Input.Mode, cat, level, kw)
				alert := &SecurityAlert{
					Timestamp: time.Now(), Direction: "input", Mode: cfg.Input.Mode,
					TriggerType: "keyword:" + cat, TriggerDetail: fmt.Sprintf("[%s/%s] %s", catLabel, level, kw),
					ContentPreview: truncate(inputContent, 200), Model: reqModel,
					APIKeyUsed: apiKey, ClientIP: clientIP, Action: cfg.Input.Mode,
					Severity: level,
				}
					dbInsertAlert(alert)
					if cfg.Input.Mode == "block" {
						dbInsertBlockedLog(reqProvider, reqModel, clientIP, apiKey, r.URL.Path, r.Method, string(bodyBytes), fmt.Sprintf("input keyword [%s] blocked: %s", cat, kw))
						sendBlockResponse(w, cfg.BlockMessage)
						return
					}
				}
			}
			{
				matched, tType, tSev, tMatch := checkThreatRules(inputContent)
				if matched {
					log.Printf("[SECURITY] input threat %s: type=%s match=%s", cfg.Input.Mode, tType, tMatch)
					alert := &SecurityAlert{
						Timestamp: time.Now(), Direction: "input", Mode: cfg.Input.Mode,
						TriggerType: "threat:" + tType, TriggerDetail: fmt.Sprintf("[%s] %s", tType, truncate(tMatch, 80)),
						Severity: tSev,
						ContentPreview: truncate(inputContent, 200), Model: reqModel,
						APIKeyUsed: apiKey, ClientIP: clientIP, Action: cfg.Input.Mode,
					}
					dbInsertAlert(alert)
					if cfg.Input.Mode == "block" {
						dbInsertBlockedLog(reqProvider, reqModel, clientIP, apiKey, r.URL.Path, r.Method, string(bodyBytes), fmt.Sprintf("input threat [%s] blocked: %s", tType, tMatch))
						sendBlockResponse(w, cfg.BlockMessage)
						return
					}
				}
			}
			if cfg.Input.SemanticEnabled && cfg.SemanticModel != "" {
				if cfg.Input.Mode == "block" {
					sr, serr := p.semanticCheck(inputContent, cfg)
					if serr != nil {
						log.Printf("[WARN] input semantic check error: %v", serr)
					} else if sr != nil {
						alerted := getAlertCategories(sr, cfg.SemanticThreshold)
						if len(alerted) > 0 {
							log.Printf("[SECURITY] input semantic block: categories=%v", alerted)
							for _, cat := range alerted {
								cr := sr.Categories[cat]
								alert := &SecurityAlert{
									Timestamp: time.Now(), Direction: "input", Mode: "block",
									TriggerType: "semantic", TriggerDetail: fmt.Sprintf("%s (%.0f%%)", categoryLabel(cat), cr.Confidence*100),
									ContentPreview: truncate(inputContent, 200), Model: reqModel,
									APIKeyUsed: apiKey, ClientIP: clientIP, Action: "block",
									Severity: "high",
								}
								dbInsertAlert(alert)
							}
							dbInsertBlockedLog(reqProvider, reqModel, clientIP, apiKey, r.URL.Path, r.Method, string(bodyBytes), "input semantic blocked")
							autoAddBlockedSample(truncate(inputContent, 500), "input_semantic")
							sendBlockResponse(w, cfg.BlockMessage)
							return
						}
					}
				} else {
					safeGo(func() { p.asyncInputSemanticCheck(inputContent, reqModel, apiKey, clientIP, cfg) })
				}
			}
			if cfg.Input.VectorEnabled {
				if cfg.Input.Mode == "block" {
					vr, verr := vectorCheck(inputContent)
					if verr != nil {
						log.Printf("[WARN] input vector check error: %v", verr)
					} else if len(vr) > 0 {
						best := vr[0]
						log.Printf("[SECURITY] input vector block: similarity=%.2f, category=%s", best.Similarity, best.Category)
						alert := &SecurityAlert{
							Timestamp: time.Now(), Direction: "input", Mode: "block",
							TriggerType: "vector", TriggerDetail: fmt.Sprintf("相似度 %.0f%% (%s)", best.Similarity*100, best.Category),
							ContentPreview: truncate(inputContent, 200), Model: reqModel,
							APIKeyUsed: apiKey, ClientIP: clientIP, Action: "block",
							Severity: "high",
						}
						dbInsertAlert(alert)
						dbInsertBlockedLog(reqProvider, reqModel, clientIP, apiKey, r.URL.Path, r.Method, string(bodyBytes), "input vector blocked")
						autoAddBlockedSample(truncate(inputContent, 500), "input_vector")
						sendBlockResponse(w, cfg.BlockMessage)
						return
					}
				} else {
				safeGo(func() { p.asyncInputVectorCheck(inputContent, reqModel, apiKey, clientIP) })
				}
			}
		}

		// ---- Output check ----
		if cfg.Output.Enabled {
			if cfg.Output.Mode == "detect" {
				if !isStream {
					bw := newBufferedResponseWriter(0)
					next.ServeHTTP(bw, r)
					for k, vs := range bw.Header() {
						for _, v := range vs {
							w.Header().Add(k, v)
						}
					}
					w.WriteHeader(bw.statusCode)
					w.Write(bw.Bytes())
					if bw.statusCode == http.StatusOK && bw.Len() > 0 && (cfg.Output.KeywordEnabled || cfg.Output.SemanticEnabled || cfg.Output.VectorEnabled) {
						var resp map[string]interface{}
						if sonic.Unmarshal(bw.Bytes(), &resp) == nil {
							outputContent := extractContentFromResponse(resp)
							if outputContent != "" {
							safeGo(func() { p.asyncOutputCheck(outputContent, reqModel, apiKey, clientIP, cfg) })
								if cfg.Output.VectorEnabled {
								safeGo(func() { p.asyncOutputVectorCheck(outputContent, reqModel, apiKey, clientIP) })
								}
							}
						}
					}
					bw.Release()
				} else {
					next.ServeHTTP(w, r)
				}
				return
			}

			// Block mode
			if !isStream {
				bw := newBufferedResponseWriter(0)
				next.ServeHTTP(bw, r)
				defer bw.Release()
				if bw.statusCode == http.StatusOK && bw.Len() > 0 {
					if bw.overflowed {
						log.Printf("[WARN] output block: response exceeded buffer limit (%d bytes), fail-closed (blocked)", bw.Len())
						alert := &SecurityAlert{
							Timestamp: time.Now(), Direction: "output", Mode: "block",
							TriggerType: "buffer_overflow", TriggerDetail: "响应超过缓冲区限制",
							ContentPreview: "", Model: reqModel,
							APIKeyUsed: apiKey, ClientIP: clientIP, Action: "block",
							Severity: "critical",
						}
						dbInsertAlert(alert)
						w.Header().Set("Content-Type", "application/json")
						w.Header().Set("X-Security-Block", "output")
						json.NewEncoder(w).Encode(buildBlockChatResponse(cfg.BlockMessage, nil))
						return
					}
					var resp map[string]interface{}
					if sonic.Unmarshal(bw.Bytes(), &resp) == nil {
					outputContent := extractContentFromResponse(resp)
					if outputContent != "" {
						blocked := false
						if cfg.Output.KeywordEnabled {
							matched, cat, level, kw := checkKeywords(outputContent)
							if matched {
								catLabel := keywordCategoryLabels[cat]
								if catLabel == "" {
									catLabel = cat
								}
								log.Printf("[SECURITY] output keyword block: cat=%s level=%s keyword=%s", cat, level, kw)
								alert := &SecurityAlert{
									Timestamp: time.Now(), Direction: "output", Mode: "block",
									TriggerType: "keyword:" + cat, TriggerDetail: fmt.Sprintf("[%s/%s] %s", catLabel, level, kw),
									ContentPreview: truncate(outputContent, 200), Model: reqModel,
									APIKeyUsed: apiKey, ClientIP: clientIP, Action: "replace",
									Severity: level,
								}
								dbInsertAlert(alert)
								w.Header().Set("Content-Type", "application/json")
								w.Header().Set("X-Security-Block", "output")
								json.NewEncoder(w).Encode(buildBlockChatResponse(cfg.BlockMessage, resp))
								blocked = true
							}
						}
							if !blocked && cfg.Output.SemanticEnabled && cfg.SemanticModel != "" {
								sr, serr := p.semanticCheck(outputContent, cfg)
								if serr == nil && sr != nil {
									alerted := getAlertCategories(sr, cfg.SemanticThreshold)
									if len(alerted) > 0 {
										log.Printf("[SECURITY] output semantic block: categories=%v", alerted)
										for _, cat := range alerted {
											cr := sr.Categories[cat]
											alert := &SecurityAlert{
												Timestamp: time.Now(), Direction: "output", Mode: "block",
												TriggerType: "semantic", TriggerDetail: fmt.Sprintf("%s (%.0f%%)", categoryLabel(cat), cr.Confidence*100),
												ContentPreview: truncate(outputContent, 200), Model: reqModel,
												APIKeyUsed: apiKey, ClientIP: clientIP, Action: "replace",
												Severity: "high",
											}
											dbInsertAlert(alert)
										}
										autoAddBlockedSample(truncate(outputContent, 500), "output_semantic")
										w.Header().Set("Content-Type", "application/json")
										w.Header().Set("X-Security-Block", "output")
										json.NewEncoder(w).Encode(buildBlockChatResponse(cfg.BlockMessage, resp))
										blocked = true
									}
								}
							}
							if !blocked && cfg.Output.VectorEnabled {
								vr, verr := vectorCheck(outputContent)
								if verr != nil {
									log.Printf("[WARN] output vector check error: %v", verr)
								} else if len(vr) > 0 {
									best := vr[0]
									log.Printf("[SECURITY] output vector block: similarity=%.2f, category=%s", best.Similarity, best.Category)
									alert := &SecurityAlert{
										Timestamp: time.Now(), Direction: "output", Mode: "block",
										TriggerType: "vector", TriggerDetail: fmt.Sprintf("相似度 %.0f%% (%s)", best.Similarity*100, best.Category),
										ContentPreview: truncate(outputContent, 200), Model: reqModel,
										APIKeyUsed: apiKey, ClientIP: clientIP, Action: "replace",
										Severity: "high",
									}
									dbInsertAlert(alert)
									autoAddBlockedSample(truncate(outputContent, 500), "output_vector")
									w.Header().Set("Content-Type", "application/json")
									w.Header().Set("X-Security-Block", "output")
									json.NewEncoder(w).Encode(buildBlockChatResponse(cfg.BlockMessage, resp))
									blocked = true
								}
							}
							if !blocked {
								for k, vs := range bw.Header() {
									for _, v := range vs {
										w.Header().Add(k, v)
									}
								}
								w.WriteHeader(bw.statusCode)
								w.Write(bw.Bytes())
							}
							return
						}
					}
				}
				for k, vs := range bw.Header() {
					for _, v := range vs {
						w.Header().Add(k, v)
					}
				}
				w.WriteHeader(bw.statusCode)
				w.Write(bw.Bytes())
				return
			}

			// Block mode + stream: use sliding window for keywords
			sw := newSlidingWindowWriter(w, cfg, reqModel, apiKey, clientIP)
			next.ServeHTTP(sw, r)
			// After stream completes, do async semantic check on accumulated content if needed
			if cfg.Output.SemanticEnabled && cfg.SemanticModel != "" && !sw.aborted {
				accumulated := sw.GetAccumulated()
				if accumulated != "" {
					safeGo(func() { p.asyncOutputCheck(accumulated, reqModel, apiKey, clientIP, cfg) })
				}
			}
			if cfg.Output.VectorEnabled && !sw.aborted {
				accumulated := sw.GetAccumulated()
				if accumulated != "" {
					safeGo(func() { p.asyncOutputVectorCheck(accumulated, reqModel, apiKey, clientIP) })
				}
			}
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (p *ProxyServer) asyncInputSemanticCheck(content, model, apiKey, clientIP string, cfg SecurityConfig) {
	sr, err := p.semanticCheck(content, cfg)
	if err != nil {
		log.Printf("[WARN] async input semantic: %v", err)
		return
	}
	if sr == nil {
		return
	}
	alerted := getAlertCategories(sr, cfg.SemanticThreshold)
	if len(alerted) == 0 {
		return
	}
	log.Printf("[SECURITY] async input semantic alert: categories=%v", alerted)
	for _, cat := range alerted {
		cr := sr.Categories[cat]
		alert := &SecurityAlert{
			Timestamp: time.Now(), Direction: "input", Mode: "detect",
			TriggerType: "semantic", TriggerDetail: fmt.Sprintf("%s (%.0f%%)", categoryLabel(cat), cr.Confidence*100),
			ContentPreview: truncate(content, 200), Model: model,
			APIKeyUsed: apiKey, ClientIP: clientIP, Action: "alert",
			Severity: "high",
		}
		dbInsertAlert(alert)
	}
}

func (p *ProxyServer) asyncOutputCheck(content, model, apiKey, clientIP string, cfg SecurityConfig) {
	if cfg.Output.KeywordEnabled {
		matched, cat, level, kw := checkKeywords(content)
		if matched {
			catLabel := keywordCategoryLabels[cat]
			if catLabel == "" {
				catLabel = cat
			}
			log.Printf("[SECURITY] async output keyword detect: cat=%s level=%s keyword=%s", cat, level, kw)
			alert := &SecurityAlert{
				Timestamp: time.Now(), Direction: "output", Mode: "detect",
				TriggerType: "keyword:" + cat, TriggerDetail: fmt.Sprintf("[%s/%s] %s", catLabel, level, kw),
				ContentPreview: truncate(content, 200), Model: model,
				APIKeyUsed: apiKey, ClientIP: clientIP, Action: "alert",
				Severity: level,
			}
			dbInsertAlert(alert)
		}
	}
	if cfg.Output.SemanticEnabled && cfg.SemanticModel != "" {
		sr, err := p.semanticCheck(content, cfg)
		if err != nil {
			log.Printf("[WARN] async output semantic: %v", err)
			return
		}
		if sr == nil {
			return
		}
		alerted := getAlertCategories(sr, cfg.SemanticThreshold)
		if len(alerted) == 0 {
			return
		}
		log.Printf("[SECURITY] async output semantic alert: categories=%v", alerted)
		for _, cat := range alerted {
			cr := sr.Categories[cat]
			alert := &SecurityAlert{
				Timestamp: time.Now(), Direction: "output", Mode: "detect",
				TriggerType: "semantic", TriggerDetail: fmt.Sprintf("%s (%.0f%%)", categoryLabel(cat), cr.Confidence*100),
				ContentPreview: truncate(content, 200), Model: model,
				APIKeyUsed: apiKey, ClientIP: clientIP, Action: "alert",
				Severity: "high",
			}
			dbInsertAlert(alert)
		}
		if cfg.AutoBanKey && apiKey != "" {
			if banAPIKey(apiKey) {
				log.Printf("[SECURITY] auto-banned key %s", maskAPIKey(apiKey))
			}
		}
	}
}

func (p *ProxyServer) asyncInputVectorCheck(content, model, apiKey, clientIP string) {
	results, err := vectorCheck(content)
	if err != nil {
		log.Printf("[WARN] async input vector: %v", err)
		return
	}
	if len(results) == 0 {
		return
	}
	best := results[0]
	log.Printf("[SECURITY] async input vector alert: similarity=%.2f, category=%s", best.Similarity, best.Category)
	alert := &SecurityAlert{
		Timestamp: time.Now(), Direction: "input", Mode: "detect",
		TriggerType: "vector", TriggerDetail: fmt.Sprintf("相似度 %.0f%% (%s)", best.Similarity*100, best.Category),
		ContentPreview: truncate(content, 200), Model: model,
		APIKeyUsed: apiKey, ClientIP: clientIP, Action: "alert",
		Severity: "high",
	}
	dbInsertAlert(alert)
	autoAddBlockedSample(truncate(content, 500), "input_vector")
}

func (p *ProxyServer) asyncOutputVectorCheck(content, model, apiKey, clientIP string) {
	results, err := vectorCheck(content)
	if err != nil {
		log.Printf("[WARN] async output vector: %v", err)
		return
	}
	if len(results) == 0 {
		return
	}
	best := results[0]
	log.Printf("[SECURITY] async output vector alert: similarity=%.2f, category=%s", best.Similarity, best.Category)
	alert := &SecurityAlert{
		Timestamp: time.Now(), Direction: "output", Mode: "detect",
		TriggerType: "vector", TriggerDetail: fmt.Sprintf("相似度 %.0f%% (%s)", best.Similarity*100, best.Category),
		ContentPreview: truncate(content, 200), Model: model,
		APIKeyUsed: apiKey, ClientIP: clientIP, Action: "alert",
		Severity: "high",
	}
	dbInsertAlert(alert)
	autoAddBlockedSample(truncate(content, 500), "output_vector")
}

func (p *ProxyServer) setupSecurityRoutes(api *mux.Router) {
	api.HandleFunc("/security/config", p.handleGetSecurityConfig).Methods("GET")
	api.HandleFunc("/security/config", p.handleUpdateSecurityConfig).Methods("PUT")
	api.HandleFunc("/security/alerts", p.handleGetSecurityAlerts).Methods("GET")
	api.HandleFunc("/security/stats", p.handleGetSecurityStats).Methods("GET")
	api.HandleFunc("/security/alerts/{id}/resolve", p.handleResolveAlert).Methods("PUT")
}

func (p *ProxyServer) handleGetSecurityConfig(w http.ResponseWriter, r *http.Request) {
	secConfigMu.Lock()
	cfg := secConfig
	secConfigMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

func (p *ProxyServer) handleUpdateSecurityConfig(w http.ResponseWriter, r *http.Request) {
	var cfg SecurityConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if cfg.Keywords == nil {
		cfg.Keywords = []string{}
	}
	if cfg.BlockMessage == "" {
		cfg.BlockMessage = "抱歉，您的内容涉及敏感信息，已被安全策略拦截。"
	}
	if cfg.KeywordLevels == nil {
		cfg.KeywordLevels = []string{"high"}
	}
	if cfg.Input.KeywordCategories == nil || len(cfg.Input.KeywordCategories) == 0 {
		cfg.Input.KeywordCategories = keywordCategories
	}
	if cfg.Output.KeywordCategories == nil || len(cfg.Output.KeywordCategories) == 0 {
		cfg.Output.KeywordCategories = keywordCategories
	}
	secConfigMu.Lock()
	secConfig = cfg
	secConfigMu.Unlock()
	rebuildMatchers(&cfg)
	dbSaveSecurityConfig(&cfg)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	auditLog(r, "security.config_update", "安全防护配置", "")
}

func (p *ProxyServer) handleGetSecurityAlerts(w http.ResponseWriter, r *http.Request) {
	limit := 50
	offset := 0
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 {
		if l > 1000 {
			l = 1000
		}
		limit = l
	}
	if o, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && o >= 0 {
		offset = o
	}
	var resolved *int
	if rv := r.URL.Query().Get("resolved"); rv == "0" || rv == "1" {
		v := int(rv[0] - '0')
		resolved = &v
	}
	severity := r.URL.Query().Get("severity")
	direction := r.URL.Query().Get("direction")
	triggerType := r.URL.Query().Get("trigger_type")
	excludeTriggerType := r.URL.Query().Get("exclude_trigger_type")
	search := r.URL.Query().Get("search")
	uid, isAdmin := getUserAndRole(r)
	alerts, total := dbGetAlerts(limit, offset, resolved, severity, direction, triggerType, search, excludeTriggerType, uid, isAdmin)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"alerts": alerts, "total": total})
}

func (p *ProxyServer) handleGetSecurityStats(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("source")
	if source == "" {
		source = "content"
	}
	stats := dbGetAlertStats(source)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (p *ProxyServer) handleResolveAlert(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var alert DBSecurityAlert
	if err := gormDB.Where("id = ?", id).Select("resolved").First(&alert).Error; err != nil {
		alert.Resolved = false
	}
	newVal := 1
	if alert.Resolved {
		newVal = 0
	}
	gormDB.Model(&DBSecurityAlert{}).Where("id = ?", id).Update("resolved", newVal)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "resolved": newVal})
}
