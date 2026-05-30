package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type capturingResponseWriter struct {
	http.ResponseWriter
	statusCode        int
	body              bytes.Buffer
	streaming         bool
	wrote             bool
	streamUsage       bytes.Buffer
	upstreamProvider  string
	upstreamModel     string
	upstreamReqHeaders string
	upstreamRespHeaders string
	upstreamReqBody   string
}

func (w *capturingResponseWriter) WriteHeader(code int) {
	if !w.wrote {
		w.statusCode = code
		w.wrote = true
		ct := w.Header().Get("Content-Type")
		if strings.Contains(ct, "text/event-stream") {
			w.streaming = true
		}
		w.ResponseWriter.WriteHeader(code)
	}
}

func (w *capturingResponseWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if !w.streaming && w.body.Len()+len(b) <= maxCaptureSize {
		w.body.Write(b)
	}
	if w.streaming {
		for _, line := range bytes.Split(b, []byte("\n")) {
			line = bytes.TrimSpace(line)
			if bytes.Contains(line, []byte(`"usage"`)) {
				if bytes.HasPrefix(line, []byte("data: ")) {
					w.streamUsage.Write(line[6:])
				} else if bytes.HasPrefix(line, []byte("{")) {
					w.streamUsage.Write(line)
				}
			}
		}
	}
	return w.ResponseWriter.Write(b)
}

func (w *capturingResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func isLocalhostOrigin(origin string) bool {
	return strings.HasPrefix(origin, "http://127.0.0.1") ||
		strings.HasPrefix(origin, "https://127.0.0.1") ||
		strings.HasPrefix(origin, "http://localhost") ||
		strings.HasPrefix(origin, "https://localhost") ||
		strings.HasPrefix(origin, "http://0.0.0.0") ||
		strings.HasPrefix(origin, "https://0.0.0.0") ||
		strings.HasPrefix(origin, "tauri://") ||
		strings.HasPrefix(origin, "https://tauri.localhost") ||
		strings.HasPrefix(origin, "http://tauri.localhost")
}

func originHasPort(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Port() != ""
}

func originFromReferer(r *http.Request) string {
	referer := r.Header.Get("Referer")
	if referer == "" {
		return ""
	}
	u, err := url.Parse(referer)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func resolveAllowOrigin(r *http.Request) string {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return ""
	}
	if !isLocalhostOrigin(origin) {
		if strings.Contains(origin, "//"+r.Host) {
			return origin
		}
		return ""
	}
	if originHasPort(origin) {
		return origin
	}
	if ref := originFromReferer(r); ref != "" && isLocalhostOrigin(ref) {
		return ref
	}
	return origin
}

func (p *ProxyServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowedOrigin := resolveAllowOrigin(r)

		if allowedOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, x-api-key, X-Requested-With")
		w.Header().Set("Access-Control-Max-Age", "86400")
		w.Header().Set("Vary", "Origin")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (p *ProxyServer) providerMatchMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if spec := p.matchRoute(r.URL.Path); spec != nil {
			r = withSpec(r, spec)
		}
		next.ServeHTTP(w, r)
	})
}

func (p *ProxyServer) apiLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if !strings.HasPrefix(path, "/api/v1/") {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()

		var bodyBytes []byte
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
			bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, 50<<20))
			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		log.Printf("[API] --> %s %s from %s", r.Method, path, getClientIP(r))
		if len(bodyBytes) > 0 && len(bodyBytes) <= 4096 {
			sanitized := sanitizeLogBody(bodyBytes)
			log.Printf("[API] --> Request Body: %s", sanitized)
		} else if len(bodyBytes) > 4096 {
			log.Printf("[API] --> Request Body: [%d bytes, too large to log]", len(bodyBytes))
		}
		log.Printf("[API] --> Headers: %v", sanitizeLogHeaders(r.Header))

		cw := &capturingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(cw, r)

		latency := time.Since(start)
		log.Printf("[API] <-- %s %s %d %dms", r.Method, path, cw.statusCode, latency.Milliseconds())
		respBody := cw.body.String()
		if len(respBody) > 50000 {
			respBody = respBody[:50000]
		}
		log.Printf("[API] <-- Response Body: %s", respBody)

		if apiReqLogger != nil {
			reqHeaders := make(map[string]string)
			for k, v := range r.Header {
				reqHeaders[k] = strings.Join(v, ",")
			}
			respHeaders := make(map[string]string)
			for k, v := range cw.Header() {
				respHeaders[k] = strings.Join(v, ",")
			}
			safeReqHeaders := sanitizeHeadersForJSON(reqHeaders)
			apiReqLogger.Info("api_request",
				"timestamp", time.Now().UTC().Format(time.RFC3339),
				"method", r.Method,
				"path", path,
				"host", r.Host,
				"source_ip", getClientIP(r),
				"user_agent", r.UserAgent(),
				"origin", r.Header.Get("Origin"),
				"status_code", cw.statusCode,
				"latency_ms", float64(latency.Milliseconds()),
				"request_headers", safeReqHeaders,
				"request_body", sanitizeBodyForJSON(bodyBytes),
				"response_body", sanitizeBodyForJSON([]byte(respBody)),
			)
		}
	})
}

func (p *ProxyServer) requestTrackingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		spec := specFromContext(r)

		if spec == nil || r.Method == "GET" {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()

		bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 50<<20))
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		model := extractModelFromBody(bodyBytes, &spec.Usage)
		provider := spec.Name
		log.Printf("[DEBUG] requestTracking: path=%s, model=%s, provider=%s", path, model, provider)

		apiKeyUsed := extractAPIKeyFromRequest(r)

		clientHeaders := make(map[string]string)
		for k, v := range r.Header {
			clientHeaders[k] = strings.Join(v, ",")
		}
		safeClientHeaders, _ := json.Marshal(clientHeaders)

		if r.Header.Get("X-Internal-Test-Call") != "" {
			cw := &capturingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(cw, r)

			latency := time.Since(start)
			var inputTokens, outputTokens int
			if cw.streaming && cw.streamUsage.Len() > 0 {
				inputTokens, outputTokens = extractTokensFromStreamUsage(cw.streamUsage.Bytes(), &spec.Usage)
			} else {
				inputTokens, outputTokens = extractTokensFromBody(cw.body.Bytes(), &spec.Usage)
			}

			reqContent := string(bodyBytes)
			if len(reqContent) > 10000 {
				reqContent = reqContent[:10000]
			}
			respContent := cw.body.String()
			if len(respContent) > 10000 {
				respContent = respContent[:10000]
			}

			uid := userIDForQuery(r)
			if uid == "" {
				apiKeysMu.RLock()
				if info, exists := apiKeys[apiKeyUsed]; exists {
					uid = info.UserID
				}
				apiKeysMu.RUnlock()
			}

			entry := &RequestLog{
				Timestamp:           start,
				Provider:           provider,
				Model:              model,
				InputTokens:        inputTokens,
				OutputTokens:       outputTokens,
				LatencyMs:          latency.Milliseconds(),
				Success:            cw.statusCode >= 200 && cw.statusCode < 300,
				ClientIP:           getClientIP(r),
				APIKeyUsed:         apiKeyUsed,
				StatusCode:         cw.statusCode,
				Path:               r.URL.Path,
				Method:              r.Method,
				RequestContent:     reqContent,
				ResponseContent:    respContent,
				UserID:             uid,
				APIKeyID:           apiKeyUsed,
				UpstreamProvider:   cw.upstreamProvider,
				UpstreamModel:      cw.upstreamModel,
				UpstreamReqHeaders: cw.upstreamReqHeaders,
				UpstreamRespHeaders: cw.upstreamRespHeaders,
				UpstreamReqBody:    cw.upstreamReqBody,
				CallType:           "client",
				ClientReqHeaders:   string(safeClientHeaders),
			}
			if provider != "" {
				p.logBuffer.Add(entry)
				dbInsertLog(entry)
			}
			return
		}

		if model != "" && apiKeyUsed != "" {
			apiKeysMu.RLock()
			if info, exists := apiKeys[apiKeyUsed]; exists && info.Active && len(info.AllowedModels) > 0 {
				allowed := false
				for _, m := range info.AllowedModels {
					if m == model || m == provider+":"+model || m == "*" || m == provider+":" || m == provider+":*" {
						allowed = true
						break
					}
				}
				apiKeysMu.RUnlock()
				if !allowed {
					log.Printf("[WARN] requestTracking: model %s not allowed for key %s", model, maskAPIKey(apiKeyUsed))
					http.Error(w, "Forbidden: model not allowed for this API key", http.StatusForbidden)
					return
				}
			} else {
				apiKeysMu.RUnlock()
			}
		}

		p.stats.mu.Lock()
		p.stats.TotalRequests++
		p.stats.ActiveRequests++
		p.stats.mu.Unlock()

		cw := &capturingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(cw, r)

		latency := time.Since(start)
		latencyMs := latency.Milliseconds()

		success := cw.statusCode >= 200 && cw.statusCode < 300
		var errMsg string
		if !success {
			errMsg = http.StatusText(cw.statusCode)
		}

		var inputTokens, outputTokens int
		if cw.streaming && cw.streamUsage.Len() > 0 {
			inputTokens, outputTokens = extractTokensFromStreamUsage(cw.streamUsage.Bytes(), &spec.Usage)
		} else {
			inputTokens, outputTokens = extractTokensFromBody(cw.body.Bytes(), &spec.Usage)
		}

		p.stats.mu.Lock()
		p.stats.ActiveRequests--
		if success {
			p.stats.SuccessRequests++
		} else {
			p.stats.ErrorRequests++
		}
		p.stats.InputTokens += int64(inputTokens)
		p.stats.OutputTokens += int64(outputTokens)
		p.stats.TotalLatencyMs += latencyMs
		if provider != "" {
			p.stats.RequestsByProvider[provider]++
			td := p.stats.TokensByProvider[provider]
			td.InputTokens += int64(inputTokens)
			td.OutputTokens += int64(outputTokens)
			p.stats.TokensByProvider[provider] = td
		}
		if model != "" {
			p.stats.RequestsByModel[model]++
			td := p.stats.TokensByModel[model]
			td.InputTokens += int64(inputTokens)
			td.OutputTokens += int64(outputTokens)
			p.stats.TokensByModel[model] = td
		}
		dateKey := start.In(getUserLocation()).Format("2006-01-02")
		if ds, ok := p.stats.DailyStats[dateKey]; ok {
			ds.Requests++
			ds.InputTokens += int64(inputTokens)
			ds.OutputTokens += int64(outputTokens)
		} else {
			p.stats.DailyStats[dateKey] = &DailyStat{
				Requests:     1,
				InputTokens:  int64(inputTokens),
				OutputTokens: int64(outputTokens),
			}
		}
		p.stats.mu.Unlock()

		entry := &RequestLog{
			Timestamp:    start,
			Provider:     provider,
			Model:        model,
			InputTokens:  inputTokens,
			OutputTokens: outputTokens,
			LatencyMs:    latencyMs,
			Success:      success,
			ErrorMessage: errMsg,
			ClientIP:     getClientIP(r),
			APIKeyUsed:   apiKeyUsed,
			StatusCode:   cw.statusCode,
			Path:         r.URL.Path,
			Method:       r.Method,
		}
		reqContent := string(bodyBytes)
		if len(reqContent) > 10000 {
			reqContent = reqContent[:10000]
		}
		entry.RequestContent = reqContent
		respContent := cw.body.String()
		if len(respContent) > 10000 {
			respContent = respContent[:10000]
		}
		entry.ResponseContent = respContent
		uid := userIDForQuery(r)
		if uid == "" {
			apiKeysMu.RLock()
			if info, exists := apiKeys[apiKeyUsed]; exists {
				uid = info.UserID
			}
			apiKeysMu.RUnlock()
		}
		entry.UserID = uid
		entry.APIKeyID = apiKeyUsed
		entry.UpstreamProvider = cw.upstreamProvider
		entry.UpstreamModel = cw.upstreamModel
		entry.UpstreamReqHeaders = cw.upstreamReqHeaders
		entry.UpstreamRespHeaders = cw.upstreamRespHeaders
		entry.UpstreamReqBody = cw.upstreamReqBody
		entry.CallType = "client"
		entry.ClientReqHeaders = string(safeClientHeaders)
		if provider != "" {
			p.logBuffer.Add(entry)
			dbInsertLog(entry)
		}

		log.Printf("%s %s %d %dms in=%d out=%d provider=%s model=%s ip=%s",
			r.Method, r.URL.Path, cw.statusCode, latencyMs,
			inputTokens, outputTokens, provider, model, getClientIP(r))
	})
}

func (p *ProxyServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[DEBUG] authMiddleware: path=%s, config.APIKey set=%v", r.URL.Path, p.config.APIKey != "")
		if r.URL.Path == "/health" || r.URL.Path == "/oauth/callback" {
			next.ServeHTTP(w, r)
			return
		}

		if isLocalhost(r) {
			if tokenStr := extractBearerToken(r); tokenStr != "" {
				if claims, err := validateToken(tokenStr); err == nil && claims != nil {
					ctx := r.Context()
					r = r.WithContext(contextWithUser(ctx, claims))
				}
			}
			next.ServeHTTP(w, r)
			return
		}

		if strings.HasPrefix(r.URL.Path, "/admin/") && !strings.HasPrefix(r.URL.Path, "/admin/api/") {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/admin" {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/assets/") || r.URL.Path == "/vite.svg" || r.URL.Path == "/favicon.ico" {
			next.ServeHTTP(w, r)
			return
		}

		if strings.HasPrefix(r.URL.Path, "/analysis/") {
			if p.config.APIKey != "" {
				authHeader := r.Header.Get("Authorization")
				if authHeader != "Bearer "+p.config.APIKey {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}
			next.ServeHTTP(w, r)
			return
		}

		if strings.HasPrefix(r.URL.Path, "/api/v1/") {
			if p.config.APIKey != "" {
				authHeader := r.Header.Get("Authorization")
				expectedAuth := "Bearer " + p.config.APIKey
				log.Printf("[DEBUG] authMiddleware: /api/v1/ path, hasAuth=%v, match=%v",
					authHeader != "", authHeader == expectedAuth)
				if authHeader != expectedAuth {
					if authHeader == "" {
						log.Printf("[WARN] authMiddleware: /api/v1/ no auth header, allowing")
					} else {
						tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
						if tokenStr == authHeader || !isValidJWT(tokenStr) {
							log.Printf("[WARN] authMiddleware: /api/v1/ auth failed")
							http.Error(w, "Unauthorized", http.StatusUnauthorized)
							return
						}
						log.Printf("[DEBUG] authMiddleware: /api/v1/ JWT valid, allowing")
					}
				}
			}
			log.Printf("[DEBUG] authMiddleware: /api/v1/ allowed (no auth required or auth passed)")
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		apiKeyHeader := r.Header.Get("x-api-key")
		log.Printf("[DEBUG] authMiddleware: proxy path, hasAuth=%v, hasApiKey=%v", authHeader != "", apiKeyHeader != "")

		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			if isValidJWT(tokenStr) {
				next.ServeHTTP(w, r)
				return
			}
		}

		validKey := false
		if p.config.APIKey != "" {
			if authHeader == "Bearer "+p.config.APIKey || apiKeyHeader == p.config.APIKey {
				validKey = true
			}
		}

		if !validKey {
			key := ""
			if authHeader != "" {
				key = strings.TrimPrefix(authHeader, "Bearer ")
			} else if apiKeyHeader != "" {
				key = apiKeyHeader
			}
			log.Printf("[DEBUG] authMiddleware: checking dynamic key, keyLen=%d", len(key))
			if key != "" {
				apiKeysMu.Lock()
				if info, exists := apiKeys[key]; exists && info.Active {
					validKey = true
					info.RequestCount++
					now := time.Now()
					info.LastUsed = &now
					apiKeysMu.Unlock()
					dbUpdateAPIKeyUsage(info.ID, info.RequestCount, now)
				} else {
					apiKeysMu.Unlock()
				}
			}
		}

		if p.config.APIKey == "" && len(apiKeys) == 0 {
			if p.config.Host == "127.0.0.1" {
				validKey = true
			}
		}

		if !validKey {
			http.Error(w, "Unauthorized: Invalid or missing API key", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func maskAPIKey(key string) string {
	if len(key) <= 8 {
		return "***"
	}
	return key[:4] + "..." + key[len(key)-4:]
}

func maskAPIKeyForLog(key string) string {
	if key == "" {
		return ""
	}
	if len(key) <= 8 {
		return "***"
	}
	return key[:4] + "..." + key[len(key)-4:]
}

func extractAPIKeyFromRequest(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if strings.HasPrefix(token, "eyJ") && strings.Count(token, ".") == 2 {
			return ""
		}
		return token
	}
	apiKeyHeader := r.Header.Get("x-api-key")
	if apiKeyHeader != "" {
		return apiKeyHeader
	}
	return ""
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	idx := strings.LastIndex(r.RemoteAddr, ":")
	if idx != -1 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}

func generateRequestID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (p *ProxyServer) requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = generateRequestID()
		}
		w.Header().Set("X-Request-ID", reqID)
		r.Header.Set("X-Request-ID", reqID)
		next.ServeHTTP(w, r)
	})
}
