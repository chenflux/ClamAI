package main

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
)

const (
	maxLogEntries  = 10000
	maxCaptureSize = 1 << 20
)

func formatTimeUTC(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
}

func formatTimeNow() string {
	return formatTimeUTC(time.Now())
}

func getUserLocation() *time.Location {
	tzName := dbGetSystemSetting("ui.timezone")
	if tzName == "" {
		tzName = "Local"
	}
	if loc, err := time.LoadLocation(tzName); err == nil {
		return loc
	}
	return time.Local
}

func formatTimeUser(t time.Time) string {
	return t.In(getUserLocation()).Format("2006-01-02 15:04:05")
}

func userHour(t time.Time) int {
	return t.In(getUserLocation()).Hour()
}

func generateID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func initLogging() *os.File {
	exePath, err := os.Executable()
	if err != nil {
		log.Printf("Failed to get executable path: %v, using current dir", err)
		exePath = "."
	}
	dir := filepath.Dir(exePath)
	logFile := filepath.Join(dir, "clamai-server.log")

	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}

	log.SetOutput(file)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
	setupFilteredLogWriter(file, "info")

	log.Printf("=== ClamAI Service Started at %s ===", time.Now().Format(time.RFC3339))
	log.Printf("Log file: %s", logFile)

	if err := initLogger(logFile, "info"); err != nil {
		log.Printf("[WARN] Failed to init structured logger: %v", err)
	}

	return file
}

func getLogFilePath() string {
	exePath, _ := os.Executable()
	dir := filepath.Dir(exePath)
	return filepath.Join(dir, "clamai-server.log")
}

func applyDBLogLevel() {
	if db == nil {
		return
	}
	lvl := dbGetStringSetting("gateway.log_level", "")
	if lvl != "" {
		SetLogLevel(lvl)
		log.Printf("[INFO] applied log level from config: %s", lvl)
	}
}

type Config struct {
	Port       string
	AdminPort  string
	Host       string
	APIKey     string
	LogLevel   string
	ConfigPath string
	ProxyURL   string
	EnableTLS  bool
	TLSCert    string
	TLSKey     string
}

type TokenDetail struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}

type DailyStat struct {
	Requests     int64 `json:"requests"`
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}

type RequestStats struct {
	mu                 sync.Mutex
	TotalRequests      atomic.Int64
	ActiveRequests     atomic.Int32
	SuccessRequests    atomic.Int64
	ErrorRequests      atomic.Int64
	InputTokens        atomic.Int64
	OutputTokens       atomic.Int64
	TotalLatencyMs     atomic.Int64
	RequestsByProvider map[string]int64
	RequestsByModel    map[string]int64
	TokensByProvider   map[string]TokenDetail
	TokensByModel      map[string]TokenDetail
	DailyStats         map[string]*DailyStat
}

type RequestStatsForJSON struct {
	TotalRequests      int64                  `json:"total_requests"`
	SuccessRequests    int64                  `json:"success_requests"`
	ErrorRequests      int64                  `json:"error_requests"`
	InputTokens        int64                  `json:"input_tokens"`
	OutputTokens       int64                  `json:"output_tokens"`
	TotalLatencyMs     int64                  `json:"total_latency_ms"`
	RequestsByProvider map[string]int64       `json:"requests_by_provider"`
	RequestsByModel    map[string]int64       `json:"requests_by_model"`
	TokensByProvider   map[string]TokenDetail `json:"tokens_by_provider"`
	TokensByModel      map[string]TokenDetail `json:"tokens_by_model"`
	DailyStats         map[string]*DailyStat  `json:"daily_stats"`
}

func NewRequestStats() *RequestStats {
	return &RequestStats{
		RequestsByProvider: make(map[string]int64),
		RequestsByModel:    make(map[string]int64),
		TokensByProvider:   make(map[string]TokenDetail),
		TokensByModel:      make(map[string]TokenDetail),
		DailyStats:         make(map[string]*DailyStat),
	}
}

func getDataDir() string {
	exePath, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exePath)
}

func (s *RequestStats) ToJSON() RequestStatsForJSON {
	return RequestStatsForJSON{
		TotalRequests:      s.TotalRequests.Load(),
		SuccessRequests:    s.SuccessRequests.Load(),
		ErrorRequests:      s.ErrorRequests.Load(),
		InputTokens:        s.InputTokens.Load(),
		OutputTokens:       s.OutputTokens.Load(),
		TotalLatencyMs:     s.TotalLatencyMs.Load(),
		RequestsByProvider: s.RequestsByProvider,
		RequestsByModel:    s.RequestsByModel,
		TokensByProvider:   s.TokensByProvider,
		DailyStats:         s.DailyStats,
	}
}

func (s *RequestStats) LoadFromJSON(j *RequestStatsForJSON) {
	s.TotalRequests.Store(j.TotalRequests)
	s.SuccessRequests.Store(j.SuccessRequests)
	s.ErrorRequests.Store(j.ErrorRequests)
	s.InputTokens.Store(j.InputTokens)
	s.OutputTokens.Store(j.OutputTokens)
	s.TotalLatencyMs.Store(j.TotalLatencyMs)
	if j.RequestsByProvider != nil {
		s.RequestsByProvider = j.RequestsByProvider
	}
	if j.RequestsByModel != nil {
		s.RequestsByModel = j.RequestsByModel
	}
	if j.TokensByProvider != nil {
		s.TokensByProvider = j.TokensByProvider
	}
	if j.DailyStats != nil {
		s.DailyStats = j.DailyStats
	}
}

type RequestLog struct {
	ID              int64     `json:"id"`
	Timestamp       time.Time `json:"timestamp"`
	Provider        string    `json:"provider"`
	Model           string    `json:"model"`
	InputTokens     int       `json:"input_tokens"`
	OutputTokens    int       `json:"output_tokens"`
	LatencyMs       int64     `json:"latency_ms"`
	Success         bool      `json:"success"`
	ErrorMessage    string    `json:"error_message"`
	ClientIP        string    `json:"client_ip"`
	APIKeyUsed      string    `json:"api_key_used"`
	StatusCode      int       `json:"status_code"`
	Path            string    `json:"path"`
	Method          string    `json:"method"`
	RequestContent  string    `json:"request_content"`
	ResponseContent string    `json:"response_content"`
	UserID          string    `json:"user_id"`
	APIKeyID        string `json:"api_key_id"`
	IsProxyCall     bool   `json:"is_proxy_call"`
	CallType        string `json:"call_type"`
	UpstreamReqHeaders  string `json:"upstream_request_headers"`
	UpstreamRespHeaders string `json:"upstream_response_headers"`
	UpstreamReqBody     string `json:"upstream_request_body"`
	UpstreamRespBody    string `json:"upstream_response_body"`
	UpstreamProvider    string `json:"upstream_provider"`
	UpstreamModel       string `json:"upstream_model"`
	ClientReqHeaders    string `json:"client_request_headers"`
}

type LogBuffer struct {
	mu    sync.Mutex
	logs  []*RequestLog
	size  int
	start int
	count int
}

func NewLogBuffer(size int) *LogBuffer {
	return &LogBuffer{
		logs: make([]*RequestLog, size),
		size: size,
	}
}

func (lb *LogBuffer) Add(entry *RequestLog) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	idx := (lb.start + lb.count) % lb.size
	lb.logs[idx] = entry
	if lb.count < lb.size {
		lb.count++
	} else {
		lb.start = (lb.start + 1) % lb.size
	}
}

func (lb *LogBuffer) GetRecent(limit int) []*RequestLog {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if limit > lb.count {
		limit = lb.count
	}
	result := make([]*RequestLog, limit)
	for i := 0; i < limit; i++ {
		idx := (lb.start + lb.count - 1 - i) % lb.size
		result[i] = lb.logs[idx]
	}
	return result
}

func (lb *LogBuffer) Count() int {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	return lb.count
}

func (lb *LogBuffer) GetAll() []*RequestLog {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	result := make([]*RequestLog, 0, lb.count)
	for i := 0; i < lb.count; i++ {
		idx := (lb.start + i) % lb.size
		result = append(result, lb.logs[idx])
	}
	return result
}

type APIKeyInfo struct {
	ID            string            `json:"id"`
	Key           string            `json:"key,omitempty"`
	Name          string            `json:"name"`
	UserID        string            `json:"user_id"`
	AllowedModels []string          `json:"allowed_models"`
	ProviderKeys  map[string]string `json:"provider_keys"`
	CreatedAt     time.Time         `json:"created_at"`
	Active        bool              `json:"active"`
	RequestCount  atomic.Int64      `json:"request_count"`
	LastUsed      *time.Time        `json:"last_used,omitempty"`
	LastSynced    *time.Time        `json:"last_synced,omitempty"`
}

var (
	apiKeys             = make(map[string]*APIKeyInfo)
	apiKeysByID         = make(map[string]*APIKeyInfo)
	apiKeysMu           sync.RWMutex
	globalConfig        *Config
	internalAnalysisKey = generateRandomKey(32)
)

func getGlobalConfig() *Config {
	return globalConfig
}

func generateRandomKey(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func saveAPIKeys() {
	apiKeysMu.Lock()
	defer apiKeysMu.Unlock()

	for _, info := range apiKeys {
		dbSaveAPIKey(info)
	}
	log.Printf("[INFO] saveAPIKeys: saved %d keys", len(apiKeys))
}

type ProxyServer struct {
	config        *Config
	router        *mux.Router
	adminRouter   *mux.Router
	providers     map[string]Provider
	providerRoutes []ProviderRouteSpec
	stats         *RequestStats
	logBuffer     *LogBuffer
	mu            sync.RWMutex
	listenAddr    string
	proxyAddr     string
	useTLS        bool
}

type OpenAIChatRequest struct {
	Model       string          `json:"model"`
	Messages    []OpenAIMessage `json:"messages"`
	Stream      bool            `json:"stream,omitempty"`
	Temperature float64         `json:"temperature,omitempty"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
	Tools       []OpenAITool    `json:"tools,omitempty"`
	ToolChoice  interface{}     `json:"tool_choice,omitempty"`
}

type OpenAIMessage struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"`
	Name    string      `json:"name,omitempty"`
}

type OpenAITool struct {
	Type     string             `json:"type"`
	Function OpenAIToolFunction `json:"function"`
}

type OpenAIToolFunction struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Parameters  map[string]interface{} `json:"parameters"`
}

type AnthropicMessagesRequest struct {
	Model         string             `json:"model"`
	Messages      []AnthropicMessage `json:"messages"`
	Stream        bool               `json:"stream,omitempty"`
	MaxTokens     int                `json:"max_tokens,omitempty"`
	Temperature   float64            `json:"temperature,omitempty"`
	TopP          float64            `json:"top_p,omitempty"`
	TopK          int                `json:"top_k,omitempty"`
	System        interface{}        `json:"system,omitempty"`
	Tools         []AnthropicTool    `json:"tools,omitempty"`
	ToolChoice    interface{}        `json:"tool_choice,omitempty"`
	StopSequences []string           `json:"stop_sequences,omitempty"`
	Metadata      interface{}        `json:"metadata,omitempty"`
}

type AnthropicMessage struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"`
}

type AnthropicTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]interface{} `json:"input_schema"`
}

type ModelInfo struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

type ModelList struct {
	Object string      `json:"object"`
	Data   []ModelInfo `json:"data"`
}

var BuildVersion = "dev"

var oauthStates = make(map[string]*OAuthStateInfo)
var oauthStatesMu sync.Mutex

func cleanupOAuthStates() {
	oauthStatesMu.Lock()
	defer oauthStatesMu.Unlock()
	now := time.Now()
	for k, v := range oauthStates {
		if now.Sub(v.CreatedAt) > 10*time.Minute {
			delete(oauthStates, k)
		}
	}
}

type OAuthStateInfo struct {
	Provider    string    `json:"provider"`
	RedirectURI string    `json:"redirect_uri"`
	CreatedAt   time.Time `json:"created_at"`
}
