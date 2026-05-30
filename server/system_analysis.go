package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
)

var (
	systemAnalysisConfig       SystemAnalysisConfig
	systemAnalysisConfigMu     sync.RWMutex
	systemAnalysisTaskCounter  int64
	systemAnalysisRunning      int32
)

type SystemAnalysisConfig struct {
	Enabled            bool   `json:"enabled"`
	Model              string `json:"model"`
	APIKeyID           string `json:"api_key_id"`
	TimeRange          string `json:"time_range"`
	IntervalMinutes    int    `json:"interval_minutes"`
	NotifyOnHighRisk   bool   `json:"notify_on_high_risk"`
	AutoBlockRiskLevel string `json:"auto_block_risk_level"`
	SystemPrompt       string `json:"system_prompt"`
}

const defaultSystemPrompt = `你是一个专业的AI安全分析师，专注于识别未知威胁和异常行为模式。

你的任务是分析API Key的调用历史，识别潜在的安全威胁，包括但不限于：
- 异常的调用频率或时间模式
- 不同于往常的模型使用行为
- 可疑的请求内容模式（可能的探测或攻击）
- IP地址异常分布
- Token消耗异常
- 可能的凭证滥用或泄露迹象

你必须只返回纯JSON，不要包含任何markdown格式。格式如下：

{
  "risk_level": "低|中|高|极高",
  "summary": "一句话总结该API Key的整体安全状况",
  "details": {
    "call_frequency": { "level": "低|中|高|极高", "description": "调用频率分析描述" },
    "model_usage": { "level": "低|中|高|极高", "description": "模型使用分析描述" },
    "success_rate": { "level": "低|中|高|极高", "description": "成功率分析描述" },
    "request_content": { "level": "低|中|高|极高", "description": "请求内容安全分析描述" },
    "ip_distribution": { "level": "低|中|高|极高", "description": "IP分布分析描述" },
    "token_usage": { "level": "低|中|高|极高", "description": "Token消耗分析描述" }
  },
  "recommendations": ["建议1", "建议2"]
}`

type SystemAnalysisTask struct {
	ID                 string `json:"id"`
	TaskNo             string `json:"task_no"`
	Name               string `json:"name"`
	APIKeyID           string `json:"api_key_id"`
	Model              string `json:"model"`
	TimeRange          string `json:"time_range"`
	ScheduleType       string `json:"schedule_type"`
	IntervalMinutes    int    `json:"interval_minutes"`
	Status             string `json:"status"`
	ResultRiskLevel    string `json:"result_risk_level"`
	ResultSummary      string `json:"result_summary"`
	ResultDetail       string `json:"result_detail"`
	ResultDimensions   string `json:"result_dimensions"`
	ResultLogsAnalyzed int    `json:"result_logs_analyzed"`
	LastRunAt          string `json:"last_run_at"`
	NextRunAt          string `json:"next_run_at"`
	CreatedAt          string `json:"created_at"`
}

var proxyServerForSystemAnalysis *ProxyServer

func initSystemAnalysis() {
	proxyServerForSystemAnalysis = getProxyServer()
	var cnt int64
	gormDB.Table("system_analysis_config").Count(&cnt)
	if cnt == 0 {
		gormDB.Create(&DBSystemAnalysisConfig{
			ID:              1,
			Enabled:         true,
			Model:           "",
			TimeRange:       "7d",
			IntervalMinutes: 60,
			NotifyOnHigh:    true,
		})
		log.Printf("[INFO] initSystemAnalysis: created default config row")
	}
	loadSystemAnalysisConfig()
	initSystemAnalysisTaskCounter()
	go startSystemAnalysisScheduler()
}

func loadSystemAnalysisConfig() {
	var record DBSystemAnalysisConfig
	err := gormDB.Where("id = 1").First(&record).Error
	var cfg SystemAnalysisConfig
	if err != nil {
		cfg.Enabled = true
		cfg.TimeRange = "7d"
		cfg.IntervalMinutes = 60
		cfg.NotifyOnHighRisk = true
		cfg.SystemPrompt = defaultSystemPrompt
	} else {
		cfg.Enabled = record.Enabled
		cfg.Model = record.Model
		cfg.APIKeyID = record.APIKeyID
		cfg.TimeRange = record.TimeRange
		cfg.IntervalMinutes = record.IntervalMinutes
		cfg.NotifyOnHighRisk = record.NotifyOnHigh
		cfg.AutoBlockRiskLevel = record.AutoBlockRisk
		cfg.SystemPrompt = record.SystemPrompt
	}
	if cfg.SystemPrompt == "" {
		cfg.SystemPrompt = defaultSystemPrompt
	}
	systemAnalysisConfigMu.Lock()
	systemAnalysisConfig = cfg
	systemAnalysisConfigMu.Unlock()
	log.Printf("[INFO] loadSystemAnalysisConfig: enabled=%v model=%s interval=%dmin promptLen=%d",
		cfg.Enabled, cfg.Model, cfg.IntervalMinutes, len(cfg.SystemPrompt))
}

func initSystemAnalysisTaskCounter() {
	var maxNo string
	gormDB.Model(&DBSystemAnalysisTask{}).Select("COALESCE(MAX(task_no), 'S0000')").Row().Scan(&maxNo)
	if len(maxNo) > 1 {
		var n int
		if _, err := fmt.Sscanf(maxNo, "S%d", &n); err == nil {
			systemAnalysisTaskCounter = int64(n)
		}
	}
}

func nextSystemTaskNo() string {
	n := atomic.AddInt64(&systemAnalysisTaskCounter, 1)
	return fmt.Sprintf("S%04d", n)
}

func startSystemAnalysisScheduler() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		systemAnalysisConfigMu.RLock()
		cfg := systemAnalysisConfig
		systemAnalysisConfigMu.RUnlock()
		if !cfg.Enabled || cfg.Model == "" {
			continue
		}
		tasks, err := dbGetDueSystemAnalysisTasks()
		if err != nil || len(tasks) == 0 {
			continue
		}
		for _, task := range tasks {
			taskID, _ := task["id"].(string)
			safeGo(func() { executeSystemAnalysisTask(taskID, task) })
			dbSetSystemTaskNextRun(taskID, cfg.IntervalMinutes)
		}
	}
}

func dbGetDueSystemAnalysisTasks() ([]map[string]interface{}, error) {
	now := time.Now().UTC()
	var dbTasks []DBSystemAnalysisTask
	if err := gormDB.Where("schedule_type = ? AND status = ? AND next_run_at <= ?", "periodic", "running", now).
		Find(&dbTasks).Error; err != nil {
		return nil, err
	}
	var tasks []map[string]interface{}
	for _, t := range dbTasks {
		tasks = append(tasks, map[string]interface{}{
			"id": t.ID, "task_no": t.TaskNo, "name": t.Name,
			"api_key_id": t.APIKeyID, "model": t.Model, "time_range": t.TimeRange,
			"interval_minutes": t.IntervalMinutes,
		})
	}
	return tasks, nil
}

func dbSetSystemTaskNextRun(id string, intervalMinutes int) error {
	nextRun := time.Now().Add(time.Duration(intervalMinutes) * time.Minute).UTC()
	return gormDB.Model(&DBSystemAnalysisTask{}).Where("id = ?", id).Update("next_run_at", nextRun).Error
}

func executeSystemAnalysisTask(taskID string, task map[string]interface{}) {
	taskStart := time.Now()
	model, _ := task["model"].(string)
	timeRange, _ := task["time_range"].(string)
	if timeRange == "" {
		timeRange = "7d"
	}

	log.Printf("[SYS-ANALYSIS] executeSystemAnalysisTask START id=%s model=%s timeRange=%s", taskID, model, timeRange)

	if model == "" {
		log.Printf("[SYS-ANALYSIS] ERROR id=%s model is empty, aborting", taskID)
		dbUpdateSystemAnalysisTaskResult(taskID, "error", "未配置分析模型", "", "", 0)
		return
	}

	modelForGateway := model
	if !strings.Contains(modelForGateway, ":") {
		provider, _ := proxyServerForSystemAnalysis.resolveProvider(modelForGateway)
		if provider != nil {
			modelForGateway = provider.GetName() + ":" + modelForGateway
			log.Printf("[SYS-ANALYSIS] id=%s resolved model to %s", taskID, modelForGateway)
		} else {
			log.Printf("[SYS-ANALYSIS] WARN id=%s could not resolve provider for model=%s, using as-is", taskID, model)
		}
	}

	apiKeysMu.Lock()
	type keyEntry struct {
		ID  string
		Key string
	}
	var allKeys []keyEntry
	for kid, k := range apiKeysByID {
		allKeys = append(allKeys, keyEntry{ID: kid, Key: k.Key})
	}
	apiKeysMu.Unlock()

	if len(allKeys) == 0 {
		log.Printf("[SYS-ANALYSIS] ERROR id=%s no API keys found", taskID)
		dbUpdateSystemAnalysisTaskResult(taskID, "error", "No API keys found", "", "", 0)
		return
	}

	log.Printf("[SYS-ANALYSIS] executeSystemAnalysisTask START id=%s model=%s keys=%d", taskID, modelForGateway, len(allKeys))

	systemAnalysisConfigMu.RLock()
	cfg := systemAnalysisConfig
	systemAnalysisConfigMu.RUnlock()

	systemPrompt := cfg.SystemPrompt
	if systemPrompt == "" {
		systemPrompt = defaultSystemPrompt
	}

	type keyResult struct {
		APIKeyID      string `json:"api_key_id"`
		APIKeyName    string `json:"api_key_name"`
		RiskLevel     string `json:"risk_level"`
		Summary       string `json:"summary"`
		Detail        string `json:"detail"`
		Dimensions    string `json:"dimensions"`
		LogsCount     int    `json:"logs_count"`
		NewLogs       int    `json:"new_logs"`
		Skipped       bool   `json:"skipped"`
		LastLogID     int64  `json:"last_log_id"`
		ThreatScore   int    `json:"threat_score"`
		ThreatSignals string `json:"threat_signals"`
		Analyzed      bool   `json:"analyzed"`
	}

	var keyResults []keyResult
	var maxRisk string
	totalLogs := 0
	riskOrder := map[string]int{"低": 1, "中": 2, "高": 3, "极高": 4}
	skippedCount := 0

	for _, k := range allKeys {
		lastLogID := getLastAnalyzedLogID(k.ID)
		logs, _ := dbGetLogsByAPIKeyAfterID(k.Key, lastLogID, 500)

		apiKeysMu.Lock()
		keyName := ""
		if info, ok := apiKeysByID[k.ID]; ok {
			keyName = info.Name
		}
		apiKeysMu.Unlock()

		if len(logs) == 0 {
			if lastLogID > 0 {
				skippedCount++
				keyResults = append(keyResults, keyResult{
					APIKeyID:   k.ID,
					APIKeyName: keyName,
					RiskLevel:  "低",
					Summary:    "无新增日志，跳过分析",
					LogsCount:  0,
					NewLogs:    0,
					Skipped:    true,
					LastLogID:  lastLogID,
				})
			}
			continue
		}

		var maxID int64
		for _, l := range logs {
			if l.ID > maxID {
				maxID = l.ID
			}
		}

		threatScore, threatSignals := scoreThreat(logs, k.ID)
		signalsJSON, _ := json.Marshal(threatSignals)
		analyzeThreshold := 30
		shouldAnalyze := threatScore >= analyzeThreshold || len(logs) == 0

		if len(logs) == 0 {
			if lastLogID > 0 {
				skippedCount++
				keyResults = append(keyResults, keyResult{
					APIKeyID:      k.ID,
					APIKeyName:    keyName,
					RiskLevel:     "低",
					Summary:       "无新增日志，跳过分析",
					LogsCount:     0,
					NewLogs:       0,
					Skipped:       true,
					LastLogID:     lastLogID,
					ThreatScore:   threatScore,
					ThreatSignals: string(signalsJSON),
					Analyzed:      false,
				})
			}
			continue
		}

		var buf strings.Builder
		buf.WriteString(fmt.Sprintf("以下是通过该API Key(%s)的新增调用记录（共%d条，自上次分析后新增），请分析调用者行为模式，识别潜在安全威胁：\n\n", k.ID, len(logs)))
		for i, l := range logs {
			timestamp := formatTimeUser(l.Timestamp)
			buf.WriteString(fmt.Sprintf("[%d] 时间=%s, 模型=%s, 提供者=%s, 输入Token=%d, 输出Token=%d, 延迟=%dms, 成功=%v, IP=%s\n",
				i+1, timestamp, l.Model, l.Provider, l.InputTokens, l.OutputTokens, l.LatencyMs, l.Success, l.ClientIP))
			if l.RequestContent != "" {
				preview := l.RequestContent
				if len(preview) > 500 {
					preview = preview[:500] + "..."
				}
				buf.WriteString(fmt.Sprintf("    请求内容: %s\n", preview))
			}
			if l.ErrorMessage != "" {
				buf.WriteString(fmt.Sprintf("    错误: %s\n", l.ErrorMessage))
			}
		}

		if !shouldAnalyze {
			maxRiskThis := "低"
			if threatScore >= 20 {
				maxRiskThis = "中"
			}
			if threatScore >= 35 {
				maxRiskThis = "高"
			}
			skippedCount++
			summaryText := fmt.Sprintf("威胁评分 %d（低于阈值%d），自动跳过AI深度分析", threatScore, analyzeThreshold)
			if len(threatSignals) > 0 {
				summaryText += fmt.Sprintf("。命中规则: %d项", len(threatSignals))
			}
			keyResults = append(keyResults, keyResult{
				APIKeyID:      k.ID,
				APIKeyName:    keyName,
				RiskLevel:     maxRiskThis,
				Summary:       summaryText,
				LogsCount:     len(logs),
				NewLogs:       len(logs),
				Skipped:       false,
				LastLogID:     maxID,
				ThreatScore:   threatScore,
				ThreatSignals: string(signalsJSON),
				Analyzed:      false,
			})
			totalLogs += len(logs)
			if riskOrder[maxRiskThis] > riskOrder[maxRisk] {
				maxRisk = maxRiskThis
			}
			continue
		}

		messages := []map[string]interface{}{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": buf.String()},
		}

		log.Printf("[SYS-ANALYSIS] id=%s calling internalChatCompletion for key=%s model=%s logs=%d...", taskID, k.ID, modelForGateway, len(logs))
		statusCode, _, _, respBody, err := proxyServerForSystemAnalysis.internalChatCompletion(modelForGateway, messages, 0.3, 1500)
		if err != nil || statusCode < 200 || statusCode >= 300 {
			log.Printf("[SYS-ANALYSIS] WARN id=%s key=%s analysis failed: err=%v status=%d bodyLen=%d", taskID, k.ID, err, statusCode, len(respBody))
			continue
		}

		var resp map[string]interface{}
		if json.Unmarshal(respBody, &resp) != nil {
			continue
		}
		contentStr := extractContentFromResp(resp)
		if contentStr == "" {
			continue
		}
		parsed := extractJSON(contentStr)
		if parsed == nil {
			continue
		}

		rl, _ := parsed["risk_level"].(string)
		s, _ := parsed["summary"].(string)
		dimsJSON := ""
		if det, ok := parsed["details"].(map[string]interface{}); ok {
			if dimBytes, err := json.Marshal(det); err == nil {
				dimsJSON = string(dimBytes)
			}
		}
		if rl == "" {
			rl = "低"
		}

		apiKeysMu.Lock()
		keyName = ""
		if info, ok := apiKeysByID[k.ID]; ok {
			keyName = info.Name
		}
		apiKeysMu.Unlock()

		keyResults = append(keyResults, keyResult{
			APIKeyID:      k.ID,
			APIKeyName:    keyName,
			RiskLevel:     rl,
			Summary:       s,
			Detail:        contentStr,
			Dimensions:    dimsJSON,
			LogsCount:     len(logs),
			NewLogs:       len(logs),
			Skipped:       false,
			LastLogID:     maxID,
			ThreatScore:   threatScore,
			ThreatSignals: string(signalsJSON),
			Analyzed:      true,
		})
		totalLogs += len(logs)
		if riskOrder[rl] > riskOrder[maxRisk] {
			maxRisk = rl
		}
	}

	if maxRisk == "" {
		maxRisk = "低"
	}

	var allSummaries []string
	analyzedCount := 0
	skippedCount = 0
	maxThreatScore := 0
	for _, kr := range keyResults {
		if kr.Analyzed {
			allSummaries = append(allSummaries, fmt.Sprintf("[%s] %s", kr.APIKeyName, kr.Summary))
			analyzedCount++
		} else {
			skippedCount++
		}
		if kr.ThreatScore > maxThreatScore {
			maxThreatScore = kr.ThreatScore
		}
	}
	summary := fmt.Sprintf("已深度分析 %d 个Key，自动评分 %d 个（共%d条日志），最高风险: %s", analyzedCount, skippedCount, totalLogs, maxRisk)
	if len(allSummaries) > 0 {
		summary += "。各Key摘要: " + strings.Join(allSummaries, "; ")
	}
	if len(summary) > 2000 {
		summary = summary[:2000]
	}

	detailJSON, _ := json.Marshal(keyResults)

	log.Printf("[SYS-ANALYSIS] DONE id=%s risk=%s keys=%d logs=%d", taskID, maxRisk, len(keyResults), totalLogs)

	dbUpdateSystemAnalysisTaskResult(taskID, maxRisk, summary, string(detailJSON), "", totalLogs)
	durationMs := time.Since(taskStart).Milliseconds()

	var topThreatSignals []ThreatSignal
	for _, kr := range keyResults {
		if kr.ThreatScore > 0 {
			var signals []ThreatSignal
			if json.Unmarshal([]byte(kr.ThreatSignals), &signals) == nil {
				topThreatSignals = append(topThreatSignals, signals...)
			}
		}
	}
	historySignalsJSON, _ := json.Marshal(topThreatSignals[:min(len(topThreatSignals), 10)])

	historyID := dbInsertSystemAnalysisTaskHistory(taskID, maxRisk, summary, string(detailJSON), "", maxRisk, totalLogs, durationMs, maxThreatScore, string(historySignalsJSON), analyzedCount, skippedCount)

	runAt := formatTimeNow()
	for _, kr := range keyResults {
		if err := gormDB.Create(&DBSystemAnalysisKeyResult{
			TaskID:        taskID,
			HistoryID:     historyID,
			APIKeyID:      kr.APIKeyID,
			APIKeyName:    kr.APIKeyName,
			RiskLevel:     kr.RiskLevel,
			Summary:       kr.Summary,
			Detail:        kr.Detail,
			Dimensions:    kr.Dimensions,
			LogsCount:     kr.LogsCount,
			NewLogs:       kr.NewLogs,
			RunAt:         runAt,
			Skipped:       kr.Skipped,
			LastLogID:     kr.LastLogID,
			ThreatScore:   kr.ThreatScore,
			ThreatSignals: kr.ThreatSignals,
			Analyzed:      kr.Analyzed,
		}).Error; err != nil {
			log.Printf("[ERROR] executeSystemAnalysisTask: create key result for key=%s: %v", kr.APIKeyID, err)
		}
	}

	systemAnalysisConfigMu.RLock()
	notifyCfg := systemAnalysisConfig
	systemAnalysisConfigMu.RUnlock()

	if notifyCfg.NotifyOnHighRisk && (maxRisk == "高" || maxRisk == "极高") {
		log.Printf("[SYS-ANALYSIS] HIGH RISK DETECTED task=%s risk=%s", taskID, maxRisk)
	}

	_ = notifyCfg
}

func dbUpdateSystemAnalysisTaskResult(id, riskLevel, summary, detail, dimensions string, logsAnalyzed int) error {
	now := time.Now().UTC()
	return gormDB.Model(&DBSystemAnalysisTask{}).Where("id = ?", id).Updates(map[string]interface{}{
		"result_risk_level":    riskLevel,
		"result_summary":       summary,
		"result_detail":        detail,
		"result_dimensions":    dimensions,
		"result_logs_analyzed": logsAnalyzed,
		"last_run_at":          now,
	}).Error
}

func dbInsertSystemAnalysisTaskHistory(taskID, riskLevel, summary, detail, dimensions, status string, logsAnalyzed int, durationMs int64, threatScore int, threatSignals string, analyzedCount, skippedCount int) int64 {
	record := DBSystemAnalysisTaskHistory{
		TaskID:        taskID,
		RiskLevel:     riskLevel,
		Summary:       summary,
		Detail:        detail,
		Dimensions:    dimensions,
		LogsAnalyzed:  logsAnalyzed,
		Status:        status,
		DurationMs:    durationMs,
		ThreatScore:   threatScore,
		ThreatSignals: threatSignals,
		AnalyzedCount: analyzedCount,
		SkippedCount: skippedCount,
		RunAt:         time.Now().UTC(),
	}
	if err := gormDB.Create(&record).Error; err != nil {
		log.Printf("[ERROR] dbInsertSystemAnalysisTaskHistory: %v", err)
	}
	return record.ID
}

func getLastAnalyzedLogID(apiKeyID string) int64 {
	var result DBSystemAnalysisKeyResult
	if err := gormDB.Where("api_key_id = ? AND skipped = false", apiKeyID).Order("id DESC").First(&result).Error; err != nil {
		return 0
	}
	return result.LastLogID
}

func dbInsertSecurityAlertFromSystem(taskID, riskLevel, summary, model, apiKey, triggerType string) {
	now := time.Now()
	direction := "input"
	mode := "block"
	severity := "high"
	if riskLevel == "极高" {
		severity = "critical"
	} else if riskLevel == "高" {
		severity = "high"
	} else if riskLevel == "中" {
		severity = "medium"
	} else {
		severity = "low"
	}
	contentPreview := fmt.Sprintf("[系统分析] 风险等级: %s, 摘要: %s", riskLevel, summary)
	if err := gormDB.Create(&DBSecurityAlert{
		Timestamp:      now,
		Direction:      direction,
		Mode:           mode,
		TriggerType:    triggerType,
		TriggerDetail:  fmt.Sprintf("[系统/%s]", riskLevel),
		Severity:       severity,
		ContentPreview: contentPreview,
		Model:          model,
		APIKeyUsed:     apiKey,
		Action:         "记录告警",
		Resolved:       false,
		ClientIP:       "system",
	}).Error; err != nil {
		log.Printf("[ERROR] dbInsertSecurityAlertFromSystem: %v", err)
	}
}

func (p *ProxyServer) handleGetSystemAnalysisConfig(w http.ResponseWriter, r *http.Request) {
	systemAnalysisConfigMu.RLock()
	cfg := systemAnalysisConfig
	systemAnalysisConfigMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

func (p *ProxyServer) handleUpdateSystemAnalysisConfig(w http.ResponseWriter, r *http.Request) {
	var input SystemAnalysisConfig
	if json.NewDecoder(r.Body).Decode(&input) != nil {
		http.Error(w, "invalid input", 400)
		return
	}
	input.APIKeyID = ""
	log.Printf("[SYS-ANALYSIS] updateConfig: enabled=%v model=%s timeRange=%s interval=%d notify=%v",
		input.Enabled, input.Model, input.TimeRange, input.IntervalMinutes, input.NotifyOnHighRisk)
	now := time.Now().UTC()
	var count int64
	gormDB.Table("system_analysis_config").Count(&count)
	log.Printf("[SYS-ANALYSIS] updateConfig: table has %d rows before update", count)

	record := DBSystemAnalysisConfig{
		ID:              1,
		Enabled:         input.Enabled,
		Model:           input.Model,
		APIKeyID:        input.APIKeyID,
		TimeRange:       input.TimeRange,
		IntervalMinutes: input.IntervalMinutes,
		NotifyOnHigh:    input.NotifyOnHighRisk,
		AutoBlockRisk:   input.AutoBlockRiskLevel,
		SystemPrompt:    input.SystemPrompt,
		UpdatedAt:       now,
	}
	result := gormDB.Save(&record)
	log.Printf("[SYS-ANALYSIS] updateConfig Save: rowsAffected=%d error=%v", result.RowsAffected, result.Error)

	var verify DBSystemAnalysisConfig
	gormDB.Where("id = 1").First(&verify)
	log.Printf("[SYS-ANALYSIS] updateConfig verify: model=%s enabled=%v", verify.Model, verify.Enabled)
	if result.Error != nil {
		log.Printf("[SYS-ANALYSIS] updateConfig DB ERROR: %v", result.Error)
		http.Error(w, result.Error.Error(), 500)
		return
	}
	loadSystemAnalysisConfig()
	ensureSystemAnalysisTask()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func ensureSystemAnalysisTask() {
	systemAnalysisConfigMu.RLock()
	cfg := systemAnalysisConfig
	systemAnalysisConfigMu.RUnlock()
	if !cfg.Enabled || cfg.Model == "" {
		return
	}
	var count int64
	gormDB.Model(&DBSystemAnalysisTask{}).Where("created_by = ?", "__system__").Count(&count)
	if count == 0 {
		id := fmt.Sprintf("sys_%d", time.Now().UnixNano())
		taskNo := nextSystemTaskNo()
		nextRun := time.Now().Add(time.Duration(cfg.IntervalMinutes) * time.Minute).UTC()
		gormDB.Create(&DBSystemAnalysisTask{
			ID:              id,
			TaskNo:          taskNo,
			Name:            "系统行为分析",
			APIKeyID:        cfg.APIKeyID,
			Model:           cfg.Model,
			TimeRange:       cfg.TimeRange,
			ScheduleType:    "periodic",
			IntervalMinutes: cfg.IntervalMinutes,
			Status:          "running",
			NextRunAt:       &nextRun,
			CreatedBy:       "__system__",
		})
		log.Printf("[INFO] ensureSystemAnalysisTask: created system task id=%s", id)
	} else {
		gormDB.Model(&DBSystemAnalysisTask{}).Where("created_by = ?", "__system__").Updates(map[string]interface{}{
			"api_key_id":       cfg.APIKeyID,
			"model":            cfg.Model,
			"time_range":       cfg.TimeRange,
			"interval_minutes": cfg.IntervalMinutes,
			"status":           "running",
		})
	}
}

func (p *ProxyServer) handleListSystemAnalysisTasks(w http.ResponseWriter, r *http.Request) {
	var tasks []DBSystemAnalysisTask
	if err := gormDB.Order("created_at DESC").Find(&tasks).Error; err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	result := make([]map[string]interface{}, len(tasks))
	for i, t := range tasks {
		m := map[string]interface{}{
			"id": t.ID, "task_no": t.TaskNo, "name": t.Name,
			"api_key_id": t.APIKeyID, "model": t.Model,
			"time_range": t.TimeRange, "schedule_type": t.ScheduleType,
			"interval_minutes": t.IntervalMinutes, "status": t.Status,
			"result_logs_analyzed": t.LogsAnalyzed,
		}
		if t.LastRunAt != nil {
			m["last_run_at"] = formatTimeUTC(*t.LastRunAt)
		}
		if t.NextRunAt != nil {
			m["next_run_at"] = formatTimeUTC(*t.NextRunAt)
		}
		m["created_at"] = formatTimeUTC(t.CreatedAt)
		if t.RiskLevel != "" {
			m["result_risk_level"] = t.RiskLevel
		}
		if t.Summary != "" {
			m["result_summary"] = t.Summary
		}
		if t.Detail != "" {
			m["result_detail"] = t.Detail
		}
		if t.Dimensions != "" {
			m["result_dimensions"] = t.Dimensions
		}
		result[i] = m
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"tasks": result})
}

func (p *ProxyServer) handleGetSystemAnalysisTaskHistory(w http.ResponseWriter, r *http.Request) {
	var records []DBSystemAnalysisTaskHistory
	if err := gormDB.Order("id DESC").Limit(50).Find(&records).Error; err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	history := make([]map[string]interface{}, len(records))
	for i, h := range records {
		history[i] = map[string]interface{}{
			"id": h.ID, "risk_level": h.RiskLevel, "summary": h.Summary,
			"detail": h.Detail, "dimensions": h.Dimensions,
			"logs_analyzed": h.LogsAnalyzed, "status": h.Status,
			"duration_ms": h.DurationMs, "run_at": formatTimeUTC(h.RunAt),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"history": history})
}

func (p *ProxyServer) handleTriggerSystemAnalysis(w http.ResponseWriter, r *http.Request) {
	if !atomic.CompareAndSwapInt32(&systemAnalysisRunning, 0, 1) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "分析任务正在执行中，请稍候"})
		return
	}

	finish := func() { atomic.StoreInt32(&systemAnalysisRunning, 0) }

	var task DBSystemAnalysisTask
	if err := gormDB.Where("created_by = ?", "__system__").Limit(1).Find(&task).Error; err != nil {
		log.Printf("[SYS-ANALYSIS] trigger ERROR query tasks: %v", err)
		finish()
		http.Error(w, err.Error(), 500)
		return
	}

	if task.ID != "" {
		if task.Model == "" {
			log.Printf("[SYS-ANALYSIS] trigger SKIP: model is empty for task %s", task.ID)
			finish()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "未配置分析模型，请先保存配置"})
			return
		}
		t := map[string]interface{}{
			"id": task.ID, "task_no": task.TaskNo, "name": task.Name,
			"api_key_id": task.APIKeyID, "model": task.Model,
			"time_range": task.TimeRange, "interval_minutes": task.IntervalMinutes,
		}
		log.Printf("[SYS-ANALYSIS] trigger: starting task id=%s model=%s", task.ID, task.Model)
		safeGo(func() { defer finish(); executeSystemAnalysisTask(task.ID, t) })
	} else {
		log.Printf("[SYS-ANALYSIS] trigger: no __system__ task found, ensuring one exists")
		ensureSystemAnalysisTask()
		var task2 DBSystemAnalysisTask
		if err := gormDB.Where("created_by = ?", "__system__").Limit(1).Find(&task2).Error; err == nil && task2.ID != "" {
			if task2.Model == "" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "未配置分析模型，请先保存配置"})
				return
			}
			t := map[string]interface{}{
				"id": task2.ID, "task_no": task2.TaskNo, "name": task2.Name,
				"api_key_id": task2.APIKeyID, "model": task2.Model,
				"time_range": task2.TimeRange, "interval_minutes": task2.IntervalMinutes,
			}
			log.Printf("[SYS-ANALYSIS] trigger: starting created task id=%s model=%s", task2.ID, task2.Model)
			safeGo(func() { defer finish(); executeSystemAnalysisTask(task2.ID, t) })
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (p *ProxyServer) handleGetDefaultPrompt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"prompt": defaultSystemPrompt})
}

func (p *ProxyServer) handleGetKeyResults(w http.ResponseWriter, r *http.Request) {
	riskFilter := r.URL.Query().Get("risk")
	historyFilter := r.URL.Query().Get("history_id")
	var results []DBSystemAnalysisKeyResult
	q := gormDB.Order("id DESC")
	if riskFilter != "" {
		q = q.Where("risk_level = ?", riskFilter)
	}
	if historyFilter != "" {
		q = q.Where("history_id = ?", historyFilter)
	}
	if err := q.Find(&results).Error; err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

		grouped := map[string][]map[string]interface{}{}
	for _, r := range results {
		rl := r.RiskLevel
		if rl == "" {
			rl = "低"
		}
		entry := map[string]interface{}{
			"id":             r.ID,
			"task_id":        r.TaskID,
			"history_id":     r.HistoryID,
			"api_key_id":     r.APIKeyID,
			"api_key_name":   r.APIKeyName,
			"risk_level":     rl,
			"summary":        r.Summary,
			"detail":         r.Detail,
			"dimensions":     r.Dimensions,
			"logs_count":     r.LogsCount,
			"new_logs":       r.NewLogs,
			"run_at":         r.RunAt,
			"skipped":        r.Skipped,
			"threat_score":   r.ThreatScore,
			"threat_signals": r.ThreatSignals,
			"analyzed":       r.Analyzed,
		}
		grouped[rl] = append(grouped[rl], entry)
	}

	order := []string{"极高", "高", "中", "低"}
	ordered := make(map[string][]map[string]interface{})
	for _, k := range order {
		if v, ok := grouped[k]; ok {
			ordered[k] = v
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"results": ordered, "total": len(results)})
}

func (p *ProxyServer) handleAnalysisStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"running": atomic.LoadInt32(&systemAnalysisRunning) == 1,
	})
}

func (p *ProxyServer) setupSystemAnalysisRoutes(api *mux.Router) {
	api.HandleFunc("/system-analysis/config", p.handleGetSystemAnalysisConfig).Methods("GET")
	api.HandleFunc("/system-analysis/config", p.handleUpdateSystemAnalysisConfig).Methods("PUT")
	api.HandleFunc("/system-analysis/config/default-prompt", p.handleGetDefaultPrompt).Methods("GET")
	api.HandleFunc("/system-analysis/tasks", p.handleListSystemAnalysisTasks).Methods("GET")
	api.HandleFunc("/system-analysis/tasks/trigger", p.handleTriggerSystemAnalysis).Methods("POST")
	api.HandleFunc("/system-analysis/history", p.handleGetSystemAnalysisTaskHistory).Methods("GET")
	api.HandleFunc("/system-analysis/key-results", p.handleGetKeyResults).Methods("GET")
	api.HandleFunc("/system-analysis/status", p.handleAnalysisStatus).Methods("GET")
}