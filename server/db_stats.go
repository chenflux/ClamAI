package main

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"gorm.io/gorm/clause"
)

func truncateStr(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen])
}

const maxLogRows = 50000

func dbSaveStats(stats *RequestStats) {
	stats.mu.Lock()
	data := stats.ToJSON()
	stats.mu.Unlock()

	gormDB.Save(&DBStat{
		ID:              1,
		TotalRequests:   data.TotalRequests,
		SuccessRequests: data.SuccessRequests,
		ErrorRequests:   data.ErrorRequests,
		InputTokens:     data.InputTokens,
		OutputTokens:    data.OutputTokens,
		TotalLatencyMs:  data.TotalLatencyMs,
		UpdatedAt:       time.Now().UTC(),
	})

	for k, v := range data.RequestsByProvider {
		td := data.TokensByProvider[k]
		gormDB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "provider"}},
			DoUpdates: clause.AssignmentColumns([]string{"requests", "input_tokens", "output_tokens"}),
		}).Create(&DBStatByProvider{
			Provider:     k,
			Requests:     v,
			InputTokens:  td.InputTokens,
			OutputTokens: td.OutputTokens,
		})
	}
	for k, v := range data.RequestsByModel {
		gormDB.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "model"}},
			DoUpdates: clause.AssignmentColumns([]string{"requests"}),
		}).Create(&DBStatByModel{
			Model:    k,
			Requests: v,
		})
	}
	for k, v := range data.DailyStats {
		gormDB.Save(&DBStatDaily{
			Date:         k,
			Requests:     v.Requests,
			InputTokens:  v.InputTokens,
			OutputTokens: v.OutputTokens,
		})
	}
}

func dbLoadStats(stats *RequestStats) {
	stats.mu.Lock()
	defer stats.mu.Unlock()

	stats.TotalRequests = 0
	stats.SuccessRequests = 0
	stats.ErrorRequests = 0
	stats.InputTokens = 0
	stats.OutputTokens = 0
	stats.TotalLatencyMs = 0
	stats.RequestsByProvider = make(map[string]int64)
	stats.TokensByProvider = make(map[string]TokenDetail)
	stats.RequestsByModel = make(map[string]int64)
	stats.TokensByModel = make(map[string]TokenDetail)
	stats.DailyStats = make(map[string]*DailyStat)

	var mainStat DBStat
	if err := gormDB.First(&mainStat).Error; err == nil {
		stats.TotalRequests = mainStat.TotalRequests
		stats.SuccessRequests = mainStat.SuccessRequests
		stats.ErrorRequests = mainStat.ErrorRequests
		stats.InputTokens = mainStat.InputTokens
		stats.OutputTokens = mainStat.OutputTokens
		stats.TotalLatencyMs = mainStat.TotalLatencyMs
	}

	var providerStats []DBStatByProvider
	gormDB.Find(&providerStats)
	for _, ps := range providerStats {
		stats.RequestsByProvider[ps.Provider] = ps.Requests
		td := TokenDetail{InputTokens: ps.InputTokens, OutputTokens: ps.OutputTokens}
		stats.TokensByProvider[ps.Provider] = td
		stats.TotalRequests += ps.Requests
		stats.InputTokens += ps.InputTokens
		stats.OutputTokens += ps.OutputTokens
	}

	var modelStats []DBStatByModel
	gormDB.Find(&modelStats)
	for _, ms := range modelStats {
		stats.RequestsByModel[ms.Model] = ms.Requests
	}

	var dailyStats []DBStatDaily
	gormDB.Find(&dailyStats)
	for _, ds := range dailyStats {
		stats.DailyStats[ds.Date] = &DailyStat{
			Requests:    ds.Requests,
			InputTokens: ds.InputTokens,
			OutputTokens: ds.OutputTokens,
		}
	}

	log.Printf("[INFO] dbLoadStats: total=%d, success=%d (from pre-computed tables)", stats.TotalRequests, stats.SuccessRequests)
}

func dbInsertLog(entry *RequestLog) {
	dbEntry := DBRequestLog{
		Timestamp:           entry.Timestamp.UTC(),
		Provider:            entry.Provider,
		Model:               entry.Model,
		InputTokens:         entry.InputTokens,
		OutputTokens:        entry.OutputTokens,
		LatencyMs:           entry.LatencyMs,
		Success:             entry.Success,
		ErrorMessage:        entry.ErrorMessage,
		ClientIP:            entry.ClientIP,
		APIKeyUsed:          entry.APIKeyUsed,
		StatusCode:          entry.StatusCode,
		Path:                entry.Path,
		Method:              entry.Method,
		RequestContent:      entry.RequestContent,
		ResponseContent:     entry.ResponseContent,
		UserID:              entry.UserID,
		APIKeyID:            entry.APIKeyID,
		IsProxyCall:         entry.IsProxyCall,
		CallType:            entry.CallType,
		UpstreamReqHeaders:  entry.UpstreamReqHeaders,
		UpstreamRespHeaders: entry.UpstreamRespHeaders,
		UpstreamReqBody:     entry.UpstreamReqBody,
		UpstreamRespBody:    entry.UpstreamRespBody,
		UpstreamProvider:    entry.UpstreamProvider,
		UpstreamModel:       entry.UpstreamModel,
		ClientReqHeaders:    entry.ClientReqHeaders,
	}
	if err := gormDB.Create(&dbEntry).Error; err != nil {
		log.Printf("[ERROR] dbInsertLog: %v", err)
	}
}

func dbInsertBlockedLog(provider, model, clientIP, apiKeyUsed, path, method, requestContent, errorMsg string) {
	entry := &RequestLog{
		Timestamp:       time.Now(),
		Provider:        provider,
		Model:           model,
		InputTokens:     0,
		OutputTokens:    0,
		LatencyMs:       0,
		Success:         false,
		ErrorMessage:    errorMsg,
		ClientIP:        clientIP,
		APIKeyUsed:      apiKeyUsed,
		StatusCode:      403,
		Path:            path,
		Method:          method,
		RequestContent:  truncateStr(requestContent, 500),
		ResponseContent: "",
	}
	dbInsertLog(entry)
}

func dbCleanupLogs() {
	result := gormDB.Exec(`DELETE FROM request_logs WHERE id NOT IN (SELECT id FROM request_logs ORDER BY id DESC LIMIT ?)`, maxLogRows)
	if result.Error != nil {
		log.Printf("[ERROR] dbCleanupLogs: %v", result.Error)
		return
	}
	if result.RowsAffected > 0 {
		log.Printf("[INFO] dbCleanupLogs: purged %d old log entries", result.RowsAffected)
	}
}

func dbLoadLogs(lb *LogBuffer) {
	const loadLimit = 10000
	rows, err := gormDB.Raw("SELECT timestamp, provider, model, input_tokens, output_tokens, latency_ms, success, error_message, client_ip, api_key_used, status_code, path, method FROM request_logs ORDER BY id DESC LIMIT ?", loadLimit).Rows()
	if err != nil {
		log.Printf("[ERROR] dbLoadLogs: %v", err)
		return
	}
	defer rows.Close()

	var entries []*RequestLog
	for rows.Next() {
		entry := &RequestLog{}
		var ts string
		var success int
		if err := rows.Scan(&ts, &entry.Provider, &entry.Model, &entry.InputTokens, &entry.OutputTokens,
			&entry.LatencyMs, &success, &entry.ErrorMessage, &entry.ClientIP,
			&entry.APIKeyUsed, &entry.StatusCode, &entry.Path, &entry.Method); err != nil {
			continue
		}
		entry.Timestamp, _ = time.Parse(time.RFC3339, ts)
		entry.Success = success == 1
		entries = append(entries, entry)
	}
	for i := len(entries) - 1; i >= 0; i-- {
		lb.Add(entries[i])
	}
	log.Printf("[INFO] dbLoadLogs: loaded %d entries", len(entries))
}

func dbGetRecentLogs(limit int, userID string) ([]*RequestLog, int) {
	var total int
	var rows *sql.Rows
	var err error
	cols := "id, timestamp, provider, model, input_tokens, output_tokens, latency_ms, success, error_message, client_ip, api_key_used, status_code, path, method, COALESCE(request_content,''), COALESCE(response_content,''), COALESCE(user_id,''), COALESCE(api_key_id,''), COALESCE(is_proxy_call,0), COALESCE(call_type,''), COALESCE(upstream_request_headers,''), COALESCE(upstream_response_headers,''), COALESCE(upstream_request_body,''), COALESCE(upstream_response_body,''), COALESCE(upstream_provider,''), COALESCE(upstream_model,''), COALESCE(client_request_headers,'')"
	if userID != "" {
		gormDB.Raw("SELECT COUNT(*) FROM request_logs WHERE user_id = ?", userID).Row().Scan(&total)
		rows, err = gormDB.Raw("SELECT "+cols+" FROM request_logs WHERE user_id = ? ORDER BY id DESC LIMIT ?", userID, limit).Rows()
	} else {
		gormDB.Raw("SELECT COUNT(*) FROM request_logs").Row().Scan(&total)
		rows, err = gormDB.Raw("SELECT "+cols+" FROM request_logs ORDER BY id DESC LIMIT ?", limit).Rows()
	}
	if err != nil {
		log.Printf("[ERROR] dbGetRecentLogs: %v", err)
		return nil, 0
	}
	defer rows.Close()

	var logs []*RequestLog
	for rows.Next() {
		entry := &RequestLog{}
		var ts string
		var success int
		var isProxyCall int
		if err := rows.Scan(&entry.ID, &ts, &entry.Provider, &entry.Model, &entry.InputTokens, &entry.OutputTokens,
			&entry.LatencyMs, &success, &entry.ErrorMessage, &entry.ClientIP,
			&entry.APIKeyUsed, &entry.StatusCode, &entry.Path, &entry.Method,
			&entry.RequestContent, &entry.ResponseContent, &entry.UserID, &entry.APIKeyID,
			&isProxyCall, &entry.CallType, &entry.UpstreamReqHeaders, &entry.UpstreamRespHeaders,
			&entry.UpstreamReqBody, &entry.UpstreamRespBody,
			&entry.UpstreamProvider, &entry.UpstreamModel, &entry.ClientReqHeaders); err != nil {
			continue
		}
		entry.Timestamp, _ = time.Parse(time.RFC3339, ts)
		entry.Success = success == 1
		entry.IsProxyCall = isProxyCall == 1
		logs = append(logs, entry)
	}
	return logs, total
}

func dbGetLogsByAPIKey(apiKey string, limit int) ([]*RequestLog, int) {
	return dbGetLogsByAPIKeyAfterID(apiKey, 0, limit)
}

func dbGetLogsByAPIKeyAfterID(apiKey string, afterID int64, limit int) ([]*RequestLog, int) {
	var total int
	if afterID > 0 {
		gormDB.Raw("SELECT COUNT(*) FROM request_logs WHERE api_key_used = ? AND id > ?", apiKey, afterID).Row().Scan(&total)
	} else {
		gormDB.Raw("SELECT COUNT(*) FROM request_logs WHERE api_key_used = ?", apiKey).Row().Scan(&total)
	}

	var rows *sql.Rows
	var err error
	if afterID > 0 {
		rows, err = gormDB.Raw("SELECT id, timestamp, provider, model, input_tokens, output_tokens, latency_ms, success, error_message, client_ip, api_key_used, status_code, path, method, COALESCE(request_content,''), COALESCE(response_content,'') FROM request_logs WHERE api_key_used = ? AND id > ? ORDER BY id DESC LIMIT ?", apiKey, afterID, limit).Rows()
	} else {
		rows, err = gormDB.Raw("SELECT id, timestamp, provider, model, input_tokens, output_tokens, latency_ms, success, error_message, client_ip, api_key_used, status_code, path, method, COALESCE(request_content,''), COALESCE(response_content,'') FROM request_logs WHERE api_key_used = ? ORDER BY id DESC LIMIT ?", apiKey, limit).Rows()
	}
	if err != nil {
		log.Printf("[ERROR] dbGetLogsByAPIKey: %v", err)
		return nil, 0
	}
	defer rows.Close()

	var logs []*RequestLog
	for rows.Next() {
		entry := &RequestLog{}
		var ts string
		var success int
		if err := rows.Scan(&entry.ID, &ts, &entry.Provider, &entry.Model, &entry.InputTokens, &entry.OutputTokens,
			&entry.LatencyMs, &success, &entry.ErrorMessage, &entry.ClientIP,
			&entry.APIKeyUsed, &entry.StatusCode, &entry.Path, &entry.Method,
			&entry.RequestContent, &entry.ResponseContent); err != nil {
			continue
		}
		entry.Timestamp, _ = time.Parse(time.RFC3339, ts)
		entry.Success = success == 1
		logs = append(logs, entry)
	}
	return logs, total
}

func dbInsertSkillsDetection(sourceType, sourceInfo, result, riskLevel, modelUsed, apiKeyID, createdBy string) {
	entry := DBSkillsDetectionHistory{
		CheckedAt:  time.Now().UTC(),
		SourceType: sourceType,
		SourceInfo: sourceInfo,
		Result:     result,
		RiskLevel:  riskLevel,
		ModelUsed:  modelUsed,
		APIKeyID:   apiKeyID,
		CreatedBy:  createdBy,
	}
	if err := gormDB.Create(&entry).Error; err != nil {
		log.Printf("[ERROR] dbInsertSkillsDetection: %v", err)
	}
}

func dbGetSkillsDetectionHistory(limit, offset int, userID string) ([]map[string]interface{}, int) {
	var total int
	if userID != "" {
		gormDB.Raw("SELECT COUNT(*) FROM skills_detection_history WHERE created_by = ? OR created_by = ''", userID).Row().Scan(&total)
	} else {
		gormDB.Raw("SELECT COUNT(*) FROM skills_detection_history").Row().Scan(&total)
	}

	var rows *sql.Rows
	var err error
	if userID != "" {
		rows, err = gormDB.Raw("SELECT id, checked_at, source_type, source_info, result, risk_level, model_used, api_key_id FROM skills_detection_history WHERE created_by = ? OR created_by = '' ORDER BY id DESC LIMIT ? OFFSET ?", userID, limit, offset).Rows()
	} else {
		rows, err = gormDB.Raw("SELECT id, checked_at, source_type, source_info, result, risk_level, model_used, api_key_id FROM skills_detection_history ORDER BY id DESC LIMIT ? OFFSET ?", limit, offset).Rows()
	}
	if err != nil {
		log.Printf("[ERROR] dbGetSkillsDetectionHistory: %v", err)
		return nil, 0
	}
	defer rows.Close()

	var records []map[string]interface{}
	for rows.Next() {
		var id int
		var checkedAt, sourceType, sourceInfo, result, riskLevel, modelUsed, apiKeyID string
		if rows.Scan(&id, &checkedAt, &sourceType, &sourceInfo, &result, &riskLevel, &modelUsed, &apiKeyID) == nil {
			records = append(records, map[string]interface{}{
				"id":          id,
				"checked_at":  checkedAt,
				"source_type": sourceType,
				"source_info": sourceInfo,
				"result":      result,
				"risk_level":  riskLevel,
				"model_used":  modelUsed,
				"api_key_id":  apiKeyID,
			})
		}
	}
	return records, total
}

func dbInsertProfileAnalysis(apiKeyID, timeRange, riskLevel, summary, result, modelUsed string, logsAnalyzed int, createdBy string) {
	entry := DBProfileAnalysisHistory{
		AnalyzedAt:   time.Now().UTC(),
		APIKeyID:     apiKeyID,
		TimeRange:    timeRange,
		RiskLevel:    riskLevel,
		Summary:      summary,
		Result:       result,
		ModelUsed:    modelUsed,
		LogsAnalyzed: logsAnalyzed,
		CreatedBy:    createdBy,
	}
	if err := gormDB.Create(&entry).Error; err != nil {
		log.Printf("[ERROR] dbInsertProfileAnalysis: %v", err)
	}
}

func dbGetProfileAnalysisHistory(limit, offset int, userID string) ([]map[string]interface{}, int) {
	var total int
	if userID != "" {
		gormDB.Raw("SELECT COUNT(*) FROM profile_analysis_history WHERE created_by = ? OR created_by = ''", userID).Row().Scan(&total)
	} else {
		gormDB.Raw("SELECT COUNT(*) FROM profile_analysis_history").Row().Scan(&total)
	}

	var rows *sql.Rows
	var err error
	if userID != "" {
		rows, err = gormDB.Raw("SELECT id, analyzed_at, api_key_id, time_range, risk_level, summary, result, model_used, logs_analyzed FROM profile_analysis_history WHERE created_by = ? OR created_by = '' ORDER BY id DESC LIMIT ? OFFSET ?", userID, limit, offset).Rows()
	} else {
		rows, err = gormDB.Raw("SELECT id, analyzed_at, api_key_id, time_range, risk_level, summary, result, model_used, logs_analyzed FROM profile_analysis_history ORDER BY id DESC LIMIT ? OFFSET ?", limit, offset).Rows()
	}
	if err != nil {
		log.Printf("[ERROR] dbGetProfileAnalysisHistory: %v", err)
		return nil, 0
	}
	defer rows.Close()

	var records []map[string]interface{}
	for rows.Next() {
		var id int
		var analyzedAt, apiKeyID, timeRange, riskLevel, summary, result, modelUsed string
		var logsAnalyzed int
		if rows.Scan(&id, &analyzedAt, &apiKeyID, &timeRange, &riskLevel, &summary, &result, &modelUsed, &logsAnalyzed) == nil {
			records = append(records, map[string]interface{}{
				"id":            id,
				"analyzed_at":   analyzedAt,
				"api_key_id":    apiKeyID,
				"time_range":    timeRange,
				"risk_level":    riskLevel,
				"summary":       summary,
				"result":        result,
				"model_used":    modelUsed,
				"logs_analyzed": logsAnalyzed,
			})
		}
	}
	return records, total
}

func dbDeleteProfileAnalysis(id int) error {
	return gormDB.Where("id = ?", id).Delete(&DBProfileAnalysisHistory{}).Error
}

type DBUsageStats struct {
	TotalRequests   int64
	SuccessRequests int64
	ErrorRequests   int64
	InputTokens     int64
	OutputTokens    int64
	TotalLatencyMs  int64
	ByProvider      map[string]map[string]interface{}
	ByModel         map[string]map[string]interface{}
	DailyBreakdown  map[string]*DailyStat
	HourlyBreakdown map[string]*DailyStat
	MinuteBreakdown map[string]*DailyStat
	Granularity     string
}

func dbGetUsageStats(periodMinutes int) *DBUsageStats {
	cutoff := time.Now().Add(-time.Duration(periodMinutes) * time.Minute).UTC()

	granularity := "hour"
	if periodMinutes <= 60 {
		granularity = "minute"
	} else if periodMinutes > 60*24 {
		granularity = "day"
	}

	stats := &DBUsageStats{
		ByProvider:      make(map[string]map[string]interface{}),
		ByModel:         make(map[string]map[string]interface{}),
		DailyBreakdown:  make(map[string]*DailyStat),
		HourlyBreakdown: make(map[string]*DailyStat),
		MinuteBreakdown: make(map[string]*DailyStat),
		Granularity:     granularity,
	}

	groupBy := ""
	if granularity == "minute" {
		groupBy = dbTruncateMinute("timestamp")
	} else if granularity == "hour" {
		groupBy = dbTruncateHour("timestamp")
	} else {
		groupBy = dbTruncateDay("timestamp")
	}

	providerExpr := "COALESCE(NULLIF(provider, ''), upstream_provider)"
	query := fmt.Sprintf(`SELECT
		COUNT(*) as total,
		SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as success,
		SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as errors,
		COALESCE(SUM(input_tokens), 0) as input_tokens,
		COALESCE(SUM(output_tokens), 0) as output_tokens,
		COALESCE(SUM(latency_ms), 0) as total_latency,
		%s as provider,
		model,
		%s as bucket
		FROM request_logs
		WHERE timestamp >= ? AND (provider != '' OR upstream_provider != '') AND call_type = 'client'
		GROUP BY %s, model, %s`, providerExpr, groupBy, providerExpr, groupBy)

	rows, err := gormDB.Raw(query, cutoff).Rows()
	if err != nil {
		log.Printf("[ERROR] dbGetUsageStats: %v", err)
		return stats
	}
	defer rows.Close()

	for rows.Next() {
		var total, success, errors, inputTok, outputTok, totalLat int64
		var provider, model, bucket string
		if err := rows.Scan(&total, &success, &errors, &inputTok, &outputTok, &totalLat, &provider, &model, &bucket); err != nil {
			continue
		}
		stats.TotalRequests += total
		stats.SuccessRequests += success
		stats.ErrorRequests += errors
		stats.InputTokens += inputTok
		stats.OutputTokens += outputTok
		stats.TotalLatencyMs += totalLat

		if _, ok := stats.ByProvider[provider]; !ok {
			stats.ByProvider[provider] = map[string]interface{}{"requests": int64(0), "tokens": int64(0), "success": int64(0)}
		}
		if v, ok := stats.ByProvider[provider]["requests"].(int64); ok {
			stats.ByProvider[provider]["requests"] = v + total
		} else {
			stats.ByProvider[provider]["requests"] = total
		}
		if v, ok := stats.ByProvider[provider]["success"].(int64); ok {
			stats.ByProvider[provider]["success"] = v + success
		} else {
			stats.ByProvider[provider]["success"] = success
		}
		if v, ok := stats.ByProvider[provider]["tokens"].(int64); ok {
			stats.ByProvider[provider]["tokens"] = v + inputTok + outputTok
		} else {
			stats.ByProvider[provider]["tokens"] = inputTok + outputTok
		}

		if _, ok := stats.ByModel[model]; !ok {
			stats.ByModel[model] = map[string]interface{}{"requests": int64(0), "tokens": int64(0)}
		}
		if v, ok := stats.ByModel[model]["requests"].(int64); ok {
			stats.ByModel[model]["requests"] = v + total
		} else {
			stats.ByModel[model]["requests"] = total
		}
		if v, ok := stats.ByModel[model]["tokens"].(int64); ok {
			stats.ByModel[model]["tokens"] = v + inputTok + outputTok
		} else {
			stats.ByModel[model]["tokens"] = inputTok + outputTok
		}

		if granularity == "minute" {
			if _, ok := stats.MinuteBreakdown[bucket]; !ok {
				stats.MinuteBreakdown[bucket] = &DailyStat{}
			}
			stats.MinuteBreakdown[bucket].Requests += total
			stats.MinuteBreakdown[bucket].InputTokens += inputTok
			stats.MinuteBreakdown[bucket].OutputTokens += outputTok
		} else if granularity == "hour" {
			if _, ok := stats.HourlyBreakdown[bucket]; !ok {
				stats.HourlyBreakdown[bucket] = &DailyStat{}
			}
			stats.HourlyBreakdown[bucket].Requests += total
			stats.HourlyBreakdown[bucket].InputTokens += inputTok
			stats.HourlyBreakdown[bucket].OutputTokens += outputTok
		} else {
			if _, ok := stats.DailyBreakdown[bucket]; !ok {
				stats.DailyBreakdown[bucket] = &DailyStat{}
			}
			stats.DailyBreakdown[bucket].Requests += total
			stats.DailyBreakdown[bucket].InputTokens += inputTok
			stats.DailyBreakdown[bucket].OutputTokens += outputTok
		}
	}

	return stats
}

func dbGetUsageStatsForUser(periodMinutes int, userID string) *DBUsageStats {
	cutoff := time.Now().Add(-time.Duration(periodMinutes) * time.Minute).UTC()

	stats := &DBUsageStats{
		ByProvider:      make(map[string]map[string]interface{}),
		ByModel:         make(map[string]map[string]interface{}),
		DailyBreakdown:  make(map[string]*DailyStat),
		HourlyBreakdown: make(map[string]*DailyStat),
		MinuteBreakdown: make(map[string]*DailyStat),
	}

	if userID == "" {
		return stats
	}

	rows, err := gormDB.Raw(`SELECT
		COUNT(*) as total,
		SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as success,
		SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as errors,
		COALESCE(SUM(input_tokens), 0) as input_tokens,
		COALESCE(SUM(output_tokens), 0) as output_tokens,
		COALESCE(SUM(latency_ms), 0) as total_latency,
		provider,
		model
		FROM request_logs
		WHERE timestamp >= ? AND user_id = ? AND call_type = 'client'
		GROUP BY provider, model`, cutoff, userID).Rows()
	if err != nil {
		log.Printf("[ERROR] dbGetUsageStatsForUser: %v", err)
		return stats
	}
	defer rows.Close()

	for rows.Next() {
		var total, success, errors, inputTok, outputTok, totalLat int64
		var provider, model string
		if err := rows.Scan(&total, &success, &errors, &inputTok, &outputTok, &totalLat, &provider, &model); err != nil {
			continue
		}
		stats.TotalRequests += total
		stats.SuccessRequests += success
		stats.ErrorRequests += errors
		stats.InputTokens += inputTok
		stats.OutputTokens += outputTok
		stats.TotalLatencyMs += totalLat

		if _, ok := stats.ByProvider[provider]; !ok {
			stats.ByProvider[provider] = map[string]interface{}{"requests": int64(0), "tokens": int64(0), "success": int64(0)}
		}
		if v, ok := stats.ByProvider[provider]["requests"].(int64); ok {
			stats.ByProvider[provider]["requests"] = v + total
		}
		if v, ok := stats.ByProvider[provider]["success"].(int64); ok {
			stats.ByProvider[provider]["success"] = v + success
		}
		if v, ok := stats.ByProvider[provider]["tokens"].(int64); ok {
			stats.ByProvider[provider]["tokens"] = v + inputTok + outputTok
		}
		if _, ok := stats.ByModel[model]; !ok {
			stats.ByModel[model] = map[string]interface{}{"requests": int64(0), "tokens": int64(0)}
		}
		if v, ok := stats.ByModel[model]["requests"].(int64); ok {
			stats.ByModel[model]["requests"] = v + total
		}
		if v, ok := stats.ByModel[model]["tokens"].(int64); ok {
			stats.ByModel[model]["tokens"] = v + inputTok + outputTok
		}
	}

	return stats
}

type CallerTopEntry struct {
	APIKeyUsed  string `json:"api_key_used"`
	KeyPreview  string `json:"key_preview"`
	ClientIP    string `json:"client_ip"`
	Requests    int64  `json:"requests"`
	InputTokens int64  `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	Owner       string `json:"owner"`
	IPs         string `json:"ips"`
}

func dbGetCallerTop10(periodMinutes int, userID string, isAdmin bool) []CallerTopEntry {
	cutoff := time.Now().Add(-time.Duration(periodMinutes) * time.Minute).UTC()
	query := `SELECT r.api_key_used, COUNT(*) as cnt,
		COALESCE(SUM(r.input_tokens), 0) as it, COALESCE(SUM(r.output_tokens), 0) as ot,
		COALESCE(u.display_name, u.username, '') as owner
		FROM request_logs r
		LEFT JOIN api_keys k ON r.api_key_used = k.key
		LEFT JOIN users u ON k.user_id = u.id
		WHERE r.timestamp >= ? AND r.api_key_used != ''`
	args := []interface{}{cutoff}
	if !isAdmin && userID != "" {
		query += ` AND r.user_id = ?`
		args = append(args, userID)
	}
	query += ` GROUP BY r.api_key_used ORDER BY cnt DESC LIMIT 10`
	rows, err := gormDB.Raw(query, args...).Rows()
	if err != nil {
		log.Printf("[ERROR] dbGetCallerTop10: %v", err)
		return nil
	}
	defer rows.Close()

	var result []CallerTopEntry
	internalKeys := map[string]bool{
		"behavior_analysis": true,
		"skills_detection":  true,
		"agent_deep_check":  true,
		"security-semantic": true,
	}
	for rows.Next() {
		var e CallerTopEntry
		if err := rows.Scan(&e.APIKeyUsed, &e.Requests, &e.InputTokens, &e.OutputTokens, &e.Owner); err != nil {
			continue
		}
		if internalKeys[e.APIKeyUsed] {
			e.KeyPreview = ""
		} else {
			e.KeyPreview = maskAPIKey(e.APIKeyUsed)
			e.APIKeyUsed = ""
		}
		result = append(result, e)
	}
	return result
}

func dbGetIPTop10(periodMinutes int, userID string, isAdmin bool) []CallerTopEntry {
	cutoff := time.Now().Add(-time.Duration(periodMinutes) * time.Minute).UTC()
	query := `SELECT r.client_ip, COUNT(*) as cnt,
		COALESCE(SUM(r.input_tokens), 0) as it, COALESCE(SUM(r.output_tokens), 0) as ot,
		` + dbGroupConcat("COALESCE(u.display_name, u.username, '')", ",") + ` as ips
		FROM request_logs r
		LEFT JOIN users u ON r.user_id = u.id
		WHERE r.timestamp >= ? AND r.client_ip != '' AND r.call_type = 'client'`
	args := []interface{}{cutoff}
	if !isAdmin && userID != "" {
		query += ` AND r.user_id = ?`
		args = append(args, userID)
	}
	query += ` GROUP BY r.client_ip ORDER BY cnt DESC LIMIT 10`
	rows, err := gormDB.Raw(query, args...).Rows()
	if err != nil {
		log.Printf("[ERROR] dbGetIPTop10: %v", err)
		return nil
	}
	defer rows.Close()

	var result []CallerTopEntry
	for rows.Next() {
		var e CallerTopEntry
		if err := rows.Scan(&e.ClientIP, &e.Requests, &e.InputTokens, &e.OutputTokens, &e.IPs); err != nil {
			continue
		}
		result = append(result, e)
	}
	return result
}

type SecurityTokenStats struct {
	TotalChecks  int64            `json:"total_checks"`
	TotalTokens  int64            `json:"total_tokens"`
	InputTokens  int64            `json:"input_tokens"`
	OutputTokens int64            `json:"output_tokens"`
	ByType       map[string]int64 `json:"by_type"`
}

func dbGetSecurityTokenStats(periodMinutes int, userID string, isAdmin bool) *SecurityTokenStats {
	cutoff := time.Now().Add(-time.Duration(periodMinutes) * time.Minute).UTC()
	stats := &SecurityTokenStats{
		ByType: make(map[string]int64),
	}

	baseWhere := `timestamp >= ? AND call_type = 'security'`
	args := []interface{}{cutoff}
	if !isAdmin && userID != "" {
		baseWhere += ` AND user_id = ?`
		args = append(args, userID)
	}

	gormDB.Raw(`SELECT COUNT(*),
		COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0)
		FROM request_logs WHERE `+baseWhere, args...).Row().Scan(&stats.TotalChecks, &stats.InputTokens, &stats.OutputTokens)
	stats.TotalTokens = stats.InputTokens + stats.OutputTokens

	rows, err := gormDB.Raw(`SELECT
		CASE
			WHEN path LIKE '%/security/semantic-check%' THEN 'security_check'
			WHEN request_content LIKE '%"analysis_type":"agent_deep_check%' THEN 'agent_deep_check'
			WHEN request_content LIKE '%"analysis_type":"user_profile_task%' THEN 'user_profile_task'
			WHEN request_content LIKE '%"analysis_type":"user_profile%' THEN 'user_profile'
			WHEN request_content LIKE '%"analysis_type":"skills_detection%' THEN 'skills_detection'
			ELSE 'security_analysis'
		END as atype,
		COALESCE(SUM(input_tokens), 0) + COALESCE(SUM(output_tokens), 0) as tok
		FROM request_logs WHERE `+baseWhere+` GROUP BY atype`, args...).Rows()
	if err != nil {
		return stats
	}
	defer rows.Close()

	for rows.Next() {
		var atype string
		var tok int64
		if rows.Scan(&atype, &tok) != nil {
			continue
		}
		stats.ByType[atype] += tok
	}
	return stats
}

type ThreatSignal struct {
	Rule     string `json:"rule"`
	Score    int    `json:"score"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

func scoreThreat(logs []*RequestLog, apiKeyID string) (int, []ThreatSignal) {
	if len(logs) == 0 {
		return 0, nil
	}

	var signals []ThreatSignal
	score := 0

	hourViolations := 0
	tokenSpikes := 0
	failThenSuccess := 0
	promptInjectionHits := 0
	encodedContent := 0
	rapidBursts := 0
	contentSuspicious := 0

	hours := make(map[int]int)
	var totalTokens, totalOutput, totalInput int
	var successCount int
	prevFailed := false
	seenReqs := make(map[string]int)
	lastReqTime := time.Time{}

	for _, l := range logs {
		tokens := l.InputTokens + l.OutputTokens
		totalTokens += tokens
		totalInput += l.InputTokens
		totalOutput += l.OutputTokens

		h := userHour(l.Timestamp)
		hours[h]++

		if l.Success {
			successCount++
			if prevFailed {
				failThenSuccess++
			}
		} else {
			prevFailed = true
		}

		if l.OutputTokens > 800 {
			tokenSpikes++
		}

		if h >= 1 && h <= 5 {
			hourViolations++
		}

		content := l.RequestContent
		if containsPromptInjection(content) {
			promptInjectionHits++
		}
		if containsEncoded(content) {
			encodedContent++
		}
		if containsSuspiciousContent(content) {
			contentSuspicious++
		}

		if !lastReqTime.IsZero() {
			interval := l.Timestamp.Sub(lastReqTime).Seconds()
			if interval < 2 && interval > 0 {
				rapidBursts++
			}
		}
		lastReqTime = l.Timestamp

		if count, ok := seenReqs[content]; ok {
			seenReqs[content] = count + 1
		} else {
			seenReqs[content] = 1
		}
	}

	total := len(logs)
	if total == 0 {
		return 0, nil
	}

	failCount := total - successCount
	if failCount > 0 && float64(successCount)/float64(total) < 0.5 {
		signals = append(signals, ThreatSignal{Rule: "error_rate_high", Score: 12, Severity: "high", Detail: fmt.Sprintf("成功率仅 %.0f%%（%d/%d）", float64(successCount)/float64(total)*100, successCount, total)})
		score += 12
	}

	if hourViolations >= 3 {
		signals = append(signals, ThreatSignal{Rule: "off_hours_activity", Score: 8, Severity: "medium", Detail: fmt.Sprintf("%d次调用发生在凌晨1-5点", hourViolations)})
		score += 8
	}

	if promptInjectionHits > 0 {
		severity := "high"
		if promptInjectionHits >= 2 {
			severity = "critical"
		}
		signals = append(signals, ThreatSignal{Rule: "prompt_injection_suspect", Score: 25, Severity: severity, Detail: fmt.Sprintf("检测到 %d 次提示词注入模式", promptInjectionHits)})
		score += 25
	}

	if encodedContent > 0 {
		signals = append(signals, ThreatSignal{Rule: "encoded_content", Score: 10, Severity: "medium", Detail: fmt.Sprintf("检测到 %d 次编码内容", encodedContent)})
		score += 10
	}

	if contentSuspicious > 0 {
		signals = append(signals, ThreatSignal{Rule: "suspicious_content", Score: 15, Severity: "high", Detail: fmt.Sprintf("检测到 %d 次可疑内容模式", contentSuspicious)})
		score += 15
	}

	if tokenSpikes > 0 && tokenSpikes >= total/3 {
		signals = append(signals, ThreatSignal{Rule: "token_spike", Score: 8, Severity: "medium", Detail: fmt.Sprintf("%d 次请求输出超过800 Token", tokenSpikes)})
		score += 8
	}

	if failThenSuccess > 0 {
		signals = append(signals, ThreatSignal{Rule: "fail_then_success", Score: 10, Severity: "medium", Detail: fmt.Sprintf("%d 次失败后紧跟成功（试探攻击特征）", failThenSuccess)})
		score += 10
	}

	if rapidBursts >= 5 {
		signals = append(signals, ThreatSignal{Rule: "rapid_burst", Score: 12, Severity: "high", Detail: fmt.Sprintf("%d 次极短间隔请求（<2秒）", rapidBursts)})
		score += 12
	}

	if totalOutput > 0 && totalInput > 0 && float64(totalOutput)/float64(totalInput) > 10 {
		signals = append(signals, ThreatSignal{Rule: "high_output_ratio", Score: 6, Severity: "low", Detail: fmt.Sprintf("输出/输入比极高（%.1f）", float64(totalOutput)/float64(totalInput))})
		score += 6
	}

	totalRepeats := 0
	for _, c := range seenReqs {
		if c > 1 {
			totalRepeats += c
		}
	}
	if totalRepeats >= 3 {
		signals = append(signals, ThreatSignal{Rule: "repeat_requests", Score: 8, Severity: "medium", Detail: fmt.Sprintf("%d 次重复请求内容", totalRepeats)})
		score += 8
	}

	if score > 100 {
		score = 100
	}

	return score, signals
}

var promptInjectionPatterns = []string{
	"ignore previous instructions",
	"disregard all previous",
	"forget all rules",
	"你现在是",
	"you are now",
	"pretend you are",
	"ignore system prompt",
	"disregard your",
	"new instructions:",
	"forget previous",
	"&&&&&",
	"[INST]",
	"[/INST]",
	"<|im_end|>",
	"<|im_start|>",
}

var suspiciousPatterns = []string{
	"hack",
	"exploit",
	"bypass",
	"injection",
	"payload",
	"eval(",
	"exec(",
	"system(",
	"rm -rf",
	"curl ",
	"wget ",
	"base64",
	"decode",
	"decrypt",
}

func containsPromptInjection(content string) bool {
	lower := strings.ToLower(content)
	for _, pattern := range promptInjectionPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func containsEncoded(content string) bool {
	if len(content) < 10 {
		return false
	}
	patterns := []string{"base64", "decode", "%3a", "%2f", "url_encode"}
	lower := strings.ToLower(content)
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	alphanum := 0
	for _, c := range content {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '=' || c == '+' || c == '/' {
			alphanum++
		}
	}
	if len(content) > 20 && alphanum > len(content)*80/100 {
		if strings.Count(content, "=") >= 1 {
			return true
		}
	}
	return false
}

func containsSuspiciousContent(content string) bool {
	lower := strings.ToLower(content)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}
