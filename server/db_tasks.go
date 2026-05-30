package main

import (
	"fmt"
	"log"
	"time"
)

func initTaskCounters() {
	var maxNo string
	var t DBAnalysisTask
	if err := gormDB.Model(&t).Select("COALESCE(MAX(task_no), 'T0000')").Row().Scan(&maxNo); err == nil && len(maxNo) > 1 {
		var n int
		if _, err := fmt.Sscanf(maxNo, "T%d", &n); err == nil && int64(n) > taskCounter {
			taskCounter = int64(n)
		}
	}
	var st DBSkillsTask
	if err := gormDB.Model(&st).Select("COALESCE(MAX(task_no), 'T0000')").Row().Scan(&maxNo); err == nil && len(maxNo) > 1 {
		var n int
		if _, err := fmt.Sscanf(maxNo, "T%d", &n); err == nil && int64(n) > taskCounter {
			taskCounter = int64(n)
		}
	}
	log.Printf("[INFO] initTaskCounters: counter=%d", taskCounter)
}

func dbCreateAnalysisTask(id, taskNo, name, apiKeyID, model, timeRange, scheduleType string, intervalMinutes int, createdBy string) error {
	now := time.Now().UTC()
	status := "idle"
	var nextRun *time.Time
	if scheduleType == "periodic" {
		nr := now.Add(time.Duration(intervalMinutes) * time.Minute)
		nextRun = &nr
		status = "running"
	}
	task := DBAnalysisTask{
		ID:              id,
		TaskNo:          taskNo,
		Name:            name,
		APIKeyID:        apiKeyID,
		Model:           model,
		TimeRange:       timeRange,
		ScheduleType:    scheduleType,
		IntervalMinutes: intervalMinutes,
		Status:          status,
		NextRunAt:       nextRun,
		CreatedAt:       now,
		CreatedBy:       createdBy,
	}
	return gormDB.Create(&task).Error
}

func dbGetAnalysisTasks(userID string) ([]map[string]interface{}, error) {
	var tasks []DBAnalysisTask
	q := gormDB.Model(&DBAnalysisTask{})
	if userID != "" {
		q = q.Where("created_by = ? OR created_by = ''", userID)
	}
	if err := q.Order("created_at DESC").Find(&tasks).Error; err != nil {
		return nil, err
	}
	var result []map[string]interface{}
	for _, t := range tasks {
		m := map[string]interface{}{
			"id":               t.ID,
			"task_no":          t.TaskNo,
			"name":             t.Name,
			"api_key_id":       t.APIKeyID,
			"model":            t.Model,
			"time_range":       t.TimeRange,
			"schedule_type":    t.ScheduleType,
			"interval_minutes": t.IntervalMinutes,
			"status":           t.Status,
			"created_at":       t.CreatedAt.UTC().Format(time.RFC3339),
			"result_logs_analyzed": t.ResultLogsCount,
		}
		if t.LastRunAt != nil {
			m["last_run_at"] = t.LastRunAt.UTC().Format(time.RFC3339)
		}
		if t.NextRunAt != nil {
			m["next_run_at"] = t.NextRunAt.UTC().Format(time.RFC3339)
		}
		if t.ResultSummary != "" {
			m["result_summary"] = t.ResultSummary
		}
		if t.ResultRiskLevel != "" {
			m["result_risk_level"] = t.ResultRiskLevel
		}
		if t.ResultDetail != "" {
			m["result_detail"] = t.ResultDetail
		}
		if t.ResultDims != "" {
			m["result_dimensions"] = t.ResultDims
		}
		if t.Progress != "" {
			m["progress"] = t.Progress
		}
		result = append(result, m)
	}
	return result, nil
}

func dbGetSkillsTaskByID(taskID string) (map[string]interface{}, error) {
	var t DBSkillsTask
	if err := gormDB.Where("id = ?", taskID).First(&t).Error; err != nil {
		return nil, err
	}
	m := map[string]interface{}{
		"id":            t.ID,
		"task_no":       t.TaskNo,
		"name":          t.Name,
		"model":         t.Model,
		"source_type":   t.SourceType,
		"source_info":   t.SourceInfo,
		"schedule_type": t.ScheduleType,
		"status":        t.Status,
		"created_at":    t.CreatedAt.UTC().Format(time.RFC3339),
		"created_by":    t.CreatedBy,
	}
	if t.LastRunAt != nil {
		m["last_run_at"] = t.LastRunAt.Format(time.RFC3339)
	}
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
	if t.Progress != "" {
		m["progress"] = t.Progress
	}
	return m, nil
}

func dbUpdateAnalysisTaskStatus(id, status string) error {
	if status == "running" {
		now := time.Now().UTC()
		return gormDB.Model(&DBAnalysisTask{}).Where("id = ?", id).Updates(map[string]interface{}{
			"status":     status,
			"next_run_at": &now,
			"progress":   "正在分析...",
		}).Error
	}
	return gormDB.Model(&DBAnalysisTask{}).Where("id = ?", id).Update("status", status).Error
}

func dbUpdateAnalysisTaskProgress(id, progress string) error {
	return gormDB.Model(&DBAnalysisTask{}).Where("id = ?", id).Update("progress", progress).Error
}

func dbUpdateAnalysisTask(id, name, apiKeyID, model, timeRange, scheduleType string, intervalMinutes int) error {
	return gormDB.Model(&DBAnalysisTask{}).Where("id = ?", id).Updates(map[string]interface{}{
		"name":             name,
		"api_key_id":       apiKeyID,
		"model":            model,
		"time_range":       timeRange,
		"schedule_type":    scheduleType,
		"interval_minutes": intervalMinutes,
	}).Error
}

func dbUpdateAnalysisTaskResult(id, riskLevel, summary, detail, dimensions string, logsAnalyzed int) error {
	now := time.Now().UTC()
	return gormDB.Model(&DBAnalysisTask{}).Where("id = ?", id).Updates(map[string]interface{}{
		"result_risk_level":   riskLevel,
		"result_summary":      summary,
		"result_detail":       detail,
		"result_dimensions":   dimensions,
		"result_logs_analyzed": logsAnalyzed,
		"last_run_at":         &now,
	}).Error
}

func dbDeleteAnalysisTask(id, userID string) error {
	q := gormDB.Where("id = ?", id)
	if userID != "" {
		q = q.Where("created_by = ? OR created_by = ''", userID)
	}
	return q.Delete(&DBAnalysisTask{}).Error
}

func dbGetDuePeriodicTasks() ([]map[string]interface{}, error) {
	now := time.Now().UTC()
	var tasks []DBAnalysisTask
	if err := gormDB.Model(&DBAnalysisTask{}).
		Select("id, task_no, name, api_key_id, model, time_range, interval_minutes").
		Where("schedule_type = ? AND status = ? AND next_run_at <= ?", "periodic", "running", now).
		Find(&tasks).Error; err != nil {
		return nil, err
	}
	var result []map[string]interface{}
	for _, t := range tasks {
		result = append(result, map[string]interface{}{
			"id":              t.ID,
			"task_no":         t.TaskNo,
			"name":            t.Name,
			"api_key_id":      t.APIKeyID,
			"model":           t.Model,
			"time_range":      t.TimeRange,
			"interval_minutes": t.IntervalMinutes,
		})
	}
	return result, nil
}

func dbSetTaskNextRun(id string, intervalMinutes int) error {
	nextRun := time.Now().Add(time.Duration(intervalMinutes) * time.Minute).UTC()
	return gormDB.Model(&DBAnalysisTask{}).Where("id = ?", id).Update("next_run_at", &nextRun).Error
}

func dbCreateSkillsTask(id, taskNo, name, model, sourceType, sourceInfo, scheduleType string, createdBy string) error {
	now := time.Now().UTC()
	task := DBSkillsTask{
		ID:           id,
		TaskNo:       taskNo,
		Name:         name,
		Model:        model,
		SourceType:   sourceType,
		SourceInfo:   sourceInfo,
		ScheduleType: scheduleType,
		Status:       "idle",
		CreatedAt:    now,
		CreatedBy:    createdBy,
	}
	return gormDB.Create(&task).Error
}

func dbGetSkillsTasks(userID string) ([]map[string]interface{}, error) {
	var tasks []DBSkillsTask
	q := gormDB.Model(&DBSkillsTask{})
	if userID != "" {
		q = q.Where("created_by = ? OR created_by = ''", userID)
	}
	if err := q.Order("created_at DESC").Find(&tasks).Error; err != nil {
		return nil, err
	}
	var result []map[string]interface{}
	for _, t := range tasks {
		m := map[string]interface{}{
			"id":            t.ID,
			"task_no":       t.TaskNo,
			"name":          t.Name,
			"model":         t.Model,
			"source_type":   t.SourceType,
			"source_info":   t.SourceInfo,
			"schedule_type": t.ScheduleType,
			"status":        t.Status,
			"created_at":    t.CreatedAt.UTC().Format(time.RFC3339),
		}
		if t.CreatedBy != "" {
			m["created_by"] = t.CreatedBy
		}
		if t.LastRunAt != nil {
			m["last_run_at"] = t.LastRunAt.UTC().Format(time.RFC3339)
		}
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
		if t.Progress != "" {
			m["progress"] = t.Progress
		}
		result = append(result, m)
	}
	return result, nil
}

func dbUpdateSkillsTaskResult(id, riskLevel, summary, detail, dimensions string) error {
	now := time.Now().UTC()
	return gormDB.Model(&DBSkillsTask{}).Where("id = ?", id).Updates(map[string]interface{}{
		"result_risk_level": riskLevel,
		"result_summary":    summary,
		"result_detail":     detail,
		"result_dimensions": dimensions,
		"last_run_at":       &now,
		"status":            "idle",
		"progress":          "",
	}).Error
}

func dbUpdateSkillsTaskStatus(id, status string) error {
	progress := ""
	if status == "running" {
		progress = "正在检测..."
	}
	return gormDB.Model(&DBSkillsTask{}).Where("id = ?", id).Updates(map[string]interface{}{
		"status":   status,
		"progress": progress,
	}).Error
}

func dbDeleteSkillsTask(id, userID string) error {
	q := gormDB.Where("id = ?", id)
	if userID != "" {
		q = q.Where("created_by = ? OR created_by = ''", userID)
	}
	return q.Delete(&DBSkillsTask{}).Error
}

func dbUpdateSkillsTask(id, name, model, sourceType, sourceInfo string) error {
	return gormDB.Model(&DBSkillsTask{}).Where("id = ?", id).Updates(map[string]interface{}{
		"name":        name,
		"model":       model,
		"source_type": sourceType,
		"source_info": sourceInfo,
	}).Error
}

func dbInsertSkillsTaskHistory(taskID, riskLevel, summary, detail, dimensions, status string, durationMs int64) {
	now := time.Now().UTC()
	h := DBSkillsTaskHistory{
		TaskID:     taskID,
		RiskLevel:  riskLevel,
		Summary:    summary,
		Detail:     detail,
		Dimensions: dimensions,
		Status:     status,
		DurationMs: durationMs,
		RunAt:      now,
	}
	if err := gormDB.Create(&h).Error; err != nil {
		log.Printf("[ERROR] dbInsertSkillsTaskHistory: %v", err)
	}
}

func dbGetSkillsTaskHistory(taskID string) ([]map[string]interface{}, error) {
	var histories []DBSkillsTaskHistory
	if err := gormDB.Model(&DBSkillsTaskHistory{}).
		Where("task_id = ?", taskID).
		Order("run_at DESC").
		Limit(50).
		Find(&histories).Error; err != nil {
		return nil, err
	}
	var result []map[string]interface{}
	for _, h := range histories {
		result = append(result, map[string]interface{}{
			"id":           h.ID,
			"risk_level":   h.RiskLevel,
			"summary":      h.Summary,
			"detail":       h.Detail,
			"dimensions":   h.Dimensions,
			"status":       h.Status,
			"duration_ms":  h.DurationMs,
			"run_at":       h.RunAt.UTC().Format(time.RFC3339),
		})
	}
	return result, nil
}

func dbInsertAnalysisTaskHistory(taskID, riskLevel, summary, detail, dimensions, status string, logsAnalyzed int, durationMs int64) {
	now := time.Now().UTC()
	h := DBAnalysisTaskHistory{
		TaskID:       taskID,
		RiskLevel:    riskLevel,
		Summary:      summary,
		Detail:       detail,
		Dimensions:   dimensions,
		LogsAnalyzed: logsAnalyzed,
		Status:       status,
		DurationMs:   durationMs,
		RunAt:        now,
	}
	if err := gormDB.Create(&h).Error; err != nil {
		log.Printf("[ERROR] dbInsertAnalysisTaskHistory: %v", err)
	}
}

func dbGetAnalysisTaskHistory(taskID string) ([]map[string]interface{}, error) {
	var histories []DBAnalysisTaskHistory
	if err := gormDB.Model(&DBAnalysisTaskHistory{}).
		Where("task_id = ?", taskID).
		Order("run_at DESC").
		Limit(50).
		Find(&histories).Error; err != nil {
		return nil, err
	}
	var result []map[string]interface{}
	for _, h := range histories {
		result = append(result, map[string]interface{}{
			"id":             h.ID,
			"risk_level":     h.RiskLevel,
			"summary":        h.Summary,
			"detail":         h.Detail,
			"dimensions":     h.Dimensions,
			"logs_analyzed":  h.LogsAnalyzed,
			"status":         h.Status,
			"duration_ms":    h.DurationMs,
			"run_at":         h.RunAt.UTC().Format(time.RFC3339),
		})
	}
	return result, nil
}
