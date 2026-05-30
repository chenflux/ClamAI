package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	db   *sql.DB
	dbMu sync.Mutex
)

func initDB() error {
	if err := initGormDB(); err != nil {
		return fmt.Errorf("initGormDB: %w", err)
	}

	if err := migrateFromJSON(); err != nil {
		log.Printf("[WARN] initDB: migration from JSON failed (non-fatal): %v", err)
	}

	migrateAdminToUsers()
	backfillSeverity()

	log.Printf("[INFO] initDB: database initialized successfully")
	initTaskCounters()

	seedDefaultThreatRules()
	loadThreatRules()

	return nil
}

func backfillSeverity() {
	var alerts []DBSecurityAlert
	if err := gormDB.Where("severity = '' OR severity IS NULL").Find(&alerts).Error; err != nil {
		return
	}

	for _, a := range alerts {
		sev := severityFromTrigger(a.TriggerType, a.TriggerDetail)
		if sev != "" {
			gormDB.Model(&DBSecurityAlert{}).Where("id = ?", a.ID).Update("severity", sev)
		}
	}
	if len(alerts) > 0 {
		log.Printf("[INFO] backfillSeverity: updated %d alerts", len(alerts))
	}
}

func migrateAdminToUsers() {
	var userCount int64
	gormDB.Model(&DBUser{}).Count(&userCount)
	if userCount > 0 {
		return
	}

	var admin DBAdminUser
	if err := gormDB.Where("id = 1").First(&admin).Error; err != nil {
		return
	}

	now := time.Now().UTC()
	user := DBUser{
		ID:           "user_admin",
		Username:     admin.Username,
		DisplayName:  admin.Username,
		PasswordHash: admin.PasswordHash,
		Role:         "admin",
		Status:       "active",
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := gormDB.Where("id = ?", user.ID).FirstOrCreate(&user).Error; err != nil {
		log.Printf("[WARN] migrateAdminToUsers: failed to insert admin into users: %v", err)
		return
	}

	log.Printf("[INFO] migrateAdminToUsers: migrated admin user '%s' to users table", admin.Username)
}

func migrateFromJSON() error {
	dir := getDataDir()

	apiKeysPath := filepath.Join(dir, "api_keys.json")
	if _, err := os.Stat(apiKeysPath); err == nil {
		data, err := os.ReadFile(apiKeysPath)
		if err == nil {
			var keys []*APIKeyInfo
			if json.Unmarshal(data, &keys) == nil && len(keys) > 0 {
				log.Printf("[INFO] migrateFromJSON: migrating %d api_keys from JSON", len(keys))
				for _, info := range keys {
					modelsJSON, _ := json.Marshal(info.AllowedModels)
					var lastUsed *time.Time
					if info.LastUsed != nil {
						t := info.LastUsed.UTC()
						lastUsed = &t
					}
					key := DBAPIKey{
						ID:            info.ID,
						Key:           info.Key,
						Name:          info.Name,
						AllowedModels: string(modelsJSON),
						CreatedAt:     info.CreatedAt.UTC(),
						Active:        info.Active,
						RequestCount:  info.RequestCount.Load(),
						LastUsed:      lastUsed,
					}
					if err := gormDB.Where("id = ?", key.ID).FirstOrCreate(&key).Error; err != nil {
						log.Printf("[ERROR] migrateFromJSON: api_keys FirstOrCreate id=%s: %v", key.ID, err)
					}
				}
				if err := os.Rename(apiKeysPath, apiKeysPath+".bak"); err != nil {
					log.Printf("[ERROR] migrateFromJSON: rename api_keys.json: %v", err)
				}
			}
		}
	}

	statsPath := filepath.Join(dir, "stats.json")
	if _, err := os.Stat(statsPath); err == nil {
		data, err := os.ReadFile(statsPath)
		if err == nil {
			var j RequestStatsForJSON
			if json.Unmarshal(data, &j) == nil && j.TotalRequests > 0 {
				log.Printf("[INFO] migrateFromJSON: migrating stats from JSON")
				stat := DBStat{
					ID:              1,
					TotalRequests:   j.TotalRequests,
					SuccessRequests: j.SuccessRequests,
					ErrorRequests:   j.ErrorRequests,
					InputTokens:     j.InputTokens,
					OutputTokens:    j.OutputTokens,
					TotalLatencyMs:  j.TotalLatencyMs,
					UpdatedAt:       time.Now().UTC(),
				}
				if err := gormDB.Save(&stat).Error; err != nil {
						log.Printf("[ERROR] migrateFromJSON: save stat: %v", err)
					}
					for k, v := range j.RequestsByProvider {
						td := j.TokensByProvider[k]
						if err := gormDB.Save(&DBStatByProvider{
							Provider:     k,
							Requests:     v,
							InputTokens:  td.InputTokens,
							OutputTokens: td.OutputTokens,
						}).Error; err != nil {
							log.Printf("[ERROR] migrateFromJSON: save stat_by_provider(%s): %v", k, err)
						}
					}
					for k, v := range j.RequestsByModel {
						if err := gormDB.Save(&DBStatByModel{Model: k, Requests: v}).Error; err != nil {
							log.Printf("[ERROR] migrateFromJSON: save stat_by_model(%s): %v", k, err)
						}
					}
					for k, v := range j.DailyStats {
						if err := gormDB.Save(&DBStatDaily{
							Date:         k,
							Requests:     v.Requests,
							InputTokens:  v.InputTokens,
							OutputTokens: v.OutputTokens,
						}).Error; err != nil {
							log.Printf("[ERROR] migrateFromJSON: save stat_daily(%s): %v", k, err)
						}
					}
					if err := os.Rename(statsPath, statsPath+".bak"); err != nil {
						log.Printf("[ERROR] migrateFromJSON: rename stats.json: %v", err)
					}
			}
		}
	}

	logsPath := filepath.Join(dir, "logs.json")
	if _, err := os.Stat(logsPath); err == nil {
		data, err := os.ReadFile(logsPath)
		if err == nil {
			var logs []*RequestLog
			if json.Unmarshal(data, &logs) == nil && len(logs) > 0 {
				log.Printf("[INFO] migrateFromJSON: migrating %d logs from JSON", len(logs))
				for _, entry := range logs {
					rl := DBRequestLog{
						Timestamp:    entry.Timestamp.UTC(),
						Provider:     entry.Provider,
						Model:        entry.Model,
						InputTokens:  entry.InputTokens,
						OutputTokens: entry.OutputTokens,
						LatencyMs:    entry.LatencyMs,
						Success:      entry.Success,
						ErrorMessage: entry.ErrorMessage,
						ClientIP:     entry.ClientIP,
						APIKeyUsed:   entry.APIKeyUsed,
						StatusCode:   entry.StatusCode,
						Path:         entry.Path,
						Method:       entry.Method,
					}
					if err := gormDB.Create(&rl).Error; err != nil {
						log.Printf("[ERROR] migrateFromJSON: create request_log: %v", err)
					}
				}
				if err := os.Rename(logsPath, logsPath+".bak"); err != nil {
					log.Printf("[ERROR] migrateFromJSON: rename logs.json: %v", err)
				}
			}
		}
	}

	return nil
}
