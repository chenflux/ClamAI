package main

import (
	"encoding/json"
	"log"
	"time"
)

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func dbSaveAPIKey(info *APIKeyInfo) {
	modelsJSON, _ := json.Marshal(info.AllowedModels)
	providerKeysJSON, _ := json.Marshal(info.ProviderKeys)

	k := &DBAPIKey{
		ID: info.ID, Key: info.Key, Name: info.Name, UserID: info.UserID,
		AllowedModels: string(modelsJSON), ProviderKeys: string(providerKeysJSON),
		CreatedAt: info.CreatedAt, Active: info.Active, RequestCount: info.RequestCount.Load(),
	}
	if info.LastUsed != nil {
		k.LastUsed = info.LastUsed
	}
	if info.LastSynced != nil {
		k.LastSynced = info.LastSynced
	}

	if err := gormDB.Save(k).Error; err != nil {
		log.Printf("[ERROR] dbSaveAPIKey: %v", err)
	}

	apiKeysMu.Lock()
	apiKeys[info.Key] = info
	apiKeysByID[info.ID] = info
	apiKeysMu.Unlock()
}

func dbDeleteAPIKey(id string) {
	apiKeysMu.Lock()
	if info, exists := apiKeysByID[id]; exists {
		delete(apiKeys, info.Key)
		delete(apiKeysByID, id)
	}
	apiKeysMu.Unlock()
	gormDB.Where("id = ?", id).Delete(&DBAPIKey{})
}

func dbUpdateAPIKeyUsage(id string, requestCount int64, lastUsed time.Time) {
	gormDB.Model(&DBAPIKey{}).Where("id = ?", id).Updates(map[string]interface{}{
		"request_count": requestCount, "last_used": &lastUsed,
	})
}

func dbLoadAPIKeys() (map[string]*APIKeyInfo, map[string]*APIKeyInfo) {
	keys := make(map[string]*APIKeyInfo)
	byID := make(map[string]*APIKeyInfo)

	var dbKeys []DBAPIKey
	if err := gormDB.Find(&dbKeys).Error; err != nil {
		log.Printf("[ERROR] dbLoadAPIKeys: %v", err)
		return keys, byID
	}

	for i := range dbKeys {
		k := &dbKeys[i]
		info := &APIKeyInfo{
			ID: k.ID, Key: k.Key, Name: k.Name, UserID: k.UserID,
			CreatedAt: k.CreatedAt, Active: k.Active,
		}
		info.RequestCount.Store(k.RequestCount)
		json.Unmarshal([]byte(k.AllowedModels), &info.AllowedModels)
		json.Unmarshal([]byte(k.ProviderKeys), &info.ProviderKeys)
		if info.ProviderKeys == nil {
			info.ProviderKeys = make(map[string]string)
		}
		if k.LastUsed != nil {
			info.LastUsed = k.LastUsed
		}
		if k.LastSynced != nil {
			info.LastSynced = k.LastSynced
		}

		keys[info.Key] = info
		byID[info.ID] = info
	}

	log.Printf("[INFO] dbLoadAPIKeys: loaded %d keys", len(keys))
	return keys, byID
}
