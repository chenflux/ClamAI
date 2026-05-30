package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

func dbGetSetting(key string) string {
	var s DBSystemSetting
	if err := gormDB.Where("key = ?", key).First(&s).Error; err != nil {
		return ""
	}
	return s.Value
}

func dbSetSetting(key, value string) {
	s := DBSystemSetting{Key: key, Value: value}
	if err := gormDB.Save(&s).Error; err != nil {
		log.Printf("[ERROR] dbSetSetting %s: %v", key, err)
	}
}

func dbGetSettingsByPrefix(prefix string) map[string]string {
	var settings []DBSystemSetting
	if err := gormDB.Where("key LIKE ?", prefix+"%").Find(&settings).Error; err != nil {
		return map[string]string{}
	}
	m := map[string]string{}
	for _, s := range settings {
		m[strings.TrimPrefix(s.Key, prefix)] = s.Value
	}
	return m
}

func dbGetBoolSetting(key string, def bool) bool {
	v := dbGetSetting(key)
	if v == "" {
		return def
	}
	return v == "true" || v == "1"
}

func dbGetIntSetting(key string, def int) int {
	v := dbGetSetting(key)
	if v == "" {
		return def
	}
	var n int
	fmt.Sscanf(v, "%d", &n)
	if n == 0 && v != "0" {
		return def
	}
	return n
}

func dbGetStringSetting(key, def string) string {
	v := dbGetSetting(key)
	if v == "" {
		return def
	}
	return v
}

var providerCache []map[string]interface{}
var providerCacheMu sync.RWMutex

func dbListProviders() []map[string]interface{} {
	providerCacheMu.RLock()
	if providerCache != nil {
		defer providerCacheMu.RUnlock()
		return providerCache
	}
	providerCacheMu.RUnlock()

	var providers []DBProvider
	if gormDB == nil {
		return []map[string]interface{}{}
	}
	if err := gormDB.Order("priority ASC, name ASC").Find(&providers).Error; err != nil {
		return []map[string]interface{}{}
	}

	result := make([]map[string]interface{}, 0, len(providers))
	for _, p := range providers {
		var modelsArr []string
		json.Unmarshal([]byte(p.Models), &modelsArr)
		if modelsArr == nil {
			modelsArr = []string{}
		}
		var disabledArr []string
		json.Unmarshal([]byte(p.DisabledModels), &disabledArr)
		if disabledArr == nil {
			disabledArr = []string{}
		}
		var oauth interface{}
		if p.OAuthConfig != "" && p.OAuthConfig != "null" {
			json.Unmarshal([]byte(p.OAuthConfig), &oauth)
		}
		var rl interface{}
		if p.RateLimits != "" && p.RateLimits != "null" {
			json.Unmarshal([]byte(p.RateLimits), &rl)
		}
		apiKeys := []map[string]interface{}{}
		if p.APIKey != "" {
			apiKeys = append(apiKeys, map[string]interface{}{
				"id": p.ID + "_key1", "key_value": p.APIKey, "name": "默认密钥",
				"is_active": true, "created_at": p.CreatedAt.UTC().Format(time.RFC3339), "usage_count": 0,
			})
		}
		m := map[string]interface{}{
			"id": p.ID, "name": p.Name, "provider_type": p.ProviderType, "auth_type": p.AuthType,
			"enabled": p.Enabled, "base_url": p.BaseURL, "api_keys": apiKeys,
			"models": modelsArr, "disabled_models": disabledArr,
			"oauth_config": oauth, "rate_limits": rl, "priority": p.Priority,
			"created_by": p.CreatedBy, "created_by_name": getUserNameByID(p.CreatedBy),
			"created_at": p.CreatedAt.UTC().Format(time.RFC3339), "updated_at": p.UpdatedAt.UTC().Format(time.RFC3339),
		}
		result = append(result, m)
	}

	providerCacheMu.Lock()
	providerCache = result
	providerCacheMu.Unlock()
	return result
}

func invalidateProviderCache() {
	providerCacheMu.Lock()
	providerCache = nil
	providerCacheMu.Unlock()
}

func dbAddProvider(p map[string]interface{}) error {
	invalidateProviderCache()
	models, _ := json.Marshal(sliceOrNil(p["models"]))
	disabled, _ := json.Marshal(sliceOrNil(p["disabled_models"]))
	oauth, _ := json.Marshal(p["oauth_config"])
	rates, _ := json.Marshal(p["rate_limits"])
	apiKey := ""
	if keys, ok := p["api_keys"].([]interface{}); ok && len(keys) > 0 {
		if km, ok := keys[0].(map[string]interface{}); ok {
			if kv, ok := km["key_value"].(string); ok {
				apiKey = kv
			}
		}
	}
	enabled := false
	if e, ok := p["enabled"].(bool); ok && e {
		enabled = true
	}
	rec := &DBProvider{
		ID: strOr(p["id"], ""), Name: strOr(p["name"], ""),
		ProviderType: strOr(p["provider_type"], ""), AuthType: strOr(p["auth_type"], "apikey"),
		Enabled: enabled, BaseURL: strOr(p["base_url"], ""), APIKey: apiKey,
		Models: string(models), DisabledModels: string(disabled),
		OAuthConfig: string(oauth), RateLimits: string(rates),
		Priority: intOr(p["priority"], 0), CreatedBy: strOr(p["created_by"], ""),
	}
	return gormDB.Save(rec).Error
}

func dbUpdateProvider(id string, p map[string]interface{}) error {
	invalidateProviderCache()
	models, _ := json.Marshal(sliceOrNil(p["models"]))
	disabled, _ := json.Marshal(sliceOrNil(p["disabled_models"]))
	oauth, _ := json.Marshal(p["oauth_config"])
	rates, _ := json.Marshal(p["rate_limits"])
	apiKey := ""
	if keys, ok := p["api_keys"].([]interface{}); ok && len(keys) > 0 {
		if km, ok := keys[0].(map[string]interface{}); ok {
			if kv, ok := km["key_value"].(string); ok {
				apiKey = kv
			}
		}
	}
	enabled := false
	if e, ok := p["enabled"].(bool); ok && e {
		enabled = true
	}
	return gormDB.Model(&DBProvider{}).Where("id = ?", id).Updates(map[string]interface{}{
		"name": p["name"], "provider_type": p["provider_type"],
		"auth_type": strOr(p["auth_type"], "apikey"), "enabled": enabled,
		"base_url": strOr(p["base_url"], ""), "api_key": apiKey,
		"models": string(models), "disabled_models": string(disabled),
		"oauth_config": string(oauth), "rate_limits": string(rates),
		"priority": intOr(p["priority"], 0),
		"updated_at": time.Now().UTC(),
	}).Error
}

func dbDeleteProvider(id string) error {
	invalidateProviderCache()
	return gormDB.Where("id = ?", id).Delete(&DBProvider{}).Error
}

func dbListModelMappings() []map[string]interface{} {
	var mappings []DBModelMapping
	if err := gormDB.Find(&mappings).Error; err != nil {
		return []map[string]interface{}{}
	}
	result := make([]map[string]interface{}, 0, len(mappings))
	for _, m := range mappings {
		result = append(result, map[string]interface{}{
			"alias": m.Alias, "provider_id": m.ProviderID, "model": m.Model, "description": m.Description,
		})
	}
	return result
}

func dbSetModelMapping(alias, providerID, model, desc string) error {
	rec := &DBModelMapping{
		Alias: alias, ProviderID: providerID, Model: model, Description: desc,
	}
	return gormDB.Save(rec).Error
}

func dbDeleteModelMapping(alias string) error {
	return gormDB.Where("alias = ?", alias).Delete(&DBModelMapping{}).Error
}

func dbListProfiles(userIDs ...string) []map[string]interface{} {
	var profiles []DBProfile
	q := gormDB.Order("created_at")
	if len(userIDs) > 0 && userIDs[0] != "" {
		q = q.Where("created_by = ? OR created_by = '' OR created_by IS NULL", userIDs[0])
	}
	if err := q.Find(&profiles).Error; err != nil {
		return []map[string]interface{}{}
	}
	result := make([]map[string]interface{}, 0, len(profiles))
	for _, p := range profiles {
		result = append(result, map[string]interface{}{
			"id": p.ID, "name": p.Name, "is_active": p.IsActive,
			"providers_json": p.ProvidersJSON, "mappings_json": p.MappingsJSON,
			"gateway_json": p.GatewayJSON, "advanced_json": p.AdvancedJSON,
			"service_json": p.ServiceJSON, "created_by": p.CreatedBy,
			"created_at": p.CreatedAt.UTC().Format(time.RFC3339), "updated_at": p.UpdatedAt.UTC().Format(time.RFC3339),
		})
	}
	return result
}

func dbSaveProfile(id, name, createdBy string, prov, mappings, gateway, advanced, service map[string]interface{}) error {
	pj, err := json.Marshal(prov)
	if err != nil {
		log.Printf("[ERROR] dbSaveProfile: marshal providers: %v", err)
	}
	mj, err := json.Marshal(mappings)
	if err != nil {
		log.Printf("[ERROR] dbSaveProfile: marshal mappings: %v", err)
	}
	gj, err := json.Marshal(gateway)
	if err != nil {
		log.Printf("[ERROR] dbSaveProfile: marshal gateway: %v", err)
	}
	aj, err := json.Marshal(advanced)
	if err != nil {
		log.Printf("[ERROR] dbSaveProfile: marshal advanced: %v", err)
	}
	sj, err := json.Marshal(service)
	if err != nil {
		log.Printf("[ERROR] dbSaveProfile: marshal service: %v", err)
	}
	p := &DBProfile{
		ID: id, Name: name, CreatedBy: createdBy,
		ProvidersJSON: string(pj), MappingsJSON: string(mj),
		GatewayJSON: string(gj), AdvancedJSON: string(aj), ServiceJSON: string(sj),
		IsActive: false,
	}
	return gormDB.Save(p).Error
}

func dbLoadProfile(id string) (map[string]interface{}, error) {
	var p DBProfile
	if err := gormDB.Where("id = ?", id).First(&p).Error; err != nil {
		return nil, fmt.Errorf("profile not found")
	}
	var prov, mappings, gateway, advanced, service map[string]interface{}
	if err := json.Unmarshal([]byte(p.ProvidersJSON), &prov); err != nil {
		log.Printf("[ERROR] dbLoadProfile: unmarshal providers for id=%s: %v", id, err)
	}
	if err := json.Unmarshal([]byte(p.MappingsJSON), &mappings); err != nil {
		log.Printf("[ERROR] dbLoadProfile: unmarshal mappings for id=%s: %v", id, err)
	}
	if err := json.Unmarshal([]byte(p.GatewayJSON), &gateway); err != nil {
		log.Printf("[ERROR] dbLoadProfile: unmarshal gateway for id=%s: %v", id, err)
	}
	if err := json.Unmarshal([]byte(p.AdvancedJSON), &advanced); err != nil {
		log.Printf("[ERROR] dbLoadProfile: unmarshal advanced for id=%s: %v", id, err)
	}
	if err := json.Unmarshal([]byte(p.ServiceJSON), &service); err != nil {
		log.Printf("[ERROR] dbLoadProfile: unmarshal service for id=%s: %v", id, err)
	}
	return map[string]interface{}{
		"name": p.Name, "providers": prov, "mappings": mappings,
		"gateway": gateway, "advanced": advanced, "service": service,
	}, nil
}

func dbDeleteProfile(id string) error {
	return gormDB.Where("id = ?", id).Delete(&DBProfile{}).Error
}

func dbRenameProfile(id, newName string) error {
	return gormDB.Model(&DBProfile{}).Where("id = ?", id).Updates(map[string]interface{}{
		"name": newName, "updated_at": time.Now().UTC(),
	}).Error
}

func dbSetActiveProfile(id string) error {
	gormDB.Model(&DBProfile{}).Where("is_active = ?", true).Update("is_active", false)
	return gormDB.Model(&DBProfile{}).Where("id = ?", id).Updates(map[string]interface{}{
		"is_active": true, "updated_at": time.Now().UTC(),
	}).Error
}

func dbGetActiveProfile() string {
	var id string
	gormDB.Raw("SELECT id FROM profiles WHERE is_active = true ORDER BY id LIMIT 1").Scan(&id)
	if id == "" {
		return "default"
	}
	return id
}

func dbGetUserSetting(userID, key string) string {
	var s DBUserSetting
	if err := gormDB.Where("user_id = ? AND key = ?", userID, key).First(&s).Error; err != nil {
		return ""
	}
	return s.Value
}

func dbSetUserSetting(userID, key, value string) error {
	s := DBUserSetting{UserID: userID, Key: key, Value: value}
	return gormDB.Save(&s).Error
}

func dbGetAllUserSettings(userID string) map[string]string {
	var settings []DBUserSetting
	if err := gormDB.Where("user_id = ?", userID).Find(&settings).Error; err != nil {
		return map[string]string{}
	}
	m := map[string]string{}
	for _, s := range settings {
		m[s.Key] = s.Value
	}
	return m
}

func strOr(v interface{}, def string) string {
	if s, ok := v.(string); ok {
		return s
	}
	return def
}

func intOr(v interface{}, def int) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	}
	return def
}

func sliceOrNil(v interface{}) []string {
	if arr, ok := v.([]string); ok {
		return arr
	}
	if arr, ok := v.([]interface{}); ok {
		var result []string
		for _, item := range arr {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return []string{}
}

func dbUpdateProviderModels(providerType string, models []string) {
	modelsJSON, _ := json.Marshal(models)
	result := gormDB.Model(&DBProvider{}).Where("provider_type = ?", providerType).Update("models", string(modelsJSON))
	if result.Error != nil {
		log.Printf("[ERROR] dbUpdateProviderModels(%s): %v", providerType, result.Error)
		return
	}
	if result.RowsAffected > 0 {
		invalidateProviderCache()
	}
}
