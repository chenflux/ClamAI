package main

import (
	"log"
	"sync"
	"time"
)

var (
	userNameCache   = make(map[string]string)
	userNameCacheMu sync.RWMutex
)

func invalidateUserNameCache(id string) {
	userNameCacheMu.Lock()
	delete(userNameCache, id)
	userNameCacheMu.Unlock()
}

func getUserNameByID(id string) string {
	if id == "" {
		return ""
	}
	userNameCacheMu.RLock()
	if name, ok := userNameCache[id]; ok {
		userNameCacheMu.RUnlock()
		return name
	}
	userNameCacheMu.RUnlock()

	var u DBUser
	if err := gormDB.Select("display_name, username").Where("id = ?", id).First(&u).Error; err != nil {
		return ""
	}
	name := u.DisplayName
	if name == "" {
		name = u.Username
	}
	userNameCacheMu.Lock()
	userNameCache[id] = name
	userNameCacheMu.Unlock()
	return name
}

func dbCreateUser(id, username, displayName, passwordHash, role string) error {
	u := &DBUser{
		ID: id, Username: username, DisplayName: displayName,
		PasswordHash: passwordHash, Role: role, Status: "active",
	}
	return gormDB.Create(u).Error
}

func dbGetUserByUsername(username string) (map[string]interface{}, error) {
	var u DBUser
	if err := gormDB.Where("username = ?", username).First(&u).Error; err != nil {
		return nil, err
	}
	return dbUserToMap(&u), nil
}

func dbGetUserByID(id string) (map[string]interface{}, error) {
	var u DBUser
	if err := gormDB.Where("id = ?", id).First(&u).Error; err != nil {
		return nil, err
	}
	return dbUserToMap(&u), nil
}

func dbListUsers() ([]map[string]interface{}, error) {
	var users []DBUser
	if err := gormDB.Order("created_at ASC").Find(&users).Error; err != nil {
		return nil, err
	}
	result := make([]map[string]interface{}, 0, len(users))
	for i := range users {
		result = append(result, dbUserToMap(&users[i]))
	}
	return result, nil
}

func dbUpdateUser(id, displayName, role, status string) error {
	invalidateUserNameCache(id)
	return gormDB.Model(&DBUser{}).Where("id = ?", id).Updates(map[string]interface{}{
		"display_name": displayName, "role": role, "status": status,
	}).Error
}

func dbUpdateUserPassword(id, passwordHash string) error {
	return gormDB.Model(&DBUser{}).Where("id = ?", id).Updates(map[string]interface{}{
		"password_hash": passwordHash,
	}).Error
}

func dbUpdateUserLastLogin(id string) {
	now := time.Now().UTC()
	if err := gormDB.Model(&DBUser{}).Where("id = ?", id).Update("last_login_at", &now).Error; err != nil {
		log.Printf("[ERROR] dbUpdateUserLastLogin(%s): %v", id, err)
	}
}

func dbDeleteUser(id string) error {
	invalidateUserNameCache(id)
	return gormDB.Where("id = ?", id).Delete(&DBUser{}).Error
}

func dbUserExists() bool {
	var count int64
	gormDB.Model(&DBUser{}).Count(&count)
	return count > 0
}

func dbAdminExists() bool {
	var count int64
	gormDB.Model(&DBUser{}).Where("role = ?", "admin").Count(&count)
	return count > 0
}

func dbAnyUserExists() bool {
	return dbUserExists()
}

func dbGetSystemSetting(key string) string {
	var s DBSystemSetting
	if err := gormDB.Where("key = ?", key).First(&s).Error; err != nil {
		return ""
	}
	return s.Value
}

func dbSetSystemSetting(key, value string) {
	s := DBSystemSetting{Key: key, Value: value}
	if err := gormDB.Save(&s).Error; err != nil {
		log.Printf("[ERROR] dbSetSystemSetting(%s): %v", key, err)
	}
}

func dbIsRegistrationOpen() bool {
	return dbGetSystemSetting("registration_open") == "true"
}

func dbSetRegistrationOpen(open bool) {
	val := "false"
	if open {
		val = "true"
	}
	dbSetSystemSetting("registration_open", val)
}

func dbUserToMap(u *DBUser) map[string]interface{} {
	m := map[string]interface{}{
		"id": u.ID, "username": u.Username, "display_name": u.DisplayName,
		"password_hash": u.PasswordHash, "role": u.Role, "status": u.Status,
		"created_at": u.CreatedAt.UTC().Format(time.RFC3339),
		"updated_at": u.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if u.LastLoginAt != nil {
		m["last_login_at"] = u.LastLoginAt.UTC().Format(time.RFC3339)
	}
	return m
}
