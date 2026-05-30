package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

func (p *ProxyServer) handleGetToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	username := getAdminUsername()
	if username == "" {
		http.Error(w, "No admin configured", http.StatusNotFound)
		return
	}
	if p.config.Host == "127.0.0.1" && isLocalhost(r) && req.Password == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(issueTokenPair(username))
		return
	}
	user, err := verifyUser(username, req.Password)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid password",
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(issueTokenPairForUser(user))
}

func (p *ProxyServer) setupUserRoutes(api *mux.Router) {
	api.HandleFunc("/users", p.handleListUsers).Methods("GET")
	api.HandleFunc("/users", p.handleCreateUser).Methods("POST")
	api.HandleFunc("/users/{id}", p.handleUpdateUser).Methods("PUT")
	api.HandleFunc("/users/{id}", p.handleDeleteUser).Methods("DELETE")
	api.HandleFunc("/users/{id}/reset-password", p.handleResetUserPassword).Methods("POST")
	api.HandleFunc("/users/settings/registration", p.handleSetRegistrationOpen).Methods("PUT")
}

func (p *ProxyServer) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := dbListUsers()
	if err != nil {
		http.Error(w, "Failed to list users", http.StatusInternalServerError)
		return
	}
	if users == nil {
		users = []map[string]interface{}{}
	}
	for _, u := range users {
		delete(u, "password_hash")
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"users": users})
}

func (p *ProxyServer) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
		Role        string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if req.Username == "" || len(req.Password) < 8 {
		http.Error(w, "用户名必填，密码至少8位", http.StatusBadRequest)
		return
	}
	for _, c := range req.Username {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			http.Error(w, "用户名只能包含字母、数字、下划线和连字符", http.StatusBadRequest)
			return
		}
	}
	if len(req.Username) > 32 {
		http.Error(w, "用户名最长32位", http.StatusBadRequest)
		return
	}
	if req.Role == "" {
		req.Role = "user"
	}
	if req.Role != "admin" && req.Role != "user" {
		http.Error(w, "角色必须是 admin 或 user", http.StatusBadRequest)
		return
	}
	if _, err := dbGetUserByUsername(req.Username); err == nil {
		http.Error(w, "用户名已存在", http.StatusConflict)
		return
	}
	hash, _ := hashPassword(req.Password)
	id := fmt.Sprintf("user_%d", time.Now().UnixNano())
	displayName := req.DisplayName
	if displayName == "" {
		displayName = req.Username
	}
	if err := dbCreateUser(id, req.Username, displayName, hash, req.Role); err != nil {
		http.Error(w, "创建用户失败", http.StatusInternalServerError)
		return
	}
	auditLog(r, "user.create", req.Username, "角色="+req.Role)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"id":      id,
		"message": "用户创建成功",
	})
}

func (p *ProxyServer) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	var req struct {
		DisplayName string `json:"display_name"`
		Role        string `json:"role"`
		Status      string `json:"status"`
		IsActive    *bool  `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if req.IsActive != nil {
		if *req.IsActive {
			req.Status = "active"
		} else {
			req.Status = "disabled"
		}
	}
	claims := getUserFromRequest(r)
	if req.Status == "disabled" {
		if claims != nil && claims.UserID == id {
			http.Error(w, "不能禁用自己", http.StatusBadRequest)
			return
		}
		target, _ := dbGetUserByID(id)
		if target != nil {
			if targetRole, _ := target["role"].(string); targetRole == "admin" {
				http.Error(w, "不能禁用管理员", http.StatusBadRequest)
				return
			}
		}
	}
	if req.Role != "admin" {
		var adminCount int64
		gormDB.Model(&DBUser{}).Where("role = ? AND id != ?", "admin", id).Count(&adminCount)
		if adminCount == 0 {
			user, _ := dbGetUserByID(id)
			if user != nil {
				if currentRole, _ := user["role"].(string); currentRole == "admin" {
					http.Error(w, "无法降级最后一个管理员", http.StatusBadRequest)
					return
				}
			}
		}
	}
	if err := dbUpdateUser(id, req.DisplayName, req.Role, req.Status); err != nil {
		http.Error(w, "更新失败", http.StatusInternalServerError)
		return
	}
	targetName := req.DisplayName
	if targetName == "" {
		if u, err := dbGetUserByID(id); err == nil {
			if dn, ok := u["display_name"].(string); ok && dn != "" {
				targetName = dn
			} else if un, ok := u["username"].(string); ok {
				targetName = un
			}
		}
	}
	auditLog(r, "user.update", targetName, "角色="+req.Role+" 状态="+req.Status)
	gormDB.Where("username IN (SELECT username FROM users WHERE id = ?)", id).Delete(&DBRefreshToken{})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (p *ProxyServer) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	claims := getUserFromRequest(r)
	if claims != nil && claims.UserID == id {
		http.Error(w, "不能删除自己", http.StatusBadRequest)
		return
	}
	user, err := dbGetUserByID(id)
	if err != nil {
		http.Error(w, "用户不存在", http.StatusNotFound)
		return
	}
	username, _ := user["username"].(string)
	if err := dbDeleteUser(id); err != nil {
		http.Error(w, "删除失败", http.StatusInternalServerError)
		return
	}
	auditLog(r, "user.delete", username, "")
	if username != "" {
		gormDB.Where("username = ?", username).Delete(&DBRefreshToken{})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (p *ProxyServer) handleResetUserPassword(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if len(req.NewPassword) < 8 {
		http.Error(w, "密码至少8位", http.StatusBadRequest)
		return
	}
	hasUpper := false
	hasDigit := false
	for _, c := range req.NewPassword {
		if c >= 'A' && c <= 'Z' {
			hasUpper = true
		}
		if c >= '0' && c <= '9' {
			hasDigit = true
		}
	}
	if !hasUpper || !hasDigit {
		http.Error(w, "密码必须包含大写字母和数字", http.StatusBadRequest)
		return
	}
	hash, _ := hashPassword(req.NewPassword)
	if err := dbUpdateUserPassword(id, hash); err != nil {
		http.Error(w, "重置失败", http.StatusInternalServerError)
		return
	}
	targetName := id
	if u, err := dbGetUserByID(id); err == nil {
		if dn, ok := u["display_name"].(string); ok && dn != "" {
			targetName = dn
		} else if un, ok := u["username"].(string); ok {
			targetName = un
		}
	}
	auditLog(r, "user.reset_password", targetName, "")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "密码已重置"})
}

func (p *ProxyServer) handleSetRegistrationOpen(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Open bool `json:"open"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	dbSetRegistrationOpen(req.Open)
	auditLog(r, "settings.registration", "开放注册", "状态="+strconv.FormatBool(req.Open))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"open":    req.Open,
	})
}
