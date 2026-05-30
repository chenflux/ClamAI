package main

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret []byte

var (
	loginAttempts   = make(map[string]*loginAttemptInfo)
	loginAttemptsMu sync.Mutex
)

type loginAttemptInfo struct {
	count    int
	lastTime time.Time
	blocked  bool
}

func getRemainingLoginAttempts(ip string) int {
	cfg := getLoginGuardConfig()
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	info, exists := loginAttempts[ip]
	if !exists {
		return cfg.MaxAttempts
	}
	remaining := cfg.MaxAttempts - info.count
	if remaining < 0 {
		remaining = 0
	}
	return remaining
}

func clearLoginAttempts(ip string) {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	delete(loginAttempts, ip)
}

func checkLoginRateLimit(ip string) bool {
	cfg := getLoginGuardConfig()
	window := time.Duration(cfg.WindowMinutes) * time.Minute
	blockDur := time.Duration(cfg.BlockMinutes) * time.Minute
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	now := time.Now()
	info, exists := loginAttempts[ip]
	if !exists {
		loginAttempts[ip] = &loginAttemptInfo{count: 1, lastTime: now}
		return true
	}
	if info.blocked && now.Sub(info.lastTime) < blockDur {
		return false
	}
	if info.blocked {
		delete(loginAttempts, ip)
		loginAttempts[ip] = &loginAttemptInfo{count: 1, lastTime: now}
		return true
	}
	if now.Sub(info.lastTime) > window {
		loginAttempts[ip] = &loginAttemptInfo{count: 1, lastTime: now}
		return true
	}
	info.count++
	info.lastTime = now
	if info.count > cfg.MaxAttempts {
		info.blocked = true
		addGreyListWithSource(ip, "login_brute")
		return false
	}
	return true
}

func init() {
	safeGo(func() {
		for {
			time.Sleep(5 * time.Minute)
			loginAttemptsMu.Lock()
			now := time.Now()
			for ip, info := range loginAttempts {
				cfg := getLoginGuardConfig()
				maxAge := time.Duration(cfg.WindowMinutes) * time.Minute
				if info.blocked {
					maxAge = time.Duration(cfg.BlockMinutes) * time.Minute
				}
				if now.Sub(info.lastTime) > maxAge {
					delete(loginAttempts, ip)
				}
			}
			loginAttemptsMu.Unlock()
		}
	})
}

type UserClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

type AdminClaims = UserClaims

func initJWTSecret() {
	secret := getOrCreateJWTSecret()
	jwtSecret = []byte(secret)
	log.Printf("[INFO] initJWTSecret: JWT secret initialized (%d bytes)", len(jwtSecret))
}

func getOrCreateJWTSecret() string {
	var record DBAdminSecret
	if err := gormDB.Where("key = ?", "jwt_secret").First(&record).Error; err == nil && record.SecretValue != "" {
		return record.SecretValue
	}
	secret := generateAPIKey()
	gormDB.Save(&DBAdminSecret{Key: "jwt_secret", SecretValue: secret})
	return secret
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

func checkPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func generateToken(userID, username, role string, expiry time.Duration) (string, error) {
	claims := UserClaims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "clamai",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func validateToken(tokenStr string) (*UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*UserClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}

func isValidJWT(tokenStr string) bool {
	claims, err := validateToken(tokenStr)
	if err != nil {
		return false
	}
	return claims.Role == "admin" || claims.Role == "user"
}
