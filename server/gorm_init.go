package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	gormDB *gorm.DB
)

func initGormDB() error {
	var err error

	dbType := os.Getenv("CLAMAI_DATABASE_TYPE")
	if dbType == "" {
		dbType = "sqlite"
	}

	gormLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
		},
	)

	if strings.ToLower(dbType) == "postgres" {
		dsn := os.Getenv("CLAMAI_DATABASE_URL")
		if dsn == "" {
			return fmt.Errorf("postgres requires CLAMAI_DATABASE_URL env var")
		}
		gormDB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
			Logger: gormLogger,
		})
		if err != nil {
			return fmt.Errorf("failed to open postgres: %w", err)
		}
		log.Printf("[INFO] initGormDB: connected to PostgreSQL")
	} else {
		dbPath := filepath.Join(getDataDir(), "clamai.db")
		log.Printf("[INFO] initGormDB: opening SQLite at %s", dbPath)
		gormDB, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{
			Logger: gormLogger,
		})
		if err != nil {
			return fmt.Errorf("failed to open sqlite: %w", err)
		}
		gormDB.Exec("PRAGMA journal_mode=WAL")
		gormDB.Exec("PRAGMA busy_timeout=5000")
	}

	sqlDB, err := gormDB.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(10)

	if err := autoMigrateAll(); err != nil {
		return fmt.Errorf("auto migration failed: %w", err)
	}

	db = sqlDB

	log.Printf("[INFO] initGormDB: database initialized successfully")
	return nil
}

func autoMigrateAll() error {
	return gormDB.AutoMigrate(
		&DBUser{},
		&DBProvider{},
		&DBAPIKey{},
		&DBRequestLog{},
		&DBSecurityAlert{},
		&DBThreatRule{},
		&DBSecurityConfig{},
		&DBRateLimitConfig{},
		&DBSystemSetting{},
		&DBUserSetting{},
		&DBAdminSecret{},
		&DBRefreshToken{},
		&DBModelMapping{},
		&DBProfile{},
		&DBSkillsDetectionHistory{},
		&DBProfileAnalysisHistory{},
		&DBAnalysisTask{},
		&DBAnalysisTaskHistory{},
		&DBSkillsTask{},
		&DBSkillsTaskHistory{},
		&DBSystemAnalysisConfig{},
		&DBSystemAnalysisTask{},
		&DBSystemAnalysisTaskHistory{},
		&DBSystemAnalysisKeyResult{},
		&DBStat{},
		&DBStatByProvider{},
		&DBStatByModel{},
		&DBStatDaily{},
		&DBAdminUser{},
		&DBVectorSample{},
		&DBVectorConfig{},
		&DBAgentEnvCheck{},
		&DBAgentConfigCheck{},
		&DBAgentRuntimeEvent{},
		&DBAuditLog{},
	)
}
