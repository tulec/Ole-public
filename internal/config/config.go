package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	HTTPPort                string
	HTTPTrustedProxies      string
	STUNListenAddr          string
	RelayListenAddr         string
	RelayQuotaWindow        time.Duration
	RelayQuotaPackets       int
	RelayQuotaBytes         int64
	RelayAbuseWindow        time.Duration
	RelayAbuseThreshold     int
	RelayAbuseBlockDuration time.Duration
	PeerHeartbeatTTL        time.Duration
	DatabaseURL             string
	AutoMigrate             bool
	CleanupInterval         time.Duration
	MigrationsDir           string
	JWTSecret               string
	JWTIssuer               string
	ServerVersion           string
	MinClientVersion        string
}

func Load() Config {
	loadDotEnv()

	return Config{
		HTTPPort:                getEnv("OLE_HTTP_PORT", ":8080"),
		HTTPTrustedProxies:      getEnv("OLE_HTTP_TRUSTED_PROXIES", ""),
		STUNListenAddr:          getEnv("OLE_STUN_LISTEN_ADDR", ":3478"),
		RelayListenAddr:         getEnv("OLE_RELAY_LISTEN_ADDR", ":3479"),
		RelayQuotaWindow:        getEnvDuration("OLE_RELAY_QUOTA_WINDOW", 0),
		RelayQuotaPackets:       getEnvInt("OLE_RELAY_QUOTA_PACKETS", 0),
		RelayQuotaBytes:         getEnvInt64("OLE_RELAY_QUOTA_BYTES", 0),
		RelayAbuseWindow:        getEnvDuration("OLE_RELAY_ABUSE_WINDOW", 1*time.Minute),
		RelayAbuseThreshold:     getEnvInt("OLE_RELAY_ABUSE_THRESHOLD", 3),
		RelayAbuseBlockDuration: getEnvDuration("OLE_RELAY_ABUSE_BLOCK_DURATION", 5*time.Minute),
		PeerHeartbeatTTL:        getEnvDuration("OLE_PEER_HEARTBEAT_TTL", 2*time.Minute),
		DatabaseURL:             getEnv("OLE_DATABASE_URL", "postgres://postgres:postgres@localhost:5432/ole?sslmode=disable"),
		AutoMigrate:             getEnv("OLE_AUTO_MIGRATE", "true") == "true",
		CleanupInterval:         getEnvDuration("OLE_CLEANUP_INTERVAL", 5*time.Minute),
		MigrationsDir:           getEnv("OLE_MIGRATIONS_DIR", "internal/store/postgres/migrations"),
		JWTSecret:               getEnv("OLE_JWT_SECRET", ""),
		JWTIssuer:               getEnv("OLE_JWT_ISSUER", "ole-server"),
		ServerVersion:           getEnv("OLE_SERVER_VERSION", "0.1.0"),
		MinClientVersion:        getEnv("OLE_MIN_CLIENT_VERSION", "0.1.0"),
	}
}

// ValidateServer must run before opening the database or any listeners.
// Migration commands only use Load and do not require a signing secret.
func (c Config) ValidateServer() error {
	secret := strings.TrimSpace(c.JWTSecret)
	if secret == "" {
		return errors.New("OLE_JWT_SECRET is required")
	}
	if strings.EqualFold(secret, "ole-dev-secret-change-me") {
		return errors.New("OLE_JWT_SECRET must not use the built-in development value")
	}
	if len(secret) < 32 {
		return errors.New("OLE_JWT_SECRET must contain at least 32 bytes; generate a random secret")
	}
	return nil
}

func loadDotEnv() {
	// Load only fills unset variables, so process values (even empty ones)
	// win over .env.local, which in turn wins over .env.
	paths := []string{".env.local", ".env"}
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			_ = godotenv.Load(path)
		}
	}
}

func getEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getEnvInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getEnvInt64(key string, fallback int64) int64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}
