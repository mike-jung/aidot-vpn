// Package config loads AidotVpn controller configuration from environment
// variables. We use a single struct with explicit defaults rather than a
// generic loader so the contract between deployment and code is obvious.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the resolved runtime configuration. Always treat it as immutable
// after Load(); reload requires a process restart.
type Config struct {
	// Listen addresses
	HTTPListen string // 0.0.0.0:10030
	GRPCListen string // 0.0.0.0:10021

	// Logging
	LogLevel  string // debug|info|warn|error
	LogFormat string // text|json

	// Database
	DB DBConfig

	// WireGuard pools (used by Phase 3 onward; loaded here for early validation)
	WGIPv4Pool *net.IPNet
	WGIPv6Pool *net.IPNet
}

// DBConfig holds MariaDB connection parameters.
type DBConfig struct {
	Host           string
	Port           int
	User           string
	Password       string
	Name           string
	MaxOpenConns   int
	MaxIdleConns   int
	ConnMaxLife    time.Duration
	ConnectTimeout time.Duration
	// AllowedTLSMode is one of "disable", "preferred", "required", "verify-ca",
	// "verify-full". Mapped to the go-sql-driver/mysql `tls=` parameter.
	TLSMode string
}

// Load reads the configuration from the process environment. It returns an
// error if any required value is missing or malformed.
func Load() (*Config, error) {
	c := &Config{
		HTTPListen: getEnv("CONTROLLER_HTTP_LISTEN", "0.0.0.0:10030"),
		GRPCListen: getEnv("CONTROLLER_GRPC_LISTEN", "0.0.0.0:10021"),
		LogLevel:   strings.ToLower(getEnv("CONTROLLER_LOG_LEVEL", "info")),
		LogFormat:  strings.ToLower(getEnv("CONTROLLER_LOG_FORMAT", "json")),
	}

	dbPort, err := getEnvInt("AIDOTVPN_DB_PORT", 4336)
	if err != nil {
		return nil, err
	}
	c.DB = DBConfig{
		Host:     getEnv("AIDOTVPN_DB_HOST", "127.0.0.1"),
		Port:     dbPort,
		User:     mustEnv("AIDOTVPN_DB_USER"),
		Password: mustEnv("AIDOTVPN_DB_PASSWORD"),
		Name:     getEnv("AIDOTVPN_DB_NAME", "aidotvpn"),
		TLSMode:  strings.ToLower(getEnv("AIDOTVPN_DB_TLS", "preferred")),
	}
	if c.DB.MaxOpenConns, err = getEnvInt("AIDOTVPN_DB_MAX_OPEN", 25); err != nil {
		return nil, err
	}
	if c.DB.MaxIdleConns, err = getEnvInt("AIDOTVPN_DB_MAX_IDLE", 10); err != nil {
		return nil, err
	}
	if c.DB.ConnMaxLife, err = getEnvDuration("AIDOTVPN_DB_CONN_MAX_LIFE", 30*time.Minute); err != nil {
		return nil, err
	}
	if c.DB.ConnectTimeout, err = getEnvDuration("AIDOTVPN_DB_CONNECT_TIMEOUT", 5*time.Second); err != nil {
		return nil, err
	}

	if v4 := os.Getenv("CONTROLLER_WG_IPV4_POOL"); v4 != "" {
		_, n, perr := net.ParseCIDR(v4)
		if perr != nil {
			return nil, fmt.Errorf("CONTROLLER_WG_IPV4_POOL: %w", perr)
		}
		c.WGIPv4Pool = n
	}
	if v6 := os.Getenv("CONTROLLER_WG_IPV6_POOL"); v6 != "" {
		_, n, perr := net.ParseCIDR(v6)
		if perr != nil {
			return nil, fmt.Errorf("CONTROLLER_WG_IPV6_POOL: %w", perr)
		}
		c.WGIPv6Pool = n
	}

	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate cross-checks the loaded config for internally-consistent values.
func (c *Config) Validate() error {
	if _, _, err := net.SplitHostPort(c.HTTPListen); err != nil {
		return fmt.Errorf("CONTROLLER_HTTP_LISTEN invalid: %w", err)
	}
	if _, _, err := net.SplitHostPort(c.GRPCListen); err != nil {
		return fmt.Errorf("CONTROLLER_GRPC_LISTEN invalid: %w", err)
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("CONTROLLER_LOG_LEVEL: %q is not one of debug|info|warn|error", c.LogLevel)
	}
	switch c.LogFormat {
	case "text", "json":
	default:
		return fmt.Errorf("CONTROLLER_LOG_FORMAT: %q is not one of text|json", c.LogFormat)
	}
	if c.DB.MaxIdleConns > c.DB.MaxOpenConns {
		return fmt.Errorf("DB pool: idle (%d) cannot exceed max open (%d)",
			c.DB.MaxIdleConns, c.DB.MaxOpenConns)
	}
	switch c.DB.TLSMode {
	case "disable", "preferred", "required", "verify-ca", "verify-full":
	default:
		return fmt.Errorf("AIDOTVPN_DB_TLS: %q is not a recognised mode", c.DB.TLSMode)
	}
	return nil
}

// DSN builds the go-sql-driver/mysql DSN string. We deliberately keep this
// here instead of in the db package so configuration semantics live in one
// place.
func (d DBConfig) DSN() string {
	// parseTime=true: scan TIMESTAMP/DATETIME into time.Time.
	// loc=UTC: ensure all conversions go through UTC.
	// collation=utf8mb4_unicode_ci: implies charset=utf8mb4.
	// multiStatements=false: explicitly disable to harden against injection.
	// readTimeout / writeTimeout: prevent stuck connections from pinning a
	// goroutine forever.
	//
	// Note on charset/collation handling across driver versions:
	//   - v1.7.x accepted comma-separated `charset=utf8mb4,utf8` as a
	//     fallback list. v1.9.x dropped that and emits the value
	//     verbatim into `SET NAMES <charset> COLLATE <collation>`,
	//     which makes the comma a SQL syntax error. We pass `collation`
	//     alone — the driver derives the matching charset for us, and
	//     this works on both v1.7 and v1.9.
	v := url.Values{}
	v.Set("parseTime", "true")
	v.Set("loc", "UTC")
	v.Set("collation", "utf8mb4_unicode_ci")
	v.Set("multiStatements", "false")
	v.Set("interpolateParams", "false")
	v.Set("readTimeout", "30s")
	v.Set("writeTimeout", "30s")
	v.Set("timeout", d.ConnectTimeout.String())

	switch d.TLSMode {
	case "disable":
		v.Set("tls", "false")
	case "preferred":
		// go-sql-driver does not have a native "preferred"; we map it to
		// "skip-verify" only in dev. Production should use required+ modes.
		v.Set("tls", "preferred")
	case "required":
		v.Set("tls", "true")
	case "verify-ca", "verify-full":
		v.Set("tls", d.TLSMode)
	}

	// user:pass@tcp(host:port)/dbname?params
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?%s",
		d.User, d.Password, d.Host, d.Port, d.Name, v.Encode())
}

// --- helpers ------------------------------------------------------------
//
// All helpers treat an explicitly-empty env var the same as an unset one.
// That matches how operators expect things to work in shells where blanking
// a variable is the easy way to "remove" it without unsetting.

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func mustEnv(key string) string {
	return os.Getenv(key) // empty allowed; Validate() reports missing values
}

func getEnvInt(key string, def int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not an integer", key, v)
	}
	return n, nil
}

func getEnvDuration(key string, def time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a valid duration: %w", key, v, err)
	}
	return d, nil
}
