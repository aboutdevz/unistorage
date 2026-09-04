package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aboutdevz/unistorage/pkg/vault"
)

// Exit codes
const (
	ExitSuccess       = 0
	ExitGeneralError  = 1
	ExitNotFound      = 1
	ExitIOError       = 1
	ExitUsageError    = 2
	ExitParamError    = 2
	ExitAuthError     = 3
	ExitConflict      = 5
	ExitDaemonOffline = 6
)

// CLIError wraps an error with a specific CLI exit code.
type CLIError struct {
	Code    int
	Message string
	Err     error
}

func (e *CLIError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// NewCLIError creates a CLIError with an exit code.
func NewCLIError(code int, msg string, err ...error) *CLIError {
	var cause error
	if len(err) > 0 {
		cause = err[0]
	}
	return &CLIError{
		Code:    code,
		Message: msg,
		Err:     cause,
	}
}

// CLIContext contains global flags and configuration resolved for this CLI invocation.
type CLIContext struct {
	ConfigDir       string
	DataDir         string
	DaemonAddr      string
	Token           string
	VaultPassphrase string
	JSON            bool
	Verbose         bool
	Quiet           bool
}

// NewCLIContext initializes configuration from flags, environment variables, and defaults.
func NewCLIContext(flags map[string]string, boolFlags map[string]bool) *CLIContext {
	ctx := &CLIContext{}

	// 1. Config directory
	if cfg, ok := flags["config"]; ok && cfg != "" {
		ctx.ConfigDir = cfg
	} else if envCfg := os.Getenv("UNISTORAGE_CONFIG_DIR"); envCfg != "" {
		ctx.ConfigDir = envCfg
	} else {
		home, _ := os.UserHomeDir()
		ctx.ConfigDir = filepath.Join(home, ".unistorage")
	}

	// 1b. Data directory
	if data, ok := flags["data"]; ok && data != "" {
		ctx.DataDir = data
	} else if envData := os.Getenv("UNISTORAGE_DATA_DIR"); envData != "" {
		ctx.DataDir = envData
	} else {
		home, _ := os.UserHomeDir()
		ctx.DataDir = filepath.Join(home, ".unistorage", "data")
	}

	// 2. Daemon address
	if addr, ok := flags["daemon-addr"]; ok && addr != "" {
		ctx.DaemonAddr = addr
	} else if envAddr := os.Getenv("UNISTORAGE_DAEMON_ADDR"); envAddr != "" {
		ctx.DaemonAddr = envAddr
	} else {
		ctx.DaemonAddr = "http://127.0.0.1:8080"
	}
	if !strings.HasPrefix(ctx.DaemonAddr, "http://") && !strings.HasPrefix(ctx.DaemonAddr, "https://") {
		ctx.DaemonAddr = "http://" + ctx.DaemonAddr
	}

	// 3. Vault passphrase
	if pass, ok := flags["vault-passphrase"]; ok && pass != "" {
		ctx.VaultPassphrase = pass
	} else if envPass := os.Getenv("UNISTORAGE_VAULT_PASSPHRASE"); envPass != "" {
		ctx.VaultPassphrase = envPass
	} else {
		ctx.VaultPassphrase = "unistorage-default-passphrase"
	}

	// 4. Token
	if tok, ok := flags["token"]; ok && tok != "" {
		ctx.Token = tok
	} else if envTok := os.Getenv("UNISTORAGE_TOKEN"); envTok != "" {
		ctx.Token = envTok
	} else {
		tokenFile := filepath.Join(ctx.ConfigDir, "daemon.token")
		if data, err := os.ReadFile(tokenFile); err == nil {
			ctx.Token = strings.TrimSpace(string(data))
		}
	}

	// 5. Output modes
	ctx.JSON = boolFlags["json"]
	ctx.Verbose = boolFlags["verbose"] || boolFlags["v"]
	ctx.Quiet = boolFlags["quiet"] || boolFlags["q"]

	return ctx
}

// VaultPath returns the absolute path to the encrypted vault file.
func (c *CLIContext) VaultPath() string {
	return filepath.Join(c.ConfigDir, "vault.enc")
}

// TokenPath returns the path to daemon.token.
func (c *CLIContext) TokenPath() string {
	return filepath.Join(c.ConfigDir, "daemon.token")
}

// PIDPath returns the path to daemon.pid.
func (c *CLIContext) PIDPath() string {
	return filepath.Join(c.ConfigDir, "daemon.pid")
}

// GetVault instantiates a FileVault pointing to the resolved vault file.
func (c *CLIContext) GetVault() *vault.FileVault {
	return vault.New(c.VaultPath())
}

// PrintJSON marshals data as indented JSON and writes to stdout.
func (c *CLIContext) PrintJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Log prints to stdout if not in quiet mode.
func (c *CLIContext) Log(format string, args ...any) {
	if !c.Quiet {
		fmt.Printf(format+"\n", args...)
	}
}

// Debug prints to stdout if verbose mode is enabled.
func (c *CLIContext) Debug(format string, args ...any) {
	if c.Verbose && !c.Quiet {
		fmt.Printf("[DEBUG] "+format+"\n", args...)
	}
}
