package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aboutdevz/unistorage/internal/daemon"
)

// RunDaemon handles subcommands under "unistorage daemon ...".
func RunDaemon(cliCtx *CLIContext, args []string, flags map[string]string, boolFlags map[string]bool) error {
	if boolFlags["help"] || boolFlags["h"] || (len(args) > 0 && args[0] == "help") {
		printDaemonHelp()
		return nil
	}
	if len(args) == 0 {
		return NewCLIError(ExitParamError, "usage: unistorage daemon <start|status|stop> [flags]")
	}

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "start":
		return runDaemonStart(cliCtx, subargs, flags, boolFlags)
	case "status":
		return runDaemonStatus(cliCtx, subargs, flags, boolFlags)
	case "stop":
		return runDaemonStop(cliCtx, subargs, flags, boolFlags)
	default:
		return NewCLIError(ExitParamError, fmt.Sprintf("unknown daemon subcommand %q (valid: start, status, stop)", subcmd))
	}
}

func runDaemonStart(cliCtx *CLIContext, args []string, flags map[string]string, boolFlags map[string]bool) error {
	port := "8080"
	if p, ok := flags["port"]; ok && p != "" {
		port = p
	} else if envP := os.Getenv("UNISTORAGE_DAEMON_PORT"); envP != "" {
		port = envP
	}
	addr := "127.0.0.1"
	if a, ok := flags["addr"]; ok && a != "" {
		addr = a
	} else if envA := os.Getenv("UNISTORAGE_DAEMON_ADDR"); envA != "" {
		addr = envA
	}

	listenAddr := net.JoinHostPort(addr, port)
	foreground := boolFlags["foreground"] || boolFlags["f"]

	if foreground {
		// Run in foreground
		if err := os.MkdirAll(cliCtx.ConfigDir, 0700); err != nil {
			return NewCLIError(ExitIOError, "failed to create config dir", err)
		}
		if cliCtx.DataDir != "" {
			if err := os.MkdirAll(cliCtx.DataDir, 0750); err != nil {
				return NewCLIError(ExitIOError, "failed to create data dir", err)
			}
		}

		pid := os.Getpid()
		if err := os.WriteFile(cliCtx.PIDPath(), []byte(strconv.Itoa(pid)+"\n"), 0600); err != nil {
			return NewCLIError(ExitIOError, "failed to write PID file", err)
		}
		defer func() { _ = os.Remove(cliCtx.PIDPath()) }()

		server, err := daemon.New(daemon.Config{
			Addr:            listenAddr,
			TokenFile:       cliCtx.TokenPath(),
			VaultPath:       cliCtx.VaultPath(),
			VaultPassphrase: cliCtx.VaultPassphrase,
			Version:         Version,
		})
		if err != nil {
			return NewCLIError(ExitIOError, "failed to initialize daemon server", err)
		}

		cliCtx.Log("Daemon started in foreground on %s (PID %d)", listenAddr, pid)
		if err := server.Start(); err != nil && err != http.ErrServerClosed {
			return NewCLIError(ExitIOError, "daemon runtime error", err)
		}
		return nil
	}

	// Detached background execution
	selfExe, err := os.Executable()
	if err != nil {
		return NewCLIError(ExitIOError, "cannot determine executable path", err)
	}

	cmdArgs := []string{
		"daemon", "start",
		"--foreground",
		"--port", port,
		"--addr", addr,
		"--config", cliCtx.ConfigDir,
		"--data", cliCtx.DataDir,
		"--vault-passphrase", cliCtx.VaultPassphrase,
	}

	// #nosec G204, G702 -- launching self executable with controlled arguments
	cmd := exec.Command(selfExe, cmdArgs...)
	cmd.Dir = cliCtx.ConfigDir
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	configureDetachedProcess(cmd.SysProcAttr)

	if err := cmd.Start(); err != nil {
		return NewCLIError(ExitIOError, "failed to spawn background daemon", err)
	}

	// Wait briefly for PID and health
	pid := cmd.Process.Pid
	if err := os.MkdirAll(cliCtx.ConfigDir, 0700); err != nil {
		return NewCLIError(ExitIOError, "failed to create config dir", err)
	}
	// #nosec G304, G703 -- PID file written inside trusted config dir with 0600 permissions
	if err := os.WriteFile(cliCtx.PIDPath(), []byte(strconv.Itoa(pid)+"\n"), 0600); err != nil {
		return NewCLIError(ExitIOError, "failed to write PID file", err)
	}

	cliCtx.Log("Daemon started on %s (PID %d)", listenAddr, pid)
	return nil
}

func runDaemonStatus(cliCtx *CLIContext, args []string, flags map[string]string, boolFlags map[string]bool) error {
	jsonOutput := cliCtx.JSON || boolFlags["json"]

	pidData, err := os.ReadFile(cliCtx.PIDPath())
	if err != nil {
		if jsonOutput {
			return cliCtx.PrintJSON(map[string]any{"status": "offline"})
		}
		cliCtx.Log("Daemon is offline.")
		return nil
	}

	pidStr := strings.TrimSpace(string(pidData))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		if jsonOutput {
			return cliCtx.PrintJSON(map[string]any{"status": "offline"})
		}
		cliCtx.Log("Daemon is offline (invalid PID file).")
		return nil
	}

	// Probe health endpoint
	client := &http.Client{Timeout: 3 * time.Second}
	healthURL := fmt.Sprintf("%s/api/v1/health", cliCtx.DaemonAddr)
	req, err := http.NewRequest(http.MethodGet, healthURL, http.NoBody)
	if err != nil {
		if jsonOutput {
			return cliCtx.PrintJSON(map[string]any{"status": "offline"})
		}
		cliCtx.Log("Daemon is offline.")
		return nil
	}

	daemonVersion := Version
	resp, hErr := client.Do(req)
	isOnline := hErr == nil && resp.StatusCode == http.StatusOK
	if resp != nil {
		var healthResp struct {
			Status  string `json:"status"`
			Version string `json:"version"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&healthResp); err == nil && healthResp.Version != "" {
			daemonVersion = healthResp.Version
		}
		_ = resp.Body.Close()
	}

	if !isOnline {
		// Try loopback fallback 127.0.0.1:8080 or 8081
		healthURL2 := "http://127.0.0.1:8080/api/v1/health"
		if req2, err := http.NewRequest(http.MethodGet, healthURL2, http.NoBody); err == nil {
			if resp2, err := client.Do(req2); err == nil && resp2.StatusCode == http.StatusOK {
				isOnline = true
				var healthResp struct {
					Status  string `json:"status"`
					Version string `json:"version"`
				}
				if err := json.NewDecoder(resp2.Body).Decode(&healthResp); err == nil && healthResp.Version != "" {
					daemonVersion = healthResp.Version
				}
				_ = resp2.Body.Close()
			}
		}
	}

	statusMap := map[string]any{
		"status":  "running",
		"pid":     pid,
		"addr":    cliCtx.DaemonAddr,
		"version": daemonVersion,
	}
	if !isOnline {
		statusMap["status"] = "offline"
	}

	if jsonOutput {
		return cliCtx.PrintJSON(statusMap)
	}

	if isOnline {
		fmt.Printf("Daemon Status: RUNNING\n  PID:     %d\n  Address: %s\n  Version: %s\n", pid, cliCtx.DaemonAddr, daemonVersion)
	} else {
		fmt.Printf("Daemon Status: OFFLINE (PID %d not responding)\n", pid)
	}

	return nil
}

func runDaemonStop(cliCtx *CLIContext, args []string, flags map[string]string, boolFlags map[string]bool) error {
	pidData, err := os.ReadFile(cliCtx.PIDPath())
	if err != nil {
		cliCtx.Log("Daemon is not running.")
		return nil
	}

	pidStr := strings.TrimSpace(string(pidData))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		_ = os.Remove(cliCtx.PIDPath())
		cliCtx.Log("Daemon stopped.")
		return nil
	}

	proc, err := os.FindProcess(pid)
	if err == nil && proc != nil {
		if kErr := proc.Kill(); kErr != nil {
			cliCtx.Debug("process kill error: %v", kErr)
		}
		// Wait up to 3 seconds
		for i := 0; i < 30; i++ {
			time.Sleep(100 * time.Millisecond)
		}
	}

	_ = os.Remove(cliCtx.PIDPath())
	cliCtx.Log("Daemon stopped.")
	return nil
}
