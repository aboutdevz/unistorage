package main

import (
	"context"
	"fmt"
	"os"
	"strings"
)

const AppVersion = "0.1.0"

var knownValueFlags = map[string]bool{
	"config":           true,
	"data":             true,
	"daemon-addr":      true,
	"token":            true,
	"vault-passphrase": true,
	"type":             true,
	"path":             true,
	"endpoint":         true,
	"bucket":           true,
	"access-key":       true,
	"secret-key":       true,
	"region":           true,
	"port":             true,
	"addr":             true,
	"conflict-dir":     true,
	"workers":          true,
	"exclude":          true,
	"include":          true,
	"buffer-size":      true,
	"concurrency":      true,
}

var knownBoolFlags = map[string]bool{
	"json":               true,
	"verbose":            true,
	"v":                  true,
	"quiet":              true,
	"q":                  true,
	"help":               true,
	"h":                  true,
	"version":            true,
	"use-path-style":     true,
	"r":                  true,
	"recursive":          true,
	"l":                  true,
	"long":               true,
	"H":                  true,
	"human-readable":     true,
	"f":                  true,
	"force":              true,
	"p":                  true,
	"progress":           true,
	"checksum":           true,
	"delete":             true,
	"dry-run":            true,
	"n":                  true,
	"no-conflict-backup": true,
	"foreground":         true,
}

func parseArgs(rawArgs []string) (positional []string, flags map[string]string, boolFlags map[string]bool, err error) {
	flags = make(map[string]string)
	boolFlags = make(map[string]bool)

	for i := 0; i < len(rawArgs); i++ {
		arg := rawArgs[i]

		if strings.HasPrefix(arg, "--") {
			name := strings.TrimPrefix(arg, "--")
			var val string
			hasVal := false

			if idx := strings.Index(name, "="); idx != -1 {
				val = name[idx+1:]
				name = name[:idx]
				hasVal = true
			}

			if knownValueFlags[name] {
				if hasVal {
					flags[name] = val
				} else if i+1 < len(rawArgs) && !strings.HasPrefix(rawArgs[i+1], "-") {
					flags[name] = rawArgs[i+1]
					i++
				} else {
					return nil, nil, nil, fmt.Errorf("flag --%s requires a value", name)
				}
				continue
			}

			if knownBoolFlags[name] {
				boolFlags[name] = true
				continue
			}

			// Unknown flag
			return nil, nil, nil, fmt.Errorf("unknown flag --%s", name)
		}

		if strings.HasPrefix(arg, "-") && len(arg) > 1 {
			short := arg[1:]
			if knownBoolFlags[short] {
				boolFlags[short] = true
				continue
			}
			if knownValueFlags[short] {
				if i+1 < len(rawArgs) && !strings.HasPrefix(rawArgs[i+1], "-") {
					flags[short] = rawArgs[i+1]
					i++
				} else {
					return nil, nil, nil, fmt.Errorf("flag -%s requires a value", short)
				}
				continue
			}
			// Check multi-char short flags like -rf or -lh
			allValid := true
			for _, r := range short {
				s := string(r)
				if knownBoolFlags[s] {
					boolFlags[s] = true
				} else {
					allValid = false
					break
				}
			}
			if allValid {
				continue
			}
			return nil, nil, nil, fmt.Errorf("unknown flag -%s", short)
		}

		positional = append(positional, arg)
	}

	return positional, flags, boolFlags, nil
}

func printHelp() {
	fmt.Println(`UniStorage - Resilient Unified Storage CLI & Core Engine

Usage:
  unistorage [command] [flags]

Available Commands:
  remote add <name> [type] [flags]   Register encrypted storage remote profile in vault
  remote list [--json]               List configured remote profiles
  remote remove <name> [-f]          Delete remote profile from vault
  ls <target> [flags]                List objects or directory contents (-r, -l, -H, --json)
  cp <src> <dest> [flags]            Copy files/directories with constant-memory streaming (-r, -f)
  sync <src> <dest> [flags]          Unidirectional sync with conflict safety backup (--checksum, --delete, --dry-run)
  rm <target> [flags]                Remove files or directory trees (-r, -f, --dry-run)
  daemon start [flags]               Start loopback background daemon (--port, --addr, --foreground)
  daemon status [--json]             Check daemon process status and probe health API
  daemon stop                        Stop running background daemon

Global Flags:
  --config <path>                    Base directory for vault and tokens (default: ~/.unistorage)
  --daemon-addr <url>                Local daemon URL (default: http://127.0.0.1:8080)
  --token <token>                    Bearer auth token override
  --vault-passphrase <pass>          Vault encryption passphrase
  --json                             Format output as structured JSON
  --verbose, -v                      Enable debug-level logging
  --quiet, -q                        Suppress informational messages
  --help, -h                         Show help for unistorage
  --version                          Show unistorage version`)
}

func printRemoteHelp() {
	fmt.Println(`UniStorage Remote Management

Usage:
  unistorage remote <command> [flags]

Available Commands:
  add <name> <type> [flags]   Register encrypted storage remote profile (types: local, s3)
  list [--json]               List configured remote profiles
  remove <name> [-f]          Delete remote profile from vault

Flags:
  --path <path>               Local filesystem root path (required for type 'local')
  --endpoint <url>            S3 endpoint URL (required for type 's3')
  --bucket <bucket>           S3 bucket name (required for type 's3')
  --region <region>           S3 region (default: us-east-1)
  --access-key <key>          S3 access key
  --secret-key <key>          S3 secret key
  --use-path-style            Force path-style S3 URLs (for MinIO)
  --json                      Output formatted JSON (for list)
  -f, --force                 Force remove without confirmation`)
}

func printLsHelp() {
	fmt.Println(`UniStorage List Objects

Usage:
  unistorage ls <remote:path|local_path> [flags]

Flags:
  -r, --recursive             List objects and directories recursively
  -l, --long                  Use long listing format with sizes and timestamps
  -H, -h, --human-readable    Print human readable file sizes (e.g. 1K, 234M, 2G)
  --json                      Format output as JSON array`)
}

func printCpHelp() {
	fmt.Println(`UniStorage Copy Files

Usage:
  unistorage cp <src> <dest> [flags]

Flags:
  -r, --recursive             Copy directories recursively
  -f, --force                 Overwrite existing files without prompting`)
}

func printSyncHelp() {
	fmt.Println(`UniStorage Resilient Sync

Usage:
  unistorage sync <src> <dest> [flags]

Flags:
  --checksum                  Verify file integrity via SHA-256 instead of size/modtime
  --delete                    Delete extraneous files from destination
  --dry-run, -n               Perform trial run with no changes made
  --conflict-dir <dir>        Directory for conflict safety backups (default: .conflicts)
  --no-conflict-backup        Disable saving conflicting files to .conflicts/
  --workers <int>             Number of parallel sync workers (default: 4)
  --json                      Format summary output as JSON`)
}

func printRmHelp() {
	fmt.Println(`UniStorage Remove Files

Usage:
  unistorage rm <target> [flags]

Flags:
  -r, --recursive             Remove directories and their contents recursively
  -f, --force                 Ignore nonexistent files and arguments, never prompt
  --dry-run, -n               Simulate removal without actually deleting`)
}

func printDaemonHelp() {
	fmt.Println(`UniStorage Background Daemon Management

Usage:
  unistorage daemon <start|status|stop> [flags]

Available Commands:
  start [flags]               Start loopback background daemon
  status [--json]             Check daemon process status and probe health API
  stop                        Stop running background daemon

Flags:
  --port <port>               Port to listen on (default: 8080)
  --addr <addr>               Address to listen on (default: 127.0.0.1)
  --foreground                Run daemon in foreground
  --json                      Format status output as JSON`)
}

func printSubcommandHelp(subcmd string) bool {
	switch subcmd {
	case "remote":
		printRemoteHelp()
		return true
	case "ls":
		printLsHelp()
		return true
	case "cp":
		printCpHelp()
		return true
	case "sync":
		printSyncHelp()
		return true
	case "rm":
		printRmHelp()
		return true
	case "daemon":
		printDaemonHelp()
		return true
	default:
		return false
	}
}

func runMain() int {
	positional, flags, boolFlags, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return ExitParamError
	}

	if boolFlags["version"] {
		fmt.Printf("unistorage version %s\n", AppVersion)
		return ExitSuccess
	}

	// 1. Handle no arguments -> show general help
	if len(positional) == 0 {
		printHelp()
		return ExitSuccess
	}

	// 2. Handle top-level "unistorage help [subcommand]"
	if positional[0] == "help" {
		if len(positional) > 1 {
			if printSubcommandHelp(positional[1]) {
				return ExitSuccess
			}
		}
		printHelp()
		return ExitSuccess
	}

	cmd := positional[0]
	cmdArgs := positional[1:]

	// 3. Handle subcommand help: "unistorage <subcommand> --help" or "unistorage <subcommand> help"
	if boolFlags["help"] || boolFlags["h"] || (len(cmdArgs) > 0 && cmdArgs[0] == "help") {
		if printSubcommandHelp(cmd) {
			return ExitSuccess
		}
		printHelp()
		return ExitSuccess
	}

	cliCtx := NewCLIContext(flags, boolFlags)
	ctx := context.Background()

	var execErr error

	switch cmd {
	case "remote":
		execErr = RunRemote(cliCtx, cmdArgs, flags, boolFlags)
	case "ls":
		execErr = RunLs(ctx, cliCtx, cmdArgs, flags, boolFlags)
	case "cp":
		execErr = RunCp(ctx, cliCtx, cmdArgs, flags, boolFlags)
	case "sync":
		execErr = RunSync(ctx, cliCtx, cmdArgs, flags, boolFlags)
	case "rm":
		execErr = RunRm(ctx, cliCtx, cmdArgs, flags, boolFlags)
	case "daemon":
		execErr = RunDaemon(cliCtx, cmdArgs, flags, boolFlags)
	case "version":
		fmt.Printf("unistorage version %s\n", AppVersion)
		return ExitSuccess
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command %q. Run 'unistorage --help' for usage.\n", cmd)
		return ExitParamError
	}

	if execErr != nil {
		if cliErr, ok := execErr.(*CLIError); ok {
			fmt.Fprintf(os.Stderr, "Error: %s\n", cliErr.Error())
			return cliErr.Code
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", execErr)
		return ExitGeneralError
	}

	return ExitSuccess
}

func main() {
	os.Exit(runMain())
}
