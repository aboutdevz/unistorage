package main

import (
	"context"
	"fmt"
	"strconv"

	synce "github.com/aboutdevz/unistorage/pkg/sync"
)

// RunSync handles "unistorage sync <src> <dest> [flags]".
func RunSync(ctx context.Context, cliCtx *CLIContext, args []string, flags map[string]string, boolFlags map[string]bool) error {
	if len(args) < 2 {
		return NewCLIError(ExitParamError, "usage: unistorage sync <src> <dest> [--checksum] [--delete] [--dry-run] [--conflict-dir <dir>] [--no-conflict-backup] [--workers <int>]")
	}

	srcStr := args[0]
	destStr := args[1]

	srcEp, err := ResolveTarget(ctx, cliCtx, srcStr, false, true)
	if err != nil {
		return err
	}

	destEp, err := ResolveTarget(ctx, cliCtx, destStr, true, true)
	if err != nil {
		return err
	}

	workers := 4
	if wStr, ok := flags["workers"]; ok && wStr != "" {
		if w, err := strconv.Atoi(wStr); err == nil && w > 0 {
			workers = w
		}
	}

	opts := synce.SyncOptions{
		Checksum:         boolFlags["checksum"],
		Delete:           boolFlags["delete"],
		DryRun:           boolFlags["dry-run"] || boolFlags["n"],
		ConflictDir:      flags["conflict-dir"],
		NoConflictBackup: boolFlags["no-conflict-backup"],
		Workers:          workers,
	}

	stats, err := synce.Sync(ctx, srcEp.Driver, srcEp.Prefix, destEp.Driver, destEp.Prefix, opts)
	if err != nil {
		if err == synce.ErrRecursiveSync {
			return NewCLIError(ExitParamError, "recursive sync loop detected", err)
		}
		return NewCLIError(ExitIOError, "sync execution failed", err)
	}

	stats.Source = srcStr
	stats.Destination = destStr

	if cliCtx.JSON || boolFlags["json"] {
		return cliCtx.PrintJSON(stats)
	}

	fmt.Print(stats.SummaryString())
	return nil
}
