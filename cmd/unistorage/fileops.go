package main

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/aboutdevz/unistorage/pkg/storage"
	synce "github.com/aboutdevz/unistorage/pkg/sync"
)

// RunLs handles "unistorage ls <target>".
func RunLs(ctx context.Context, cliCtx *CLIContext, args []string, flags map[string]string, boolFlags map[string]bool) error {
	if len(args) < 1 {
		return NewCLIError(ExitParamError, "usage: unistorage ls <remote:path|local_path> [flags]")
	}

	targetStr := args[0]
	endpoint, err := ResolveTarget(ctx, cliCtx, targetStr, false, false)
	if err != nil {
		return err
	}

	recursive := boolFlags["r"] || boolFlags["recursive"]
	longFormat := boolFlags["l"] || boolFlags["long"]
	humanReadable := boolFlags["H"] || boolFlags["human-readable"]
	jsonOutput := cliCtx.JSON || boolFlags["json"]

	// Case 1: Target is an existing single file
	if endpoint.IsFile {
		info, err := endpoint.Driver.Stat(ctx, endpoint.Prefix)
		if err != nil {
			return NewCLIError(ExitNotFound, fmt.Sprintf("cannot stat %q", endpoint.Prefix), err)
		}

		if jsonOutput {
			return cliCtx.PrintJSON([]*storage.ObjectInfo{info})
		}
		if longFormat {
			printObjectLong(info, humanReadable)
		} else {
			fmt.Println(info.Key)
		}
		return nil
	}

	// Case 2: Target is a directory or remote prefix
	var objects []storage.ObjectInfo
	if adv, ok := endpoint.Driver.(storage.AdvancedDriver); ok {
		res, lErr := adv.ListWithOptions(ctx, storage.ListOptions{
			Prefix:    endpoint.Prefix,
			Recursive: recursive,
		})
		if lErr == nil && res != nil {
			objects = res.Objects
		}
	}
	if objects == nil {
		var lErr error
		objects, lErr = endpoint.Driver.List(ctx, endpoint.Prefix)
		if lErr != nil {
			return NewCLIError(ExitIOError, fmt.Sprintf("failed to list %q", targetStr), lErr)
		}
	}

	if objects == nil {
		objects = make([]storage.ObjectInfo, 0)
	}

	if jsonOutput {
		return cliCtx.PrintJSON(objects)
	}

	for _, obj := range objects {
		if !recursive && endpoint.Prefix != "" && !strings.HasPrefix(obj.Path, endpoint.Prefix) {
			continue
		}
		if longFormat {
			printObjectLong(&obj, humanReadable)
		} else {
			displayName := obj.Key
			if displayName == "" {
				displayName = obj.Path
			}
			if obj.IsDir && !strings.HasSuffix(displayName, "/") {
				displayName += "/"
			}
			fmt.Println(displayName)
		}
	}

	return nil
}

func printObjectLong(obj *storage.ObjectInfo, human bool) {
	mode := "-rw-r--r--"
	if obj.IsDir {
		mode = "drwxr-xr-x"
	}
	sizeStr := fmt.Sprintf("%10d", obj.Size)
	if human {
		if obj.IsDir {
			sizeStr = "         -"
		} else {
			sizeStr = fmt.Sprintf("%10s", synce.FormatBytes(obj.Size))
		}
	}
	timeStr := obj.ModTime.UTC().Format("2006-01-02 15:04:05 UTC")
	name := obj.Key
	if name == "" {
		name = obj.Path
	}
	if obj.IsDir && !strings.HasSuffix(name, "/") {
		name += "/"
	}
	fmt.Printf("%s   %s   %s   %s\n", mode, sizeStr, timeStr, name)
}

// RunCp handles "unistorage cp <src> <dest>".
func RunCp(ctx context.Context, cliCtx *CLIContext, args []string, flags map[string]string, boolFlags map[string]bool) error {
	if len(args) < 2 {
		return NewCLIError(ExitParamError, "usage: unistorage cp <src> <dest> [-r] [-f]")
	}

	srcStr := args[0]
	destStr := args[1]
	recursive := boolFlags["r"] || boolFlags["recursive"]

	srcEp, err := ResolveTarget(ctx, cliCtx, srcStr, false, false)
	if err != nil {
		return err
	}

	destEp, err := ResolveTarget(ctx, cliCtx, destStr, true, recursive || srcEp.IsDir)
	if err != nil {
		return err
	}

	if recursive || srcEp.IsDir {
		// Recursive copy: list all objects under source prefix and stream to destination
		objects, err := srcEp.Driver.List(ctx, srcEp.Prefix)
		if err != nil {
			return NewCLIError(ExitIOError, fmt.Sprintf("failed to list source %q", srcStr), err)
		}

		cleanSrcPrefix := strings.Trim(strings.ReplaceAll(srcEp.Prefix, "\\", "/"), "/")
		cleanDestPrefix := strings.Trim(strings.ReplaceAll(destEp.Prefix, "\\", "/"), "/")

		transferred := 0
		for _, obj := range objects {
			if obj.IsDir {
				continue
			}
			rel := obj.Path
			if cleanSrcPrefix != "" && strings.HasPrefix(rel, cleanSrcPrefix) {
				rel = strings.TrimPrefix(rel, cleanSrcPrefix)
				rel = strings.TrimPrefix(rel, "/")
			}

			destPath := rel
			if cleanDestPrefix != "" {
				destPath = cleanDestPrefix + "/" + rel
			}

			rc, err := srcEp.Driver.Read(ctx, obj.Path)
			if err != nil {
				return NewCLIError(ExitIOError, fmt.Sprintf("failed to read %q", obj.Path), err)
			}
			wErr := destEp.Driver.Write(ctx, destPath, rc, obj.Size)
			_ = rc.Close()
			if wErr != nil {
				return NewCLIError(ExitIOError, fmt.Sprintf("failed to write %q", destPath), wErr)
			}
			transferred++
		}
		cliCtx.Log("Copied %d files from %s to %s", transferred, srcStr, destStr)
		return nil
	}

	// Single file copy
	statInfo, err := srcEp.Driver.Stat(ctx, srcEp.Prefix)
	if err != nil {
		return NewCLIError(ExitNotFound, fmt.Sprintf("source file %q not found", srcEp.Prefix), err)
	}

	rc, err := srcEp.Driver.Read(ctx, srcEp.Prefix)
	if err != nil {
		return NewCLIError(ExitIOError, fmt.Sprintf("failed to open source %q", srcEp.Prefix), err)
	}
	defer rc.Close()

	destPath := destEp.Prefix
	if destEp.IsDir || destPath == "" {
		destPath = filepath.Base(srcEp.Prefix)
	}

	bufPtr := storage.BufferPool.Get().(*[]byte)
	defer storage.BufferPool.Put(bufPtr)

	// Stream via constant memory
	pr, pw := io.Pipe()
	go func() {
		_, copyErr := io.CopyBuffer(pw, rc, *bufPtr)
		if copyErr != nil {
			_ = pw.CloseWithError(copyErr)
		} else {
			_ = pw.Close()
		}
	}()

	if err := destEp.Driver.Write(ctx, destPath, pr, statInfo.Size); err != nil {
		return NewCLIError(ExitIOError, fmt.Sprintf("failed to write destination %q", destPath), err)
	}

	cliCtx.Log("Copied %s -> %s (%s)", srcStr, destStr, synce.FormatBytes(statInfo.Size))
	return nil
}

// RunRm handles "unistorage rm <target> [-r] [-f]".
func RunRm(ctx context.Context, cliCtx *CLIContext, args []string, flags map[string]string, boolFlags map[string]bool) error {
	if len(args) < 1 {
		return NewCLIError(ExitParamError, "usage: unistorage rm <target> [-r] [-f]")
	}

	targetStr := args[0]
	endpoint, err := ResolveTarget(ctx, cliCtx, targetStr, false, false)
	if err != nil {
		return err
	}

	dryRun := boolFlags["dry-run"] || boolFlags["n"]
	if dryRun {
		cliCtx.Log("(dry-run) Removed '%s'.", targetStr)
		return nil
	}

	recursive := boolFlags["r"] || boolFlags["recursive"]

	if recursive || endpoint.IsDir {
		objects, err := endpoint.Driver.List(ctx, endpoint.Prefix)
		if err != nil {
			return NewCLIError(ExitIOError, fmt.Sprintf("failed to list objects for removal in %q", targetStr), err)
		}
		for _, obj := range objects {
			if !obj.IsDir {
				_ = endpoint.Driver.Delete(ctx, obj.Path)
			}
		}
		_ = endpoint.Driver.Delete(ctx, endpoint.Prefix)
		cliCtx.Log("Removed '%s'.", targetStr)
		return nil
	}

	if err := endpoint.Driver.Delete(ctx, endpoint.Prefix); err != nil {
		return NewCLIError(ExitIOError, fmt.Sprintf("failed to remove %q", targetStr), err)
	}

	cliCtx.Log("Removed '%s'.", targetStr)
	return nil
}
