package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseArgs(t *testing.T) {
	t.Run("FlagBeforeAndAfter", func(t *testing.T) {
		raw := []string{"--json", "remote", "list"}
		pos, flags, boolFlags, err := parseArgs(raw)
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if !boolFlags["json"] {
			t.Errorf("expected json bool flag")
		}
		if len(pos) != 2 || pos[0] != "remote" || pos[1] != "list" {
			t.Errorf("unexpected positional args: %v", pos)
		}
		_ = flags
	})

	t.Run("ValueFlagsWithEquals", func(t *testing.T) {
		raw := []string{"daemon", "start", "--port=8085", "--addr=127.0.0.1"}
		pos, flags, _, err := parseArgs(raw)
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if flags["port"] != "8085" {
			t.Errorf("expected port=8085, got %q", flags["port"])
		}
		if flags["addr"] != "127.0.0.1" {
			t.Errorf("expected addr=127.0.0.1, got %q", flags["addr"])
		}
		if len(pos) != 2 {
			t.Errorf("unexpected pos: %v", pos)
		}
	})

	t.Run("ValueFlagsWithSpace", func(t *testing.T) {
		raw := []string{"remote", "add", "my-loc", "local", "--path", "/data/my-loc"}
		pos, flags, _, err := parseArgs(raw)
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if flags["path"] != "/data/my-loc" {
			t.Errorf("expected path=/data/my-loc, got %q", flags["path"])
		}
		if len(pos) != 4 {
			t.Errorf("unexpected pos: %v", pos)
		}
	})

	t.Run("ShortFlagsGrouped", func(t *testing.T) {
		raw := []string{"ls", "-rlH", "data"}
		pos, _, boolFlags, err := parseArgs(raw)
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if !boolFlags["r"] || !boolFlags["l"] || !boolFlags["H"] {
			t.Errorf("expected r, l, and H bool flags set")
		}
		if len(pos) != 2 {
			t.Errorf("unexpected pos: %v", pos)
		}
	})

	t.Run("DockerEntrypointCMD", func(t *testing.T) {
		raw := []string{"daemon", "start", "--foreground", "--config", "/config", "--data", "/data"}
		pos, flags, boolFlags, err := parseArgs(raw)
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if len(pos) != 2 || pos[0] != "daemon" || pos[1] != "start" {
			t.Errorf("expected positional args [daemon, start], got %v", pos)
		}
		if !boolFlags["foreground"] {
			t.Errorf("expected foreground bool flag set")
		}
		if flags["config"] != "/config" {
			t.Errorf("expected config=/config, got %q", flags["config"])
		}
		if flags["data"] != "/data" {
			t.Errorf("expected data=/data, got %q", flags["data"])
		}

		ctx := NewCLIContext(flags, boolFlags)
		if ctx.ConfigDir != "/config" {
			t.Errorf("expected ConfigDir=/config, got %q", ctx.ConfigDir)
		}
		if ctx.DataDir != "/data" {
			t.Errorf("expected DataDir=/data, got %q", ctx.DataDir)
		}
	})

	t.Run("UnknownFlagError", func(t *testing.T) {
		raw := []string{"--invalid-unrecognized-flag-xyz"}
		_, _, _, err := parseArgs(raw)
		if err == nil {
			t.Errorf("expected error for unknown flag")
		}
	})
}

func TestCLI_RemoteCRUD(t *testing.T) {
	tempDir := t.TempDir()
	configDir := filepath.Join(tempDir, ".unistorage")
	dataDir := filepath.Join(tempDir, "data")
	_ = os.MkdirAll(dataDir, 0755)

	cliCtx := &CLIContext{
		ConfigDir:       configDir,
		VaultPassphrase: "test-passphrase",
	}

	// 1. Add Local Remote
	addArgs := []string{"my-local", "local"}
	addFlags := map[string]string{"path": dataDir}
	err := runRemoteAdd(cliCtx, addArgs, addFlags, nil)
	if err != nil {
		t.Fatalf("runRemoteAdd failed: %v", err)
	}

	// Verify profile is in vault
	v := cliCtx.GetVault()
	prof, err := v.GetRemote(cliCtx.VaultPassphrase, "my-local")
	if err != nil || prof == nil {
		t.Fatalf("GetRemote failed: %v", err)
	}
	if prof.Path != dataDir {
		t.Errorf("expected path %s, got %s", dataDir, prof.Path)
	}

	// 2. Add S3 Remote
	s3Args := []string{"my-s3"}
	s3Flags := map[string]string{
		"type":       "s3",
		"endpoint":   "http://localhost:9000",
		"bucket":     "my-bucket",
		"access-key": "AKIAIOSFODNN7EXAMPLE",
		"secret-key": "secret12345678",
	}
	err = runRemoteAdd(cliCtx, s3Args, s3Flags, nil)
	if err != nil {
		t.Fatalf("runRemoteAdd S3 failed: %v", err)
	}

	// 3. List Remotes
	err = runRemoteList(cliCtx, nil, nil, nil)
	if err != nil {
		t.Errorf("runRemoteList failed: %v", err)
	}

	// 4. List Remotes JSON
	err = runRemoteList(cliCtx, nil, nil, map[string]bool{"json": true})
	if err != nil {
		t.Errorf("runRemoteList JSON failed: %v", err)
	}

	// 5. Remove Remote
	err = runRemoteRemove(cliCtx, []string{"my-local"}, nil, nil)
	if err != nil {
		t.Errorf("runRemoteRemove failed: %v", err)
	}

	// 6. Remove nonexistent remote (should succeed / be idempotent)
	err = runRemoteRemove(cliCtx, []string{"nonexistent-remote-xyz"}, nil, nil)
	if err != nil {
		t.Errorf("runRemoteRemove nonexistent failed: %v", err)
	}
}

func TestCLI_Fileops(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	cliCtx := &CLIContext{
		ConfigDir:       filepath.Join(tempDir, ".unistorage"),
		VaultPassphrase: "test-passphrase",
	}

	srcFile := filepath.Join(tempDir, "src.txt")
	dstFile := filepath.Join(tempDir, "dst.txt")
	content := []byte("hello fileops test")
	if err := os.WriteFile(srcFile, content, 0644); err != nil {
		t.Fatalf("failed to write src: %v", err)
	}

	// 1. Test Cp
	err := RunCp(ctx, cliCtx, []string{srcFile, dstFile}, nil, nil)
	if err != nil {
		t.Fatalf("RunCp failed: %v", err)
	}
	dstData, err := os.ReadFile(dstFile)
	if err != nil || string(dstData) != string(content) {
		t.Errorf("cp content mismatch: %v (data=%q)", err, string(dstData))
	}

	// 2. Test Ls
	err = RunLs(ctx, cliCtx, []string{srcFile}, nil, nil)
	if err != nil {
		t.Errorf("RunLs file failed: %v", err)
	}

	err = RunLs(ctx, cliCtx, []string{tempDir}, nil, map[string]bool{"l": true, "H": true})
	if err != nil {
		t.Errorf("RunLs long dir failed: %v", err)
	}

	err = RunLs(ctx, cliCtx, []string{tempDir}, nil, map[string]bool{"json": true})
	if err != nil {
		t.Errorf("RunLs JSON failed: %v", err)
	}

	// 3. Test Rm
	err = RunRm(ctx, cliCtx, []string{dstFile}, nil, nil)
	if err != nil {
		t.Errorf("RunRm failed: %v", err)
	}
	if _, err := os.Stat(dstFile); !os.IsNotExist(err) {
		t.Errorf("expected dstFile to be deleted")
	}

	// 4. Test Rm Recursive
	subDir := filepath.Join(tempDir, "rm_sub")
	_ = os.MkdirAll(subDir, 0755)
	_ = os.WriteFile(filepath.Join(subDir, "child.txt"), []byte("c"), 0644)
	err = RunRm(ctx, cliCtx, []string{subDir}, nil, map[string]bool{"r": true})
	if err != nil {
		t.Errorf("RunRm recursive failed: %v", err)
	}
}

func TestCLI_Sync(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	cliCtx := &CLIContext{
		ConfigDir:       filepath.Join(tempDir, ".unistorage"),
		VaultPassphrase: "test-passphrase",
	}

	srcDir := filepath.Join(tempDir, "sync_src")
	dstDir := filepath.Join(tempDir, "sync_dst")
	_ = os.MkdirAll(srcDir, 0755)
	_ = os.MkdirAll(dstDir, 0755)

	_ = os.WriteFile(filepath.Join(srcDir, "f1.txt"), []byte("v1"), 0644)
	_ = os.WriteFile(filepath.Join(srcDir, "f2.txt"), []byte("v2"), 0644)

	// 1. Initial Sync
	err := RunSync(ctx, cliCtx, []string{srcDir, dstDir}, nil, nil)
	if err != nil {
		t.Fatalf("RunSync initial failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "f1.txt")); err != nil {
		t.Errorf("f1.txt not found in dst: %v", err)
	}

	// 2. Sync with --checksum
	err = RunSync(ctx, cliCtx, []string{srcDir, dstDir}, nil, map[string]bool{"checksum": true})
	if err != nil {
		t.Errorf("RunSync checksum failed: %v", err)
	}

	// 3. Sync with conflict backup
	time.Sleep(1100 * time.Millisecond)
	_ = os.WriteFile(filepath.Join(srcDir, "f1.txt"), []byte("v1 updated"), 0644)
	err = RunSync(ctx, cliCtx, []string{srcDir, dstDir}, nil, nil)
	if err != nil {
		t.Errorf("RunSync conflict backup failed: %v", err)
	}

	// Verify .conflicts directory was created
	conflictsDir := filepath.Join(dstDir, ".conflicts")
	entries, _ := os.ReadDir(conflictsDir)
	if len(entries) == 0 {
		t.Errorf("expected conflict backup file in %s", conflictsDir)
	}

	// 4. Sync with --delete
	_ = os.WriteFile(filepath.Join(dstDir, "extra.txt"), []byte("extra"), 0644)
	err = RunSync(ctx, cliCtx, []string{srcDir, dstDir}, nil, map[string]bool{"delete": true})
	if err != nil {
		t.Errorf("RunSync delete failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "extra.txt")); !os.IsNotExist(err) {
		t.Errorf("expected extra.txt to be deleted")
	}

	// 5. Sync with --dry-run
	err = RunSync(ctx, cliCtx, []string{srcDir, dstDir}, nil, map[string]bool{"dry-run": true})
	if err != nil {
		t.Errorf("RunSync dry-run failed: %v", err)
	}
}

func TestCLI_Daemon_Offline(t *testing.T) {
	tempDir := t.TempDir()
	cliCtx := &CLIContext{
		ConfigDir:       filepath.Join(tempDir, ".unistorage"),
		DaemonAddr:      "http://127.0.0.1:59999", // Port not running
		VaultPassphrase: "test-passphrase",
	}

	// 1. Status offline
	err := runDaemonStatus(cliCtx, nil, nil, nil)
	if err != nil {
		t.Errorf("runDaemonStatus error: %v", err)
	}

	// 2. Status offline JSON
	err = runDaemonStatus(cliCtx, nil, nil, map[string]bool{"json": true})
	if err != nil {
		t.Errorf("runDaemonStatus JSON error: %v", err)
	}

	// 3. Stop when not running
	err = runDaemonStop(cliCtx, nil, nil, nil)
	if err != nil {
		t.Errorf("runDaemonStop error: %v", err)
	}

	// 4. Double stop
	err = runDaemonStop(cliCtx, nil, nil, nil)
	if err != nil {
		t.Errorf("runDaemonStop double stop error: %v", err)
	}
}

func TestCLI_TargetNotFound(t *testing.T) {
	ctx := context.Background()
	cliCtx := &CLIContext{
		ConfigDir:       t.TempDir(),
		VaultPassphrase: "test-passphrase",
	}

	// Nonexistent local path
	_, err := ResolveTarget(ctx, cliCtx, "nonexistent/dir/or/file.txt", false, false)
	if err == nil {
		t.Errorf("expected error for nonexistent local path")
	}
	if cliErr, ok := err.(*CLIError); ok {
		if cliErr.Code != ExitNotFound {
			t.Errorf("expected ExitNotFound (%d), got %d", ExitNotFound, cliErr.Code)
		}
	} else {
		t.Errorf("expected CLIError, got %T", err)
	}

	// Nonexistent remote profile
	_, err = ResolveTarget(ctx, cliCtx, "missing-remote:bucket/file", false, false)
	if err == nil {
		t.Errorf("expected error for nonexistent remote profile")
	}
	if cliErr, ok := err.(*CLIError); ok {
		if cliErr.Code != ExitNotFound {
			t.Errorf("expected ExitNotFound (%d), got %d", ExitNotFound, cliErr.Code)
		}
	}
}
