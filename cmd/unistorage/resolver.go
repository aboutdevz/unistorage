package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aboutdevz/unistorage/pkg/storage"
	"github.com/aboutdevz/unistorage/pkg/storage/local"
	"github.com/aboutdevz/unistorage/pkg/storage/s3"
	synce "github.com/aboutdevz/unistorage/pkg/sync"
	"github.com/aboutdevz/unistorage/pkg/vault"
)

// ResolvedEndpoint contains the instantiated storage.Driver and relative prefix path.
type ResolvedEndpoint struct {
	Driver storage.Driver
	Prefix string
	IsDir  bool
	IsFile bool
}

// ResolveTarget parses a target path and instantiates the appropriate storage driver.
func ResolveTarget(ctx context.Context, cliCtx *CLIContext, targetStr string, isDest bool, mustBeDir bool) (*ResolvedEndpoint, error) {
	loc, err := synce.ParseTarget(targetStr)
	if err != nil {
		return nil, NewCLIError(ExitParamError, "invalid target", err)
	}

	if !loc.IsRemote {
		// Local filesystem path
		absPath, err := filepath.Abs(loc.Path)
		if err != nil {
			absPath = loc.Path
		}

		fi, statErr := os.Stat(absPath)
		if statErr == nil {
			if fi.IsDir() {
				drv, err := local.New(absPath)
				if err != nil {
					return nil, NewCLIError(ExitIOError, "failed to initialize local driver", err)
				}
				return &ResolvedEndpoint{
					Driver: drv,
					Prefix: "",
					IsDir:  true,
				}, nil
			}
			// It is an existing file
			dir := filepath.Dir(absPath)
			base := filepath.Base(absPath)
			drv, err := local.New(dir)
			if err != nil {
				return nil, NewCLIError(ExitIOError, "failed to initialize local driver", err)
			}
			return &ResolvedEndpoint{
				Driver: drv,
				Prefix: base,
				IsFile: true,
			}, nil
		}

		// File or dir does not exist yet
		if !isDest {
			return nil, NewCLIError(ExitNotFound, fmt.Sprintf("local path not found: %s", loc.Path))
		}

		isDir := mustBeDir || strings.HasSuffix(targetStr, "/") || strings.HasSuffix(targetStr, "\\")
		if isDir {
			if err := os.MkdirAll(absPath, 0750); err != nil {
				return nil, NewCLIError(ExitIOError, "failed to create destination directory", err)
			}
			drv, err := local.New(absPath)
			if err != nil {
				return nil, NewCLIError(ExitIOError, "failed to initialize local driver", err)
			}
			return &ResolvedEndpoint{
				Driver: drv,
				Prefix: "",
				IsDir:  true,
			}, nil
		}

		// Destination file that does not exist yet: parent must exist
		parent := filepath.Dir(absPath)
		if err := os.MkdirAll(parent, 0750); err != nil {
			return nil, NewCLIError(ExitIOError, "failed to create destination parent directory", err)
		}
		drv, err := local.New(parent)
		if err != nil {
			return nil, NewCLIError(ExitIOError, "failed to initialize local destination parent", err)
		}
		return &ResolvedEndpoint{
			Driver: drv,
			Prefix: filepath.Base(absPath),
			IsFile: true,
		}, nil
	}

	// Remote target
	v := cliCtx.GetVault()
	prof, err := v.GetRemote(cliCtx.VaultPassphrase, loc.RemoteName)
	if err != nil {
		if errors.Is(err, vault.ErrRemoteNotFound) {
			return nil, NewCLIError(ExitNotFound, fmt.Sprintf("remote profile %q not found", loc.RemoteName))
		}
		return nil, NewCLIError(ExitAuthError, fmt.Sprintf("failed to unlock vault for remote %q", loc.RemoteName), err)
	}

	switch prof.Type {
	case "local":
		baseDir := prof.Path
		if baseDir == "" {
			return nil, NewCLIError(ExitParamError, fmt.Sprintf("remote %q is missing base path", prof.Name))
		}
		drv, err := local.New(baseDir)
		if err != nil {
			return nil, NewCLIError(ExitIOError, "failed to initialize local remote driver", err)
		}
		return &ResolvedEndpoint{
			Driver: drv,
			Prefix: loc.Path,
			IsDir:  loc.Path == "" || strings.HasSuffix(loc.Path, "/"),
		}, nil

	case "s3":
		bucket := prof.Bucket
		prefix := loc.Path

		if bucket == "" {
			// Extract bucket from path: bucket/prefix
			parts := strings.SplitN(loc.Path, "/", 2)
			bucket = parts[0]
			if len(parts) > 1 {
				prefix = parts[1]
			} else {
				prefix = ""
			}
		} else {
			// Bucket is configured in profile
			if strings.HasPrefix(prefix, bucket+"/") {
				prefix = strings.TrimPrefix(prefix, bucket+"/")
			} else if prefix == bucket {
				prefix = ""
			}
		}

		s3Drv, err := s3.New(ctx, s3.Config{
			Endpoint:     prof.Endpoint,
			Region:       prof.Region,
			Bucket:       bucket,
			AccessKey:    prof.AccessKey,
			SecretKey:    prof.SecretKey,
			UsePathStyle: true,
		})
		if err != nil {
			return nil, NewCLIError(ExitIOError, fmt.Sprintf("failed to initialize s3 driver for %q", prof.Name), err)
		}

		return &ResolvedEndpoint{
			Driver: s3Drv,
			Prefix: prefix,
			IsDir:  prefix == "" || strings.HasSuffix(prefix, "/"),
		}, nil

	default:
		return nil, NewCLIError(ExitParamError, fmt.Sprintf("unknown remote type %q", prof.Type))
	}
}
