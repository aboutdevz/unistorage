package main

import (
	"encoding/json"
	"fmt"
	"runtime"
)

var (
	// Version is the semantic release version injected at build time via -ldflags.
	Version = "0.1.0"
	// Commit is the git commit hash injected at build time via -ldflags.
	Commit = "none"
	// BuildTime is the ISO-8601 build timestamp injected at build time via -ldflags.
	BuildTime = "unknown"
)

// AppVersion provides a reference for backward compatibility.
var AppVersion = Version

// VersionInfo contains structured runtime and build metadata.
type VersionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	BuildTime string `json:"build_time,omitempty"`
	GoVersion string `json:"go_version"`
	Compiler  string `json:"compiler"`
	Platform  string `json:"platform"`
}

// GetVersionInfo returns structured version information.
func GetVersionInfo() VersionInfo {
	return VersionInfo{
		Version:   Version,
		Commit:    Commit,
		BuildTime: BuildTime,
		GoVersion: runtime.Version(),
		Compiler:  runtime.Compiler,
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

// printVersion outputs version information in either human-readable or JSON format.
func printVersion(asJSON bool) {
	info := GetVersionInfo()
	if asJSON {
		b, err := json.MarshalIndent(info, "", "  ")
		if err == nil {
			fmt.Println(string(b))
			return
		}
	}

	if info.Commit != "" && info.Commit != "none" {
		fmt.Printf("unistorage version %s (commit: %s, built: %s, %s, %s)\n",
			info.Version, info.Commit, info.BuildTime, info.GoVersion, info.Platform)
	} else {
		fmt.Printf("unistorage version %s\n", info.Version)
	}
}
