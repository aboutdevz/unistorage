package main

import (
	"fmt"
	"strings"

	"github.com/aboutdevz/unistorage/pkg/vault"
)

// RunRemote handles subcommands under "unistorage remote ...".
func RunRemote(cliCtx *CLIContext, args []string, flags map[string]string, boolFlags map[string]bool) error {
	if boolFlags["help"] || boolFlags["h"] || (len(args) > 0 && args[0] == "help") {
		printRemoteHelp()
		return nil
	}
	if len(args) == 0 {
		return NewCLIError(ExitParamError, "usage: unistorage remote <add|list|remove> [args...]")
	}

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "add":
		return runRemoteAdd(cliCtx, subargs, flags, boolFlags)
	case "list", "ls":
		return runRemoteList(cliCtx, subargs, flags, boolFlags)
	case "remove", "rm", "delete":
		return runRemoteRemove(cliCtx, subargs, flags, boolFlags)
	default:
		return NewCLIError(ExitParamError, fmt.Sprintf("unknown remote subcommand %q (valid: add, list, remove)", subcmd))
	}
}

func runRemoteAdd(cliCtx *CLIContext, args []string, flags map[string]string, boolFlags map[string]bool) error {
	if len(args) < 1 {
		return NewCLIError(ExitParamError, "usage: unistorage remote add <name> [type] [flags]")
	}

	name := args[0]
	remoteType := flags["type"]
	if remoteType == "" && len(args) > 1 {
		remoteType = args[1]
	}
	if remoteType == "" {
		return NewCLIError(ExitParamError, "missing required remote type (e.g. 'local' or 's3')")
	}

	prof := vault.RemoteProfile{
		Name: name,
		Type: strings.ToLower(remoteType),
	}

	switch prof.Type {
	case "local":
		path := flags["path"]
		if path == "" && len(args) > 2 {
			path = args[2]
		}
		if path == "" {
			return NewCLIError(ExitParamError, "missing required --path flag for local remote")
		}
		prof.Path = path

	case "s3":
		prof.Endpoint = flags["endpoint"]
		prof.Bucket = flags["bucket"]
		prof.AccessKey = flags["access-key"]
		prof.SecretKey = flags["secret-key"]
		prof.Region = flags["region"]
		if prof.Region == "" {
			prof.Region = "us-east-1"
		}

	default:
		return NewCLIError(ExitParamError, fmt.Sprintf("unsupported remote type %q (supported: local, s3)", prof.Type))
	}

	v := cliCtx.GetVault()
	if err := v.SaveRemote(cliCtx.VaultPassphrase, prof); err != nil {
		return NewCLIError(ExitIOError, "failed to save remote to encrypted vault", err)
	}

	cliCtx.Log("Remote '%s' (%s) successfully registered in encrypted vault.", prof.Name, prof.Type)
	return nil
}

func runRemoteList(cliCtx *CLIContext, args []string, flags map[string]string, boolFlags map[string]bool) error {
	v := cliCtx.GetVault()
	names, err := v.ListRemotes(cliCtx.VaultPassphrase)
	if err != nil {
		return NewCLIError(ExitIOError, "failed to list remotes from encrypted vault", err)
	}

	type safeProfile struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Endpoint string `json:"endpoint,omitempty"`
		Path     string `json:"path,omitempty"`
		Bucket   string `json:"bucket,omitempty"`
		Status   string `json:"status"`
	}

	profiles := make([]safeProfile, 0)
	for _, name := range names {
		p, err := v.GetRemote(cliCtx.VaultPassphrase, name)
		if err == nil && p != nil {
			sp := safeProfile{
				Name:     p.Name,
				Type:     p.Type,
				Endpoint: p.Endpoint,
				Path:     p.Path,
				Bucket:   p.Bucket,
				Status:   "CONFIGURED",
			}
			profiles = append(profiles, sp)
		}
	}

	if cliCtx.JSON || boolFlags["json"] {
		return cliCtx.PrintJSON(profiles)
	}

	// Formatted table output
	fmt.Printf("%-15s %-8s %-32s %-15s %s\n", "NAME", "TYPE", "ENDPOINT / PATH", "BUCKET", "STATUS")
	for _, p := range profiles {
		loc := p.Path
		if p.Type == "s3" {
			loc = p.Endpoint
		}
		bucket := p.Bucket
		if bucket == "" {
			bucket = "-"
		}
		fmt.Printf("%-15s %-8s %-32s %-15s %s\n", p.Name, p.Type, loc, bucket, p.Status)
	}

	return nil
}

func runRemoteRemove(cliCtx *CLIContext, args []string, flags map[string]string, boolFlags map[string]bool) error {
	if len(args) < 1 {
		return NewCLIError(ExitParamError, "usage: unistorage remote remove <name>")
	}

	name := args[0]
	v := cliCtx.GetVault()
	if err := v.DeleteRemote(cliCtx.VaultPassphrase, name); err != nil {
		return NewCLIError(ExitIOError, fmt.Sprintf("failed to remove remote %q from vault", name), err)
	}

	cliCtx.Log("Remote '%s' removed from vault.", name)
	return nil
}
