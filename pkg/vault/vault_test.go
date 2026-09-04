package vault_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aboutdevz/unistorage/pkg/vault"
)

func TestVault_SaveAndGet(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "unistorage-vault-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	vaultPath := filepath.Join(tempDir, "vault.enc")
	v := vault.New(vaultPath)
	passphrase := "master-secret-passphrase-1234"

	profile := vault.RemoteProfile{
		Name:      "s3-production",
		Type:      "s3",
		Endpoint:  "https://s3.us-east-1.amazonaws.com",
		Region:    "us-east-1",
		Bucket:    "my-company-backup-bucket",
		AccessKey: "AKIAIOSFODNN7EXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Options: map[string]string{
			"storage_class": "STANDARD_IA",
		},
	}

	// 1. Save profile
	if err := v.SaveRemote(passphrase, profile); err != nil {
		t.Fatalf("SaveRemote failed: %v", err)
	}

	// 2. Verify file exists on disk and is non-empty
	info, err := os.Stat(vaultPath)
	if err != nil {
		t.Fatalf("vault file missing: %v", err)
	}
	if info.Size() == 0 {
		t.Fatalf("vault file is empty")
	}

	// 3. Get profile back
	retrieved, err := v.GetRemote(passphrase, "s3-production")
	if err != nil {
		t.Fatalf("GetRemote failed: %v", err)
	}

	if retrieved.Name != profile.Name ||
		retrieved.Type != profile.Type ||
		retrieved.Bucket != profile.Bucket ||
		retrieved.AccessKey != profile.AccessKey ||
		retrieved.SecretKey != profile.SecretKey {
		t.Fatalf("retrieved profile does not match saved profile: %+v vs %+v", retrieved, profile)
	}
}

func TestVault_InvalidPassphrase(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "unistorage-vault-badpass-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	vaultPath := filepath.Join(tempDir, "vault.enc")
	v := vault.New(vaultPath)
	correctPass := "correct-master-key"
	wrongPass := "wrong-master-key"

	profile := vault.RemoteProfile{
		Name: "local-backup",
		Type: "local",
		Path: "/mnt/backup",
	}

	if err := v.SaveRemote(correctPass, profile); err != nil {
		t.Fatalf("save remote failed: %v", err)
	}

	// Try reading with wrong passphrase
	_, err = v.GetRemote(wrongPass, "local-backup")
	if err == nil {
		t.Fatalf("expected error for wrong passphrase, got nil")
	}
	if !errors.Is(err, vault.ErrInvalidPassword) {
		t.Fatalf("expected ErrInvalidPassword, got: %v", err)
	}
}

func TestVault_ListAndDelete(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "unistorage-vault-crud-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	vaultPath := filepath.Join(tempDir, "vault.enc")
	v := vault.New(vaultPath)
	pass := "super-secure-pass"

	p1 := vault.RemoteProfile{Name: "rem-1", Type: "local", Path: "/data1"}
	p2 := vault.RemoteProfile{Name: "rem-2", Type: "s3", Bucket: "bucket-b"}
	p3 := vault.RemoteProfile{Name: "rem-3", Type: "s3", Bucket: "bucket-c"}

	_ = v.SaveRemote(pass, p1)
	_ = v.SaveRemote(pass, p2)
	_ = v.SaveRemote(pass, p3)

	// List
	names, err := v.ListRemotes(pass)
	if err != nil {
		t.Fatalf("ListRemotes failed: %v", err)
	}
	if len(names) != 3 {
		t.Fatalf("expected 3 remotes, got %d", len(names))
	}

	// Delete rem-2
	if err := v.DeleteRemote(pass, "rem-2"); err != nil {
		t.Fatalf("DeleteRemote failed: %v", err)
	}

	// Verify rem-2 is gone
	_, err = v.GetRemote(pass, "rem-2")
	if !errors.Is(err, vault.ErrRemoteNotFound) {
		t.Fatalf("expected ErrRemoteNotFound, got: %v", err)
	}

	// Idempotent delete
	if err := v.DeleteRemote(pass, "rem-2"); err != nil {
		t.Fatalf("idempotent delete failed: %v", err)
	}
}

func TestVault_CorruptedHeader(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "unistorage-vault-corrupt-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	vaultPath := filepath.Join(tempDir, "vault.enc")
	v := vault.New(vaultPath)
	pass := "pass"

	_ = v.SaveRemote(pass, vault.RemoteProfile{Name: "rem-1", Type: "local"})

	// Corrupt magic header
	data, _ := os.ReadFile(vaultPath)
	data[0] = 'X'
	data[1] = 'Y'
	_ = os.WriteFile(vaultPath, data, 0600)

	_, err = v.GetRemote(pass, "rem-1")
	if !errors.Is(err, vault.ErrCorruptedVault) {
		t.Fatalf("expected ErrCorruptedVault for tampered header, got %v", err)
	}
}

func TestVault_MemZero(t *testing.T) {
	buf := []byte("highly-sensitive-secret-token-12345")
	vault.MemZero(buf)
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("byte at index %d was not zeroed: %d", i, b)
		}
	}
}
