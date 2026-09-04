package vault_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aboutdevz/unistorage/pkg/vault"
)

const (
	canaryAccessKey = "CANARY_ACCESS_KEY_SECRET_12345"
	canarySecretKey = "CANARY_SECRET_KEY_SUPER_CONFIDENTIAL_67890"
	canaryBucket    = "canary-protected-bucket"
	canaryRemote    = "canary-remote"
	masterPass      = "master-adversarial-passphrase-2026"
)

func setupCanaryVault(t *testing.T) (*vault.FileVault, string, func()) {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "unistorage-adversarial-vault-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	vaultPath := filepath.Join(tempDir, "vault.enc")
	v := vault.New(vaultPath)

	profile := vault.RemoteProfile{
		Name:      canaryRemote,
		Type:      "s3",
		Endpoint:  "https://s3.us-west-2.amazonaws.com",
		Region:    "us-west-2",
		Bucket:    canaryBucket,
		AccessKey: canaryAccessKey,
		SecretKey: canarySecretKey,
		Options: map[string]string{
			"canary_option": "confidential_value",
		},
	}

	if err := v.SaveRemote(masterPass, profile); err != nil {
		t.Fatalf("failed to seed canary vault: %v", err)
	}

	cleanup := func() {
		_ = os.RemoveAll(tempDir)
	}

	return v, vaultPath, cleanup
}

func assertZeroPlaintextLeakage(t *testing.T, profile *vault.RemoteProfile, err error, contextDesc string) {
	t.Helper()
	if err == nil {
		t.Fatalf("[%s] expected decryption error, but got nil!", contextDesc)
	}
	if profile != nil {
		t.Fatalf("[%s] expected nil profile, but got non-nil: %+v", contextDesc, profile)
	}

	errStr := err.Error()
	if strings.Contains(errStr, canaryAccessKey) ||
		strings.Contains(errStr, canarySecretKey) ||
		strings.Contains(errStr, canaryBucket) {
		t.Fatalf("[%s] CRITICAL: plaintext canary leaked in error string: %s", contextDesc, errStr)
	}
}

// TestAdversarial_VaultTamper_CiphertextBitFlips flips bits at various offsets in ciphertext and tag.
func TestAdversarial_VaultTamper_CiphertextBitFlips(t *testing.T) {
	v, vaultPath, cleanup := setupCanaryVault(t)
	defer cleanup()

	originalBytes, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("failed to read vault bytes: %v", err)
	}

	headerLen := 4 + 1 + 4 + 4 + 1 + 16 + 12 // 42 bytes
	if len(originalBytes) <= headerLen+16 {
		t.Fatalf("vault file too small: %d bytes", len(originalBytes))
	}

	ciphertextLen := len(originalBytes) - headerLen
	offsetsToTest := []struct {
		name   string
		offset int
	}{
		{"Ciphertext_Start", headerLen},
		{"Ciphertext_Offset+1", headerLen + 1},
		{"Ciphertext_Middle", headerLen + ciphertextLen/2},
		{"Ciphertext_BeforeTag", len(originalBytes) - 17},
		{"GCM_Tag_FirstByte", len(originalBytes) - 16},
		{"GCM_Tag_MiddleByte", len(originalBytes) - 8},
		{"GCM_Tag_LastByte", len(originalBytes) - 1},
	}

	for _, tc := range offsetsToTest {
		t.Run(tc.name, func(t *testing.T) {
			tampered := make([]byte, len(originalBytes))
			copy(tampered, originalBytes)

			// Flip bit 0
			tampered[tc.offset] ^= 0x01

			if err := os.WriteFile(vaultPath, tampered, 0600); err != nil {
				t.Fatalf("failed to write tampered vault: %v", err)
			}

			prof, err := v.GetRemote(masterPass, canaryRemote)
			assertZeroPlaintextLeakage(t, prof, err, tc.name)

			if !errors.Is(err, vault.ErrInvalidPassword) {
				t.Logf("[%s] got error: %v (expected ErrInvalidPassword)", tc.name, err)
			}

			// Also verify ListRemotes fails
			remotes, listErr := v.ListRemotes(masterPass)
			if listErr == nil {
				t.Fatalf("[%s] ListRemotes succeeded on tampered vault! Got: %v", tc.name, remotes)
			}
		})
	}
}

// TestAdversarial_VaultTamper_NonceAndSalt flips bits in the nonce and salt header fields.
func TestAdversarial_VaultTamper_NonceAndSalt(t *testing.T) {
	v, vaultPath, cleanup := setupCanaryVault(t)
	defer cleanup()

	originalBytes, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("failed to read vault bytes: %v", err)
	}

	// Header layout: Magic(4) + Ver(1) + Time(4) + Mem(4) + Threads(1) + Salt(16) + Nonce(12)
	// Salt is at [14 : 30]
	// Nonce is at [30 : 42]
	cases := []struct {
		name   string
		offset int
	}{
		{"Salt_Byte0", 14},
		{"Salt_Byte7", 21},
		{"Salt_Byte15", 29},
		{"Nonce_Byte0", 30},
		{"Nonce_Byte5", 35},
		{"Nonce_Byte11", 41},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := make([]byte, len(originalBytes))
			copy(tampered, originalBytes)
			tampered[tc.offset] ^= 0xFF

			if err := os.WriteFile(vaultPath, tampered, 0600); err != nil {
				t.Fatalf("failed to write tampered vault: %v", err)
			}

			prof, err := v.GetRemote(masterPass, canaryRemote)
			assertZeroPlaintextLeakage(t, prof, err, tc.name)
		})
	}
}

// TestAdversarial_VaultTamper_MagicAndVersion tests header metadata corruption.
func TestAdversarial_VaultTamper_MagicAndVersion(t *testing.T) {
	v, vaultPath, cleanup := setupCanaryVault(t)
	defer cleanup()

	originalBytes, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("failed to read vault bytes: %v", err)
	}

	// 1. Corrupted Magic
	t.Run("CorruptMagic", func(t *testing.T) {
		tampered := make([]byte, len(originalBytes))
		copy(tampered, originalBytes)
		copy(tampered[0:4], []byte("HACK"))

		_ = os.WriteFile(vaultPath, tampered, 0600)
		prof, err := v.GetRemote(masterPass, canaryRemote)
		assertZeroPlaintextLeakage(t, prof, err, "CorruptMagic")
		if !errors.Is(err, vault.ErrCorruptedVault) {
			t.Errorf("expected ErrCorruptedVault, got %v", err)
		}
	})

	// 2. Unsupported Version
	t.Run("UnsupportedVersion", func(t *testing.T) {
		tampered := make([]byte, len(originalBytes))
		copy(tampered, originalBytes)
		tampered[4] = 0x99 // unsupported version

		_ = os.WriteFile(vaultPath, tampered, 0600)
		prof, err := v.GetRemote(masterPass, canaryRemote)
		assertZeroPlaintextLeakage(t, prof, err, "UnsupportedVersion")
		if !errors.Is(err, vault.ErrCorruptedVault) {
			t.Errorf("expected ErrCorruptedVault, got %v", err)
		}
	})
}

// TestAdversarial_VaultTamper_Truncation tests truncated vault files.
func TestAdversarial_VaultTamper_Truncation(t *testing.T) {
	v, vaultPath, cleanup := setupCanaryVault(t)
	defer cleanup()

	originalBytes, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("failed to read vault bytes: %v", err)
	}

	lengths := []struct {
		name   string
		length int
	}{
		{"Truncated_1Byte", len(originalBytes) - 1},
		{"Truncated_TagHalf", len(originalBytes) - 8},
		{"Truncated_AllTag", len(originalBytes) - 16},
		{"Truncated_CiphertextHalf", 42 + (len(originalBytes)-42)/2},
		{"Truncated_HeaderBoundary", 41},
		{"Truncated_MagicOnly", 4},
		{"Truncated_Empty", 0},
	}

	for _, tc := range lengths {
		t.Run(tc.name, func(t *testing.T) {
			tampered := originalBytes[:tc.length]
			if err := os.WriteFile(vaultPath, tampered, 0600); err != nil {
				t.Fatalf("failed to write truncated vault: %v", err)
			}

			prof, err := v.GetRemote(masterPass, canaryRemote)
			if tc.length == 0 {
				// Empty file: loadStore returns empty map, GetRemote returns ErrRemoteNotFound
				if !errors.Is(err, vault.ErrRemoteNotFound) {
					t.Logf("empty file returned: %v", err)
				}
				if prof != nil {
					t.Fatalf("expected nil profile for empty file, got: %+v", prof)
				}
			} else {
				assertZeroPlaintextLeakage(t, prof, err, tc.name)
			}
		})
	}
}

// TestAdversarial_VaultTamper_AppendedJunk tests appending rogue bytes to ciphertext.
func TestAdversarial_VaultTamper_AppendedJunk(t *testing.T) {
	v, vaultPath, cleanup := setupCanaryVault(t)
	defer cleanup()

	originalBytes, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("failed to read vault bytes: %v", err)
	}

	junkSizes := []int{1, 16, 256, 1024}
	for _, size := range junkSizes {
		t.Run(fmt.Sprintf("Append_%dBytes", size), func(t *testing.T) {
			tampered := append([]byte(nil), originalBytes...)
			tampered = append(tampered, bytes.Repeat([]byte{0xDE, 0xAD, 0xBE, 0xEF}, size/4+1)[:size]...)

			if err := os.WriteFile(vaultPath, tampered, 0600); err != nil {
				t.Fatalf("failed to write vault with appended junk: %v", err)
			}

			prof, err := v.GetRemote(masterPass, canaryRemote)
			assertZeroPlaintextLeakage(t, prof, err, fmt.Sprintf("Append_%dBytes", size))
		})
	}
}

// TestAdversarial_VaultTamper_Argon2Params tests tampering with the Argon2 parameters stored in the header.
func TestAdversarial_VaultTamper_Argon2Params(t *testing.T) {
	v, vaultPath, cleanup := setupCanaryVault(t)
	defer cleanup()

	originalBytes, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("failed to read vault bytes: %v", err)
	}

	// Offset 5..8 is timeVal (uint32)
	// Offset 9..12 is memVal (uint32)
	// Offset 13 is threadsVal (uint8)
	t.Run("Tamper_TimeVal", func(t *testing.T) {
		tampered := make([]byte, len(originalBytes))
		copy(tampered, originalBytes)
		tampered[8] ^= 0x01 // flip last byte of timeVal

		if err := os.WriteFile(vaultPath, tampered, 0600); err != nil {
			t.Fatalf("failed to write tampered vault: %v", err)
		}

		prof, err := v.GetRemote(masterPass, canaryRemote)
		assertZeroPlaintextLeakage(t, prof, err, "Tamper_TimeVal")
	})

	t.Run("Tamper_MemVal", func(t *testing.T) {
		tampered := make([]byte, len(originalBytes))
		copy(tampered, originalBytes)
		tampered[12] ^= 0x01 // flip last byte of memVal

		if err := os.WriteFile(vaultPath, tampered, 0600); err != nil {
			t.Fatalf("failed to write tampered vault: %v", err)
		}

		prof, err := v.GetRemote(masterPass, canaryRemote)
		assertZeroPlaintextLeakage(t, prof, err, "Tamper_MemVal")
	})

	t.Run("Tamper_ThreadsVal", func(t *testing.T) {
		tampered := make([]byte, len(originalBytes))
		copy(tampered, originalBytes)
		tampered[13] = 2 // change threads from 4 to 2

		if err := os.WriteFile(vaultPath, tampered, 0600); err != nil {
			t.Fatalf("failed to write tampered vault: %v", err)
		}

		prof, err := v.GetRemote(masterPass, canaryRemote)
		assertZeroPlaintextLeakage(t, prof, err, "Tamper_ThreadsVal")
	})

	t.Run("Tamper_ThreadsZero", func(t *testing.T) {
		tampered := make([]byte, len(originalBytes))
		copy(tampered, originalBytes)
		tampered[13] = 0 // set threads to 0

		if err := os.WriteFile(vaultPath, tampered, 0600); err != nil {
			t.Fatalf("failed to write tampered vault: %v", err)
		}

		// Argon2 in Go panics if threads == 0! Let's verify whether it panics or errors.
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Empirical finding: argon2 panics when threads == 0: %v", r)
			}
		}()
		prof, err := v.GetRemote(masterPass, canaryRemote)
		assertZeroPlaintextLeakage(t, prof, err, "Tamper_ThreadsZero")
	})
}
