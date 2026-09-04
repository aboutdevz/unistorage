package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"

	"golang.org/x/crypto/argon2"
)

var (
	ErrRemoteNotFound  = errors.New("vault: remote profile not found")
	ErrInvalidPassword = errors.New("vault: authentication failed: invalid passphrase or corrupted vault")
	ErrCorruptedVault  = errors.New("vault: corrupted vault header or format")
)

const (
	VaultMagic       = "UNIS"
	VaultVersion     = byte(0x01)
	Argon2Time       = uint32(3)
	Argon2Memory     = uint32(64 * 1024) // 64 MiB in KiB
	Argon2Threads    = uint8(4)
	SaltLength       = 16
	NonceLength      = 12
	DerivedKeyLength = 32
	TagLength        = 16

	vaultMagic       = VaultMagic
	vaultVersion     = VaultVersion
	argon2Time       = Argon2Time
	argon2Memory     = Argon2Memory
	argon2Threads    = Argon2Threads
	saltLength       = SaltLength
	nonceLength      = NonceLength
	derivedKeyLength = DerivedKeyLength
)

// RemoteProfile holds configuration attributes and credentials for a backend remote.
type RemoteProfile struct {
	Name      string            `json:"name"`
	Type      string            `json:"type"` // "local", "s3"
	Endpoint  string            `json:"endpoint,omitempty"`
	Region    string            `json:"region,omitempty"`
	Bucket    string            `json:"bucket,omitempty"`
	AccessKey string            `json:"access_key,omitempty"`
	SecretKey string            `json:"secret_key,omitempty"`
	Path      string            `json:"path,omitempty"`
	Options   map[string]string `json:"options,omitempty"`
}

// Vault manages encrypted persistence of remote profiles.
type Vault interface {
	SaveRemote(passphrase string, profile RemoteProfile) error
	GetRemote(passphrase string, name string) (*RemoteProfile, error)
	ListRemotes(passphrase string) ([]string, error)
	DeleteRemote(passphrase string, name string) error
}

// MemZero wipes a sensitive byte buffer in memory, preventing heap residue.
func MemZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// FileVault implements Vault storing AES-256-GCM encrypted profiles on disk.
type FileVault struct {
	mu       sync.RWMutex
	filePath string
}

// New creates a FileVault at the specified path.
func New(filePath string) *FileVault {
	return &FileVault{filePath: filePath}
}

// DefaultVaultPath returns standard default ~/.unistorage/vault.enc location.
func DefaultVaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".unistorage", "vault.enc"), nil
}

// deriveKey computes an AES-256 key from passphrase and salt using Argon2id.
func deriveKey(passphrase []byte, salt []byte, time uint32, memory uint32, threads uint8) []byte {
	return argon2.IDKey(passphrase, salt, time, memory, threads, derivedKeyLength)
}

// loadStore decrypts and unmarshals the vault storage map.
func (v *FileVault) loadStore(passphrase []byte) (map[string]RemoteProfile, error) {
	data, err := os.ReadFile(v.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]RemoteProfile), nil
		}
		return nil, fmt.Errorf("failed to read vault file: %w", err)
	}

	if len(data) < 4+1+4+4+1+saltLength+nonceLength {
		return nil, ErrCorruptedVault
	}

	offset := 0
	// 1. Magic (4 bytes)
	if string(data[offset:offset+4]) != vaultMagic {
		return nil, ErrCorruptedVault
	}
	offset += 4

	// 2. Version (1 byte)
	ver := data[offset]
	if ver != vaultVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrCorruptedVault, ver)
	}
	offset++

	// 3. Argon2 parameters
	timeVal := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	memVal := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	threadsVal := data[offset]
	offset++

	// 4. Salt (16 bytes)
	salt := data[offset : offset+saltLength]
	offset += saltLength

	// 5. Nonce (12 bytes)
	nonce := data[offset : offset+nonceLength]
	offset += nonceLength

	// 6. Ciphertext + Tag
	ciphertext := data[offset:]

	// Derive key
	derivedKey := deriveKey(passphrase, salt, timeVal, memVal, threadsVal)
	defer MemZero(derivedKey)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("cipher init error: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm init error: %w", err)
	}

	// AAD is Magic (4 bytes) + Version (1 byte)
	aad := []byte(vaultMagic + string([]byte{vaultVersion}))

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrInvalidPassword
	}
	defer MemZero(plaintext)

	var store map[string]RemoteProfile
	if err := json.Unmarshal(plaintext, &store); err != nil {
		return nil, fmt.Errorf("failed to unmarshal decrypted vault data: %w", err)
	}

	return store, nil
}

// saveStore encrypts and writes the vault storage map to disk with 0600 permissions.
func (v *FileVault) saveStore(passphrase []byte, store map[string]RemoteProfile) error {
	// #nosec G117 -- plaintext remote profile is marshaled strictly to be encrypted by AES-256-GCM
	plaintext, err := json.Marshal(store)
	if err != nil {
		return fmt.Errorf("failed to marshal vault store: %w", err)
	}
	defer MemZero(plaintext)

	var salt [saltLength]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	var nonce [nonceLength]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	derivedKey := deriveKey(passphrase, salt[:], argon2Time, argon2Memory, argon2Threads)
	defer MemZero(derivedKey)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return fmt.Errorf("cipher init error: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gcm init error: %w", err)
	}

	aad := []byte(vaultMagic + string([]byte{vaultVersion}))
	ciphertext := gcm.Seal(nil, nonce[:], plaintext, aad)

	// Ensure parent directory exists
	dir := filepath.Dir(v.filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create vault directory: %w", err)
	}

	// Wire buffer: Magic(4) + Ver(1) + Time(4) + Mem(4) + Threads(1) + Salt(16) + Nonce(12) + Ciphertext(with tag)
	headerLen := 4 + 1 + 4 + 4 + 1 + saltLength + nonceLength
	totalLen := headerLen + len(ciphertext)
	payload := make([]byte, totalLen)

	idx := 0
	copy(payload[idx:idx+4], []byte(vaultMagic))
	idx += 4
	payload[idx] = vaultVersion
	idx++
	binary.BigEndian.PutUint32(payload[idx:idx+4], argon2Time)
	idx += 4
	binary.BigEndian.PutUint32(payload[idx:idx+4], argon2Memory)
	idx += 4
	payload[idx] = argon2Threads
	idx++
	copy(payload[idx:idx+saltLength], salt[:])
	idx += saltLength
	copy(payload[idx:idx+nonceLength], nonce[:])
	idx += nonceLength
	copy(payload[idx:], ciphertext)

	// Write atomically with 0600 permissions
	tmpFile := fmt.Sprintf("%s.tmp.%d", v.filePath, os.Getpid())
	if err := os.WriteFile(tmpFile, payload, 0600); err != nil {
		return fmt.Errorf("failed to write temp vault file: %w", err)
	}
	defer func() { _ = os.Remove(tmpFile) }()

	if err := os.Rename(tmpFile, v.filePath); err != nil {
		_ = os.Remove(v.filePath)
		if retryErr := os.Rename(tmpFile, v.filePath); retryErr != nil {
			return fmt.Errorf("atomic vault replacement failed: %w", retryErr)
		}
	}

	return nil
}

// SaveRemoteBytes saves or updates a remote profile in the vault using a mutable byte slice passphrase.
func (v *FileVault) SaveRemoteBytes(passphrase []byte, profile RemoteProfile) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	store, err := v.loadStore(passphrase)
	if err != nil {
		return err
	}

	store[profile.Name] = profile
	return v.saveStore(passphrase, store)
}

// SaveRemote saves or updates a remote profile in the vault.
func (v *FileVault) SaveRemote(passphrase string, profile RemoteProfile) error {
	pBytes := []byte(passphrase)
	defer MemZero(pBytes)
	return v.SaveRemoteBytes(pBytes, profile)
}

// GetRemoteBytes retrieves a profile by name from the encrypted vault using a mutable byte slice passphrase.
func (v *FileVault) GetRemoteBytes(passphrase []byte, name string) (*RemoteProfile, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	store, err := v.loadStore(passphrase)
	if err != nil {
		return nil, err
	}

	profile, ok := store[name]
	if !ok {
		return nil, ErrRemoteNotFound
	}

	res := profile
	return &res, nil
}

// GetRemote retrieves a profile by name from the encrypted vault.
func (v *FileVault) GetRemote(passphrase string, name string) (*RemoteProfile, error) {
	pBytes := []byte(passphrase)
	defer MemZero(pBytes)
	return v.GetRemoteBytes(pBytes, name)
}

// ListRemotes enumerates the names of all remote profiles in the vault.
func (v *FileVault) ListRemotes(passphrase string) ([]string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	pBytes := []byte(passphrase)
	defer MemZero(pBytes)

	store, err := v.loadStore(pBytes)
	if err != nil {
		return nil, err
	}

	var names []string
	for k := range store {
		names = append(names, k)
	}
	sort.Strings(names)
	return names, nil
}

// DeleteRemote removes a remote profile from the vault. Idempotent if missing.
func (v *FileVault) DeleteRemote(passphrase string, name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	pBytes := []byte(passphrase)
	defer MemZero(pBytes)

	store, err := v.loadStore(pBytes)
	if err != nil {
		return err
	}

	if _, ok := store[name]; !ok {
		return nil
	}

	delete(store, name)
	return v.saveStore(pBytes, store)
}

// Verify interface compliance
var _ Vault = (*FileVault)(nil)
