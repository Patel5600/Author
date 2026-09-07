package client

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"author/pkg/protocol"
)

var (
	ErrDeviceLimitReached = fmt.Errorf("device identity limit reached (max %d identities allowed)", protocol.MaxIdentitiesPerDevice)
	ErrKeyNotFound        = errors.New("private key not found for identity")
)

type LocalIdentity struct {
	Username  string                  `json:"username"`
	PubKey    string                  `json:"pubkey"`
	Status    protocol.IdentityStatus `json:"status"`
	Version   int64                   `json:"version"`
	CreatedAt time.Time               `json:"created_at"`
	UpdatedAt time.Time               `json:"updated_at"`
}

type IdentityRegistry struct {
	Identities []LocalIdentity `json:"identities"`
}

type KeyStore struct {
	baseDir  string
	keysDir  string
	regFile  string
}

func DefaultKeyStoreDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".author"), nil
}

func NewKeyStore(baseDir string) (*KeyStore, error) {
	if baseDir == "" {
		var err error
		baseDir, err = DefaultKeyStoreDir()
		if err != nil {
			return nil, err
		}
	}

	keysDir := filepath.Join(baseDir, "keys")
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create keystore directories: %w", err)
	}

	return &KeyStore{
		baseDir: baseDir,
		keysDir: keysDir,
		regFile: filepath.Join(baseDir, "identities.json"),
	}, nil
}

func (ks *KeyStore) loadRegistry() (*IdentityRegistry, error) {
	if _, err := os.Stat(ks.regFile); os.IsNotExist(err) {
		return &IdentityRegistry{Identities: []LocalIdentity{}}, nil
	}

	data, err := os.ReadFile(ks.regFile)
	if err != nil {
		return nil, err
	}

	var reg IdentityRegistry
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, err
	}
	return &reg, nil
}

func (ks *KeyStore) saveRegistry(reg *IdentityRegistry) error {
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ks.regFile, data, 0600)
}

func (ks *KeyStore) keyPath(username string) string {
	return filepath.Join(ks.keysDir, fmt.Sprintf("%s.key", username))
}

// ListIdentities returns all locally stored profiles.
func (ks *KeyStore) ListIdentities() ([]LocalIdentity, error) {
	reg, err := ks.loadRegistry()
	if err != nil {
		return nil, err
	}
	return reg.Identities, nil
}

// GetKey retrieves the private key for a given username.
func (ks *KeyStore) GetKey(username string) (ed25519.PrivateKey, error) {
	username = strings.ToLower(username)
	path := ks.keyPath(username)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	privHex := strings.TrimSpace(string(data))
	return protocol.HexToPrivateKey(privHex)
}

// SaveNewIdentity stores the private key and registers the identity profile (enforcing limit).
func (ks *KeyStore) SaveNewIdentity(username string, privKey ed25519.PrivateKey, pubKeyHex string) error {
	username = strings.ToLower(username)
	reg, err := ks.loadRegistry()
	if err != nil {
		return err
	}

	for _, id := range reg.Identities {
		if id.Username == username {
			return fmt.Errorf("identity %q already exists locally", username)
		}
	}

	if len(reg.Identities) >= protocol.MaxIdentitiesPerDevice {
		return ErrDeviceLimitReached
	}

	// Write private key
	privHex := protocol.PrivateKeyToHex(privKey)
	if err := os.WriteFile(ks.keyPath(username), []byte(privHex), 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	now := time.Now().UTC()
	reg.Identities = append(reg.Identities, LocalIdentity{
		Username:  username,
		PubKey:    pubKeyHex,
		Status:    protocol.StatusActive,
		Version:   1,
		CreatedAt: now,
		UpdatedAt: now,
	})

	return ks.saveRegistry(reg)
}

// UpdateIdentityKey replaces the private key and updates version & pubkey.
func (ks *KeyStore) UpdateIdentityKey(username string, newPrivKey ed25519.PrivateKey, newPubKeyHex string, newVersion int64) error {
	username = strings.ToLower(username)
	reg, err := ks.loadRegistry()
	if err != nil {
		return err
	}

	found := false
	for i, id := range reg.Identities {
		if id.Username == username {
			reg.Identities[i].PubKey = newPubKeyHex
			reg.Identities[i].Version = newVersion
			reg.Identities[i].UpdatedAt = time.Now().UTC()
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("identity %q not found locally", username)
	}

	// Overwrite key file
	privHex := protocol.PrivateKeyToHex(newPrivKey)
	if err := os.WriteFile(ks.keyPath(username), []byte(privHex), 0600); err != nil {
		return fmt.Errorf("failed to update key file: %w", err)
	}

	return ks.saveRegistry(reg)
}

// MarkRevoked marks the local identity status as revoked.
func (ks *KeyStore) MarkRevoked(username string) error {
	username = strings.ToLower(username)
	reg, err := ks.loadRegistry()
	if err != nil {
		return err
	}

	found := false
	for i, id := range reg.Identities {
		if id.Username == username {
			reg.Identities[i].Status = protocol.StatusRevoked
			reg.Identities[i].UpdatedAt = time.Now().UTC()
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("identity %q not found locally", username)
	}

	return ks.saveRegistry(reg)
}
