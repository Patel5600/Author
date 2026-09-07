package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestE2EEEncryptionCycle(t *testing.T) {
	// Generate Bob's recipient Ed25519 identity key
	bobPub, bobPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Bob's key: %v", err)
	}
	bobPubHex := hex.EncodeToString(bobPub)

	originalMessage := "Secret cryptographic payload: Alice ➔ Bob"

	// Alice encrypts for Bob
	env, err := EncryptMessage(bobPubHex, originalMessage, "alice")
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if env.Alg != E2EEAlgorithm {
		t.Fatalf("Unexpected algorithm: %s", env.Alg)
	}

	// Verify Bob can decrypt
	decrypted, err := DecryptMessage(bobPriv, env)
	if err != nil {
		t.Fatalf("Bob failed to decrypt: %v", err)
	}

	if decrypted != originalMessage {
		t.Fatalf("Decrypted message mismatch. Got %q, want %q", decrypted, originalMessage)
	}

	// Verify Charlie (wrong key) CANNOT decrypt
	_, charliePriv, _ := ed25519.GenerateKey(rand.Reader)
	_, err = DecryptMessage(charliePriv, env)
	if err == nil {
		t.Fatal("Expected decryption to fail with wrong private key, but it succeeded!")
	}

	// Verify tampering with ciphertext fails authentication
	tamperedBytes, _ := hex.DecodeString(env.Ciphertext)
	tamperedBytes[len(tamperedBytes)-1] ^= 0xFF
	env.Ciphertext = hex.EncodeToString(tamperedBytes)
	_, err = DecryptMessage(bobPriv, env)
	if err == nil {
		t.Fatal("Expected decryption to fail with tampered ciphertext, but it succeeded!")
	}
}
