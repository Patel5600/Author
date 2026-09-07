package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

var (
	ErrInvalidPubKeyLength = errors.New("public key must be 32 bytes (64 hex characters)")
	ErrInvalidPrivKeyLength = errors.New("private key must be 64 bytes (128 hex characters)")
	ErrInvalidSigLength     = errors.New("signature must be 64 bytes (128 hex characters)")
	ErrSignatureMismatch    = errors.New("cryptographic signature verification failed")
)

// GenerateKeyPair generates a cryptographically secure Ed25519 keypair.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ed25519 keypair: %w", err)
	}
	return pub, priv, nil
}

// GenerateNonce creates a cryptographically secure random hex string.
func GenerateNonce(byteLen int) (string, error) {
	if byteLen <= 0 {
		byteLen = 16
	}
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to read secure random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// FormatClaimPayload produces the canonical string representation for CLAIM events.
func FormatClaimPayload(username, pubKeyHex string, timestamp int64, nonce string) string {
	return fmt.Sprintf("%s:%s:%s:%s:%d:%s", ProtocolPrefix, ActionClaim, username, pubKeyHex, timestamp, nonce)
}

// FormatRotatePayload produces the canonical string representation for ROTATE events.
func FormatRotatePayload(username, oldPubKeyHex, newPubKeyHex string, version int64, timestamp int64, nonce string) string {
	return fmt.Sprintf("%s:%s:%s:%s:%s:%d:%d:%s", ProtocolPrefix, ActionRotate, username, oldPubKeyHex, newPubKeyHex, version, timestamp, nonce)
}

// FormatRevokePayload produces the canonical string representation for REVOKE events.
func FormatRevokePayload(username, pubKeyHex string, timestamp int64, nonce string) string {
	return fmt.Sprintf("%s:%s:%s:%s:%d:%s", ProtocolPrefix, ActionRevoke, username, pubKeyHex, timestamp, nonce)
}

// Sha256Hex computes the hex-encoded SHA-256 digest of arbitrary string data.
func Sha256Hex(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// FormatSendPayload produces the canonical string representation for SEND events.
func FormatSendPayload(recipient, sender, payloadSha256 string, timestamp int64, nonce string) string {
	return fmt.Sprintf("%s:%s:%s:%s:%s:%d:%s", ProtocolPrefix, ActionSend, recipient, sender, payloadSha256, timestamp, nonce)
}

// FormatInboxPayload produces the canonical string representation for INBOX challenge responses.
func FormatInboxPayload(recipient string, timestamp int64, nonce string) string {
	return fmt.Sprintf("%s:%s:%s:%d:%s", ProtocolPrefix, ActionInbox, recipient, timestamp, nonce)
}

// FormatAckPayload produces the canonical string representation for message delivery ACK events.
func FormatAckPayload(recipient string, idsSummary string, timestamp int64, nonce string) string {
	return fmt.Sprintf("%s:%s:%s:%s:%d:%s", ProtocolPrefix, ActionAck, recipient, idsSummary, timestamp, nonce)
}

// SignMessage signs an arbitrary message using the Ed25519 private key, returning a hex-encoded signature.
func SignMessage(privKey ed25519.PrivateKey, message string) string {
	sig := ed25519.Sign(privKey, []byte(message))
	return hex.EncodeToString(sig)
}

// VerifySignature verifies a hex-encoded signature against a hex-encoded public key and message.
func VerifySignature(pubKeyHex, message, sigHex string) error {
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return ErrInvalidPubKeyLength
	}

	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return ErrInvalidSigLength
	}

	if !ed25519.Verify(pubKeyBytes, []byte(message), sigBytes) {
		return ErrSignatureMismatch
	}

	return nil
}

// PublicKeyToHex converts an Ed25519 public key to lowercase hex string.
func PublicKeyToHex(pubKey ed25519.PublicKey) string {
	return hex.EncodeToString(pubKey)
}

// PrivateKeyToHex converts an Ed25519 private key to lowercase hex string.
func PrivateKeyToHex(privKey ed25519.PrivateKey) string {
	return hex.EncodeToString(privKey)
}

// HexToPublicKey decodes a 64-char hex string into an Ed25519 public key.
func HexToPublicKey(pubKeyHex string) (ed25519.PublicKey, error) {
	bytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex encoding: %w", err)
	}
	if len(bytes) != ed25519.PublicKeySize {
		return nil, ErrInvalidPubKeyLength
	}
	return ed25519.PublicKey(bytes), nil
}

// HexToPrivateKey decodes a 128-char hex string into an Ed25519 private key.
func HexToPrivateKey(privKeyHex string) (ed25519.PrivateKey, error) {
	bytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex encoding: %w", err)
	}
	if len(bytes) != ed25519.PrivateKeySize {
		return nil, ErrInvalidPrivKeyLength
	}
	return ed25519.PrivateKey(bytes), nil
}
