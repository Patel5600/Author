package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/nacl/box"
)

const (
	E2EEAlgorithm = "x25519-xsalsa20-poly1305"
	E2EEVersion   = 1
)

// EncryptedEnvelope is the canonical Zero-Knowledge message structure.
// The relay server and database only ever store and route this ciphertext.
type EncryptedEnvelope struct {
	Version    int    `json:"v"`
	Alg        string `json:"alg"`
	EphemPub   string `json:"ephem_pub"`  // Hex 32-byte ephemeral X25519 public key
	Nonce      string `json:"nonce"`      // Hex 24-byte random nonce
	Ciphertext string `json:"ciphertext"` // Hex authenticated ciphertext
	Sender     string `json:"sender,omitempty"`
}

// Ed25519PublicKeyToCurve25519 maps an Ed25519 public key point (x, y) on Twisted Edwards
// to an X25519 (Curve25519) Montgomery u-coordinate via birational equivalence:
// u = (1 + y) / (1 - y) mod (2^255 - 19)
func Ed25519PublicKeyToCurve25519(edPub []byte) ([]byte, error) {
	if len(edPub) != 32 {
		return nil, errors.New("invalid ed25519 public key length")
	}

	// Copy and clear the sign bit (bit 255)
	yBytes := make([]byte, 32)
	copy(yBytes, edPub)
	yBytes[31] &= 0x7F

	// Reverse to big-endian for math/big
	revY := make([]byte, 32)
	for i := 0; i < 32; i++ {
		revY[i] = yBytes[31-i]
	}
	y := new(big.Int).SetBytes(revY)

	// Field modulus: 2^255 - 19
	two := big.NewInt(2)
	p := new(big.Int).Exp(two, big.NewInt(255), nil)
	p.Sub(p, big.NewInt(19))

	one := big.NewInt(1)

	// num = (1 + y) mod p
	num := new(big.Int).Add(one, y)
	num.Mod(num, p)

	// den = (1 - y) mod p
	den := new(big.Int).Sub(one, y)
	den.Mod(den, p)

	// invDen = (1 - y)^-1 mod p
	invDen := new(big.Int).ModInverse(den, p)
	if invDen == nil {
		return nil, errors.New("cannot invert denominator for curve conversion")
	}

	// u = (num * invDen) mod p
	u := new(big.Int).Mul(num, invDen)
	u.Mod(u, p)

	uBytes := u.Bytes()
	out := make([]byte, 32)
	for i, b := range uBytes {
		out[len(uBytes)-1-i] = b
	}
	return out, nil
}

// Ed25519PrivateKeyToCurve25519 derives the X25519 private scalar by taking the SHA-512
// digest of the 32-byte Ed25519 seed and clamping the lower 32 bytes (standard RFC 8032 / libsodium).
func Ed25519PrivateKeyToCurve25519(edPriv ed25519.PrivateKey) []byte {
	seed := edPriv.Seed()
	h := sha512.Sum512(seed)
	s := make([]byte, 32)
	copy(s, h[:32])
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
	return s
}

// EncryptMessage generates a fresh ephemeral X25519 key pair, performs Diffie-Hellman
// key exchange with the recipient's derived X25519 public key, and returns an EncryptedEnvelope.
func EncryptMessage(recipientEdPubHex string, plaintext string, senderHandle string) (*EncryptedEnvelope, error) {
	recipientEdPubHex = strings.TrimSpace(recipientEdPubHex)
	recipEdBytes, err := hex.DecodeString(recipientEdPubHex)
	if err != nil || len(recipEdBytes) != 32 {
		return nil, fmt.Errorf("invalid recipient ed25519 public key hex: %w", err)
	}

	recipXPubBytes, err := Ed25519PublicKeyToCurve25519(recipEdBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to derive recipient curve25519 public key: %w", err)
	}

	var recipXPub [32]byte
	copy(recipXPub[:], recipXPubBytes)

	// Generate fresh ephemeral keypair for Perfect Forward Secrecy
	ephemPub, ephemPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral keypair: %w", err)
	}

	// Generate random 24-byte nonce
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}

	// Encrypt using NaCl box (XSalsa20-Poly1305)
	ciphertext := box.Seal(nil, []byte(plaintext), &nonce, &recipXPub, ephemPriv)

	return &EncryptedEnvelope{
		Version:    E2EEVersion,
		Alg:        E2EEAlgorithm,
		EphemPub:   hex.EncodeToString(ephemPub[:]),
		Nonce:      hex.EncodeToString(nonce[:]),
		Ciphertext: hex.EncodeToString(ciphertext),
		Sender:     senderHandle,
	}, nil
}

// DecryptMessage decrypts an EncryptedEnvelope using the recipient's Ed25519 private key.
func DecryptMessage(recipientEdPriv ed25519.PrivateKey, env *EncryptedEnvelope) (string, error) {
	if env.Alg != E2EEAlgorithm {
		return "", fmt.Errorf("unsupported encryption algorithm: %s", env.Alg)
	}

	ephemPubBytes, err := hex.DecodeString(env.EphemPub)
	if err != nil || len(ephemPubBytes) != 32 {
		return "", errors.New("invalid ephemeral public key hex")
	}

	nonceBytes, err := hex.DecodeString(env.Nonce)
	if err != nil || len(nonceBytes) != 24 {
		return "", errors.New("invalid nonce hex (must be 24 bytes)")
	}

	ciphertextBytes, err := hex.DecodeString(env.Ciphertext)
	if err != nil {
		return "", errors.New("invalid ciphertext hex")
	}

	// Derive recipient's X25519 private key
	xPrivBytes := Ed25519PrivateKeyToCurve25519(recipientEdPriv)
	var myXPriv [32]byte
	copy(myXPriv[:], xPrivBytes)

	var ephemPub [32]byte
	copy(ephemPub[:], ephemPubBytes)

	var nonce [24]byte
	copy(nonce[:], nonceBytes)

	plaintext, ok := box.Open(nil, ciphertextBytes, &nonce, &ephemPub, &myXPriv)
	if !ok {
		return "", errors.New("decryption failed: invalid ciphertext, wrong recipient key, or corrupted data")
	}

	return string(plaintext), nil
}

// ParseEncryptedEnvelope attempts to parse a raw payload string into an EncryptedEnvelope.
func ParseEncryptedEnvelope(payload string) (*EncryptedEnvelope, bool) {
	payload = strings.TrimSpace(payload)
	if !strings.HasPrefix(payload, "{") || !strings.Contains(payload, E2EEAlgorithm) {
		return nil, false
	}

	var env EncryptedEnvelope
	if err := json.Unmarshal([]byte(payload), &env); err != nil {
		return nil, false
	}
	if env.Alg == E2EEAlgorithm && env.EphemPub != "" && env.Nonce != "" && env.Ciphertext != "" {
		return &env, true
	}
	return nil, false
}
