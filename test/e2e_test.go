package test

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"author/internal/relay"
	"author/pkg/client"
	"author/pkg/protocol"
)

func setupTestServer(t *testing.T) (*httptest.Server, *client.Client) {
	tempDir, err := os.MkdirTemp("", "author_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	dbPath := filepath.Join(tempDir, "test.db")
	srv, err := relay.NewServer(relay.Config{
		DBPath:  dbPath,
		Version: "test-0.1.0",
	})
	if err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close() })

	c := client.NewClient(ts.URL)
	return ts, c
}

func TestHealthCheck(t *testing.T) {
	_, c := setupTestServer(t)

	health, err := c.Health()
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	if health.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", health.Status)
	}
	if health.Version != "test-0.1.0" {
		t.Errorf("expected version 'test-0.1.0', got %q", health.Version)
	}
}

func TestClaimAndResolveLifecycle(t *testing.T) {
	_, c := setupTestServer(t)

	pub, priv, err := protocol.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	pubHex := protocol.PublicKeyToHex(pub)

	// 1. Claim Alice
	res, err := c.Claim("alice", priv)
	if err != nil {
		t.Fatalf("claim failed: %v", err)
	}
	if res.Username != "alice" {
		t.Errorf("expected username alice, got %q", res.Username)
	}
	if res.PubKey != pubHex {
		t.Errorf("expected pubkey %q, got %q", pubHex, res.PubKey)
	}
	if res.Status != protocol.StatusActive {
		t.Errorf("expected status active, got %q", res.Status)
	}
	if res.Version != 1 {
		t.Errorf("expected version 1, got %d", res.Version)
	}

	// 2. Resolve Alice
	resolved, err := c.Resolve("alice")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if resolved.PubKey != pubHex || resolved.Version != 1 {
		t.Errorf("resolve mismatch: got %+v", resolved)
	}

	// 3. Resolve non-existent user
	_, err = c.Resolve("nonexistent")
	if err == nil {
		t.Fatalf("expected error resolving nonexistent user, got nil")
	}

	// 4. Double claim should fail (Username collision)
	_, otherPriv, _ := protocol.GenerateKeyPair()
	_, err = c.Claim("alice", otherPriv)
	if err == nil {
		t.Fatalf("expected duplicate claim to fail, got nil")
	}
	if !strings.Contains(err.Error(), "already claimed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRotateLifecycle(t *testing.T) {
	_, c := setupTestServer(t)

	pub1, priv1, _ := protocol.GenerateKeyPair()
	pub1Hex := protocol.PublicKeyToHex(pub1)

	// Claim Bob
	resBob, err := c.Claim("bob", priv1)
	if err != nil {
		t.Fatalf("claim failed: %v", err)
	}
	if resBob.PubKey != pub1Hex {
		t.Fatalf("expected initial pubkey %s, got %s", pub1Hex, resBob.PubKey)
	}

	// Generate second key for Bob
	pub2, priv2, _ := protocol.GenerateKeyPair()
	pub2Hex := protocol.PublicKeyToHex(pub2)

	// Rotate Bob's key from v1 to v2
	err = c.Rotate("bob", priv1, priv2, 2)
	if err != nil {
		t.Fatalf("rotate failed: %v", err)
	}

	// Resolve Bob and verify key updated
	resolved, err := c.Resolve("bob")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if resolved.PubKey != pub2Hex {
		t.Errorf("expected new pubkey %s, got %s", pub2Hex, resolved.PubKey)
	}
	if resolved.Version != 2 {
		t.Errorf("expected version 2, got %d", resolved.Version)
	}

	// Try rotating again using the old key (priv1) -> should fail signature verification or current key mismatch
	_, priv3, _ := protocol.GenerateKeyPair()
	err = c.Rotate("bob", priv1, priv3, 3)
	if err == nil {
		t.Fatalf("expected rotation using revoked old key to fail, got nil")
	}

	// Rotate legitimately to v3 using priv2
	pub3Hex := protocol.PublicKeyToHex(priv3.Public().(ed25519.PublicKey))
	err = c.Rotate("bob", priv2, priv3, 3)
	if err != nil {
		t.Fatalf("rotate to v3 failed: %v", err)
	}

	resolved3, _ := c.Resolve("bob")
	if resolved3.PubKey != pub3Hex || resolved3.Version != 3 {
		t.Errorf("expected version 3, got %+v", resolved3)
	}
}

func TestRevocationLifecycle(t *testing.T) {
	_, c := setupTestServer(t)

	_, priv, _ := protocol.GenerateKeyPair()

	// Claim Charlie
	_, err := c.Claim("charlie", priv)
	if err != nil {
		t.Fatalf("claim failed: %v", err)
	}

	// Revoke Charlie
	err = c.Revoke("charlie", priv)
	if err != nil {
		t.Fatalf("revoke failed: %v", err)
	}

	// Resolve Charlie -> should be revoked
	resolved, err := c.Resolve("charlie")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if resolved.Status != protocol.StatusRevoked {
		t.Errorf("expected status revoked, got %q", resolved.Status)
	}

	// Attempting to rotate a revoked identity must fail
	_, newPriv, _ := protocol.GenerateKeyPair()
	err = c.Rotate("charlie", priv, newPriv, 2)
	if err == nil {
		t.Fatalf("expected rotate on revoked identity to fail, got nil")
	}

	// Attempting to re-claim a revoked username must fail
	_, err = c.Claim("charlie", newPriv)
	if err == nil {
		t.Fatalf("expected claim on revoked username to fail, got nil")
	}
}

func TestDeviceLimitEnforcement(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "author_keystore_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	ks, err := client.NewKeyStore(tempDir)
	if err != nil {
		t.Fatalf("failed to init keystore: %v", err)
	}

	// Save max allowed (3)
	users := []string{"user_one", "user_two", "user_three"}
	for _, u := range users {
		pub, priv, _ := protocol.GenerateKeyPair()
		err := ks.SaveNewIdentity(u, priv, protocol.PublicKeyToHex(pub))
		if err != nil {
			t.Fatalf("failed to save %q: %v", u, err)
		}
	}

	// 4th identity should hit device limit
	pub4, priv4, _ := protocol.GenerateKeyPair()
	err = ks.SaveNewIdentity("user_four", priv4, protocol.PublicKeyToHex(pub4))
	if err == nil {
		t.Fatalf("expected 4th identity to exceed device limit, got nil")
	}
	if !strings.Contains(err.Error(), "device identity limit reached") {
		t.Errorf("unexpected error: %v", err)
	}

	// List identities
	list, err := ks.ListIdentities()
	if err != nil {
		t.Fatalf("failed to list identities: %v", err)
	}
	if len(list) != 3 {
		t.Errorf("expected 3 identities, got %d", len(list))
	}
}

func TestMessagingQueueLifecycle(t *testing.T) {
	_, c := setupTestServer(t)

	// Claim Alice and Bob
	_, alicePriv, _ := protocol.GenerateKeyPair()
	_, err := c.Claim("alice", alicePriv)
	if err != nil {
		t.Fatalf("failed to claim alice: %v", err)
	}

	_, bobPriv, _ := protocol.GenerateKeyPair()
	_, err = c.Claim("bob", bobPriv)
	if err != nil {
		t.Fatalf("failed to claim bob: %v", err)
	}

	// Alice sends message to Bob
	secretPayload := "Hello Bob, this is a cryptographically signed message!"
	err = c.Send("alice", alicePriv, "bob", secretPayload)
	if err != nil {
		t.Fatalf("send message failed: %v", err)
	}

	// Eve tries to access Bob's inbox with Eve's key -> must fail signature check
	_, evePriv, _ := protocol.GenerateKeyPair()
	_, err = c.Inbox("bob", evePriv)
	if err == nil {
		t.Fatalf("expected unauthorized inbox access by Eve to fail, got nil")
	}

	// Bob checks his inbox
	messages, err := c.Inbox("bob", bobPriv)
	if err != nil {
		t.Fatalf("bob inbox failed: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message in bob's inbox, got %d", len(messages))
	}
	if messages[0].Sender != "alice" {
		t.Errorf("expected sender alice, got %s", messages[0].Sender)
	}
	if messages[0].Payload != secretPayload {
		t.Errorf("payload mismatch: expected %q, got %q", secretPayload, messages[0].Payload)
	}

	// Bob acknowledges message
	err = c.Ack("bob", bobPriv, []int64{messages[0].ID})
	if err != nil {
		t.Fatalf("ack failed: %v", err)
	}

	// Bob checks inbox again -> should be empty
	messagesAfter, err := c.Inbox("bob", bobPriv)
	if err != nil {
		t.Fatalf("bob inbox after ack failed: %v", err)
	}
	if len(messagesAfter) != 0 {
		t.Errorf("expected 0 messages after ack, got %d", len(messagesAfter))
	}
}

func TestSSEEventStream(t *testing.T) {
	tsServer, c := setupTestServer(t)

	_, davePriv, _ := protocol.GenerateKeyPair()
	_, err := c.Claim("dave", davePriv)
	if err != nil {
		t.Fatalf("claim dave failed: %v", err)
	}

	ts := protocol.CurrentUnix()
	nonce, _ := protocol.GenerateNonce(16)
	msg := protocol.FormatInboxPayload("dave", ts, nonce)
	sig := protocol.SignMessage(davePriv, msg)

	eventsURL := fmt.Sprintf("%s/v1/events?recipient=dave&ts=%d&nonce=%s&sig=%s", tsServer.URL, ts, nonce, sig)
	resp, err := http.Get(eventsURL)
	if err != nil {
		t.Fatalf("SSE request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("expected Content-Type text/event-stream, got %s", ct)
	}

	scanner := bufio.NewScanner(resp.Body)
	if scanner.Scan() {
		line := scanner.Text()
		if line != "event: connected" {
			t.Errorf("expected 'event: connected', got %q", line)
		}
	}
}

func TestEndToEndEncryption(t *testing.T) {
	_, c := setupTestServer(t)

	_, alicePriv, _ := protocol.GenerateKeyPair()
	_, err := c.Claim("alice", alicePriv)
	if err != nil {
		t.Fatalf("claim alice failed: %v", err)
	}

	bobPub, bobPriv, _ := protocol.GenerateKeyPair()
	bobPubHex := protocol.PublicKeyToHex(bobPub)
	_, err = c.Claim("bob", bobPriv)
	if err != nil {
		t.Fatalf("claim bob failed: %v", err)
	}

	secretPlaintext := "Super-secret Zero-Knowledge message: X25519 nacl.box verified!"

	// Alice encrypts for Bob
	env, err := protocol.EncryptMessage(bobPubHex, secretPlaintext, "alice")
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	envJSON, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Alice sends to relay
	if err := c.Send("alice", alicePriv, "bob", string(envJSON)); err != nil {
		t.Fatalf("send failed: %v", err)
	}

	// Bob pulls inbox from relay
	messages, err := c.Inbox("bob", bobPriv)
	if err != nil {
		t.Fatalf("inbox failed: %v", err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}

	rawRelayPayload := messages[0].Payload

	// CRITICAL ZERO-KNOWLEDGE ASSERTION:
	// The relay stored payload MUST NOT contain the plaintext!
	if strings.Contains(rawRelayPayload, secretPlaintext) {
		t.Fatalf("Zero-knowledge breach! Raw relay payload contains plaintext: %s", rawRelayPayload)
	}

	// Bob parses and decrypts
	receivedEnv, ok := protocol.ParseEncryptedEnvelope(rawRelayPayload)
	if !ok {
		t.Fatalf("failed to parse encrypted envelope from relay payload: %s", rawRelayPayload)
	}

	decrypted, err := protocol.DecryptMessage(bobPriv, receivedEnv)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if decrypted != secretPlaintext {
		t.Fatalf("plaintext mismatch! got %q, want %q", decrypted, secretPlaintext)
	}

	// Verify Alice CANNOT decrypt (only Bob's private key can open it)
	_, err = protocol.DecryptMessage(alicePriv, receivedEnv)
	if err == nil {
		t.Fatal("expected decryption to fail with sender key, but it succeeded")
	}
}

func TestBlindedHandlePrivacyAndWoT(t *testing.T) {
	server, _ := setupTestServer(t)

	// 1. Generate identity for Alice
	alicePub, alicePriv, _ := protocol.GenerateKeyPair()
	aliceHex := protocol.PublicKeyToHex(alicePub)

	// Compute blind handle token for "alice_secret"
	handleToken := protocol.DeriveHandleToken("alice_secret")
	ts := time.Now().Unix()
	nonce, _ := protocol.GenerateNonce(16)

	// Format claim using blinded handle token
	msg := protocol.FormatClaimPayload(handleToken, aliceHex, ts, nonce)
	sig := protocol.SignMessage(alicePriv, msg)

	claimReq := protocol.ClaimRequest{
		Username:  handleToken,
		PubKey:    aliceHex,
		Timestamp: ts,
		Nonce:     nonce,
		Sig:       sig,
	}

	body, _ := json.Marshal(claimReq)
	resp, err := http.Post(server.URL+"/v1/claim", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 Created for blinded claim, got: %v (err: %v)", resp.StatusCode, err)
	}

	// 2. Resolve by blinded token
	resolveResp, err := http.Get(server.URL + "/v1/resolve/" + handleToken)
	if err != nil || resolveResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK resolving by blinded token, got: %v", resolveResp.StatusCode)
	}

	var resData protocol.ResolveResponse
	json.NewDecoder(resolveResp.Body).Decode(&resData)
	if resData.PubKey != aliceHex {
		t.Fatalf("expected resolved pubkey %s, got %s", aliceHex, resData.PubKey)
	}

	// 3. Resolve by plaintext alias (fallback support)
	resolvePlainResp, err := http.Get(server.URL + "/v1/resolve/alice_secret")
	if err != nil || resolvePlainResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK resolving by plaintext alias, got: %v", resolvePlainResp.StatusCode)
	}

	// 4. Test Web of Trust Peer Attestation
	bobPub, bobPriv, _ := protocol.GenerateKeyPair()
	bobHex := protocol.PublicKeyToHex(bobPub)

	// Alice signs an attestation vouching for Bob (Level 2 = Direct In-Person)
	attestation, err := protocol.SignAttestation(alicePriv, aliceHex, bobHex, protocol.TrustLevelDirect, ts)
	if err != nil {
		t.Fatalf("failed to sign WoT attestation: %v", err)
	}

	if err := protocol.VerifyAttestation(attestation); err != nil {
		t.Fatalf("attestation verification failed: %v", err)
	}

	// Bob signs an attestation vouching for Charlie (Level 1 = Mutual/Transitive)
	charliePub, _, _ := protocol.GenerateKeyPair()
	charlieHex := protocol.PublicKeyToHex(charliePub)

	charlieAtt, err := protocol.SignAttestation(bobPriv, bobHex, charlieHex, protocol.TrustLevelVouched, ts)
	if err != nil {
		t.Fatalf("failed to sign transitive attestation: %v", err)
	}

	if err := protocol.VerifyAttestation(charlieAtt); err != nil {
		t.Fatalf("charlie attestation verification failed: %v", err)
	}
}

