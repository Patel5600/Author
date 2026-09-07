package protocol

import (
	"testing"
	"time"
)

func TestUsernameValidation(t *testing.T) {
	valid := []string{"alice", "bob_123", "charlie_dev", "a12", "a123456789b123456789c123456789d1"}
	for _, u := range valid {
		if err := ValidateUsername(u); err != nil {
			t.Errorf("expected valid username %q, got error: %v", u, err)
		}
	}

	invalid := []struct {
		name string
		err  error
	}{
		{"", ErrUsernameTooShort},
		{"ab", ErrUsernameTooShort},
		{"toolongusernameexceedingthemaximumallowedlengthofthirtytwocharacters", ErrUsernameTooLong},
		{"alice!", ErrUsernameInvalidChar},
		{"alice-bob", ErrUsernameInvalidChar},
		{"Alice", ErrUsernameInvalidChar},
		{"admin", ErrUsernameReserved},
		{"root", ErrUsernameReserved},
		{"relay", ErrUsernameReserved},
	}

	for _, tc := range invalid {
		if err := ValidateUsername(tc.name); err == nil {
			t.Errorf("expected error for %q, got nil", tc.name)
		}
	}
}

func TestTimestampDrift(t *testing.T) {
	now := time.Now().Unix()
	if err := ValidateTimestamp(now, now, 300); err != nil {
		t.Fatalf("expected 0 drift to pass, got: %v", err)
	}
	if err := ValidateTimestamp(now-100, now, 300); err != nil {
		t.Fatalf("expected 100s past to pass, got: %v", err)
	}
	if err := ValidateTimestamp(now+100, now, 300); err != nil {
		t.Fatalf("expected 100s future to pass, got: %v", err)
	}
	if err := ValidateTimestamp(now-301, now, 300); err == nil {
		t.Fatalf("expected 301s drift to fail")
	}
}

func TestSignatureCycle(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pubHex := PublicKeyToHex(pub)
	nonce, _ := GenerateNonce(16)
	ts := time.Now().Unix()

	// CLAIM
	claimMsg := FormatClaimPayload("alice", pubHex, ts, nonce)
	sig := SignMessage(priv, claimMsg)

	if err := VerifySignature(pubHex, claimMsg, sig); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}

	// Corrupt signature
	corruptSig := sig[:len(sig)-2] + "00"
	if err := VerifySignature(pubHex, claimMsg, corruptSig); err == nil {
		t.Fatalf("expected corrupted signature to fail verification")
	}

	// Corrupt message
	tamperedMsg := FormatClaimPayload("eve", pubHex, ts, nonce)
	if err := VerifySignature(pubHex, tamperedMsg, sig); err == nil {
		t.Fatalf("expected tampered message to fail verification")
	}
}
