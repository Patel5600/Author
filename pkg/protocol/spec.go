package protocol

import "time"

// Action represents identity state modification events.
type Action string

const (
	ActionClaim  Action = "CLAIM"
	ActionRotate Action = "ROTATE"
	ActionRevoke Action = "REVOKE"
	ActionSend   Action = "SEND"
	ActionInbox  Action = "INBOX"
	ActionAck    Action = "ACK"
)

// IdentityStatus represents the lifecycle state of a registered identity.
type IdentityStatus string

const (
	StatusActive  IdentityStatus = "active"
	StatusRevoked IdentityStatus = "revoked"
)

const (
	// MaxTimestampDriftSeconds is the allowed clock drift window (5 minutes).
	MaxTimestampDriftSeconds = 300
	// ProtocolPrefix is the domain separation prefix used for canonical signing payloads.
	ProtocolPrefix = "author-id:v1"
	// HandlePrefix is the domain separation prefix for blind handle tokens.
	HandlePrefix = "author-handle:v1"
	// WoTPrefix is the domain separation prefix for Web of Trust attestations.
	WoTPrefix = "author-wot:v1"
	// MaxIdentitiesPerDevice is the default client policy cap.
	MaxIdentitiesPerDevice = 3
)

// TrustLevel defines confidence in an identity attestation.
type TrustLevel uint8

const (
	TrustLevelStranger TrustLevel = 0 // Unvouched
	TrustLevelVouched  TrustLevel = 1 // Mutual / transitive vouch
	TrustLevelDirect   TrustLevel = 2 // Verified in-person (QR / direct exchange)
)

// TrustAttestation represents a cryptographic peer endorsement in the Web of Trust.
type TrustAttestation struct {
	IssuerPub  string     `json:"issuer_pub"`  // Ed25519 public key of endorser
	SubjectPub string     `json:"subject_pub"` // Ed25519 public key of endorsed party
	Level      TrustLevel `json:"level"`       // Confidence level (1=Vouched, 2=Direct)
	Timestamp  int64      `json:"timestamp"`   // Unix timestamp in seconds
	Sig        string     `json:"sig"`         // Detached Ed25519 signature by issuer_pub
}

// ClaimRequest is submitted to POST /v1/claim.
type ClaimRequest struct {
	Username  string `json:"username"`
	PubKey    string `json:"pubkey"`    // Hex-encoded 32-byte Ed25519 public key
	Timestamp int64  `json:"timestamp"` // Unix timestamp in seconds
	Nonce     string `json:"nonce"`     // Cryptographic random hex string (min 16 chars)
	Sig       string `json:"sig"`       // Hex-encoded 64-byte Ed25519 signature
}

// RotateRequest is submitted to POST /v1/rotate.
type RotateRequest struct {
	Username  string `json:"username"`
	OldPubKey string `json:"old_pubkey"` // Hex-encoded current public key
	NewPubKey string `json:"new_pubkey"` // Hex-encoded new public key
	Version   int64  `json:"version"`    // Target version (must equal current version + 1)
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Sig       string `json:"sig"`               // Signed by old_pubkey's private key
	NewSig    string `json:"new_sig,omitempty"` // Optional dual-signature by new_pubkey
}

// RevokeRequest is submitted to POST /v1/revoke.
type RevokeRequest struct {
	Username  string `json:"username"`
	PubKey    string `json:"pubkey"` // Hex-encoded currently active public key
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Sig       string `json:"sig"` // Signed by active private key
}

// ResolveResponse is returned by GET /v1/resolve/{user}.
type ResolveResponse struct {
	Username  string         `json:"username"`
	PubKey    string         `json:"pubkey"`
	Status    IdentityStatus `json:"status"`
	Version   int64          `json:"version"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// ApiResponse represents standard JSON responses for mutations.
type ApiResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
	Error   string `json:"error,omitempty"`
}

// HealthResponse is returned by GET /health.
type HealthResponse struct {
	Status        string `json:"status"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	TotalClaims   int64  `json:"total_claims"`
	Version       string `json:"version"`
}

// SendMessageRequest is submitted to POST /v1/send.
type SendMessageRequest struct {
	Recipient string `json:"recipient"` // Target username
	Sender    string `json:"sender"`    // Sender username
	Payload   string `json:"payload"`   // Encrypted payload string (ciphertext/envelope)
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Sig       string `json:"sig"` // Signed by sender's private key
}

// QueuedMessage represents an encrypted message waiting in relay queue.
type QueuedMessage struct {
	ID        int64  `json:"id"`
	Sender    string `json:"sender"`
	Payload   string `json:"payload"`
	Timestamp int64  `json:"timestamp"`
}

// InboxRequest is submitted to POST /v1/inbox to authenticate and fetch messages.
type InboxRequest struct {
	Recipient string `json:"recipient"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
	Sig       string `json:"sig"` // Signed by recipient's private key
}

// InboxResponse returns the list of queued messages.
type InboxResponse struct {
	Messages []QueuedMessage `json:"messages"`
}

// AckRequest is submitted to POST /v1/ack to delete delivered messages.
type AckRequest struct {
	Recipient  string  `json:"recipient"`
	MessageIDs []int64 `json:"message_ids"`
	Timestamp  int64   `json:"timestamp"`
	Nonce      string  `json:"nonce"`
	Sig        string  `json:"sig"` // Signed by recipient's private key
}
