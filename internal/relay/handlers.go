package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"author/pkg/protocol"
)

type Handler struct {
	store        *Store
	broker       *Broker
	startTime    time.Time
	version      string
	claimLimiter *RateLimiter
}

func NewHandler(store *Store, broker *Broker, version string) *Handler {
	if broker == nil {
		broker = NewBroker()
	}
	return &Handler{
		store:        store,
		broker:       broker,
		startTime:    time.Now().UTC(),
		version:      version,
		claimLimiter: NewRateLimiter(20, time.Minute), // 20 claims per min per IP
	}
}

func (h *Handler) respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *Handler) respondError(w http.ResponseWriter, status int, message string) {
	h.respondJSON(w, status, protocol.ApiResponse{
		Success: false,
		Error:   message,
	})
}

// Health checks relay status and active claims.
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	totalClaims, err := h.store.CountIdentities()
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, "Failed to query database")
		return
	}

	uptime := int64(time.Since(h.startTime).Seconds())
	h.respondJSON(w, http.StatusOK, protocol.HealthResponse{
		Status:        "ok",
		UptimeSeconds: uptime,
		TotalClaims:   totalClaims,
		Version:       h.version,
	})
}

// HandleClaim registers a new identity.
func (h *Handler) HandleClaim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	clientIP := GetClientIP(r)
	if !h.claimLimiter.Allow(clientIP) {
		h.respondError(w, http.StatusTooManyRequests, "Rate limit exceeded for claims")
		return
	}

	var req protocol.ClaimRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}

	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	req.PubKey = strings.ToLower(strings.TrimSpace(req.PubKey))

	if err := protocol.ValidateUsername(req.Username); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	serverNow := protocol.CurrentUnix()
	if err := protocol.ValidateTimestamp(req.Timestamp, serverNow, protocol.MaxTimestampDriftSeconds); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := protocol.ValidateNonce(req.Nonce); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Replay protection
	if err := h.store.CheckAndRecordNonce(req.Nonce, req.Timestamp); err != nil {
		h.respondError(w, http.StatusConflict, err.Error())
		return
	}

	// Verify cryptographic signature
	msg := protocol.FormatClaimPayload(req.Username, req.PubKey, req.Timestamp, req.Nonce)
	if err := protocol.VerifySignature(req.PubKey, msg, req.Sig); err != nil {
		h.respondError(w, http.StatusUnauthorized, "Cryptographic signature verification failed")
		return
	}

	// Persist claim in database
	if err := h.store.CreateIdentity(req.Username, req.PubKey, req.Timestamp); err != nil {
		if errors.Is(err, ErrIdentityExists) {
			h.respondError(w, http.StatusConflict, "Username is already claimed")
			return
		}
		h.respondError(w, http.StatusInternalServerError, "Database error creating identity")
		return
	}

	_ = h.store.LogAudit(req.Username, string(protocol.ActionClaim), "", req.PubKey, req.Sig, clientIP, req.Timestamp)

	h.respondJSON(w, http.StatusCreated, protocol.ApiResponse{
		Success: true,
		Message: "Identity successfully claimed",
		Data: map[string]any{
			"username": req.Username,
			"pubkey":   req.PubKey,
			"status":   protocol.StatusActive,
			"version":  1,
		},
	})
}

// HandleResolve fetches the current public key binding of a user.
func (h *Handler) HandleResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Extract username from URL path: /v1/resolve/{user}
	path := strings.TrimPrefix(r.URL.Path, "/v1/resolve/")
	username := strings.ToLower(strings.TrimSpace(path))
	if username == "" {
		h.respondError(w, http.StatusBadRequest, "Username is required in URL path")
		return
	}

	id, err := h.store.GetIdentity(username)
	if err != nil {
		if errors.Is(err, ErrIdentityNotFound) {
			h.respondError(w, http.StatusNotFound, "Identity not found")
			return
		}
		h.respondError(w, http.StatusInternalServerError, "Database error retrieving identity")
		return
	}

	h.respondJSON(w, http.StatusOK, protocol.ResolveResponse{
		Username:  id.Username,
		PubKey:    id.PubKey,
		Status:    id.Status,
		Version:   id.Version,
		CreatedAt: id.CreatedAt,
		UpdatedAt: id.UpdatedAt,
	})
}

// HandleRotate updates an existing identity's public key.
func (h *Handler) HandleRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req protocol.RotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}

	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	req.OldPubKey = strings.ToLower(strings.TrimSpace(req.OldPubKey))
	req.NewPubKey = strings.ToLower(strings.TrimSpace(req.NewPubKey))

	if err := protocol.ValidateUsername(req.Username); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	serverNow := protocol.CurrentUnix()
	if err := protocol.ValidateTimestamp(req.Timestamp, serverNow, protocol.MaxTimestampDriftSeconds); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := protocol.ValidateNonce(req.Nonce); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.OldPubKey == req.NewPubKey {
		h.respondError(w, http.StatusBadRequest, "New public key must be different from old public key")
		return
	}

	// Replay protection
	if err := h.store.CheckAndRecordNonce(req.Nonce, req.Timestamp); err != nil {
		h.respondError(w, http.StatusConflict, err.Error())
		return
	}

	// Verify old key signature
	msg := protocol.FormatRotatePayload(req.Username, req.OldPubKey, req.NewPubKey, req.Version, req.Timestamp, req.Nonce)
	if err := protocol.VerifySignature(req.OldPubKey, msg, req.Sig); err != nil {
		h.respondError(w, http.StatusUnauthorized, "Signature by current key failed verification")
		return
	}

	// Optional dual-signature verification by new key
	if req.NewSig != "" {
		if err := protocol.VerifySignature(req.NewPubKey, msg, req.NewSig); err != nil {
			h.respondError(w, http.StatusUnauthorized, "Dual-signature by new key failed verification")
			return
		}
	}

	// Update in database
	if err := h.store.RotateIdentity(req.Username, req.OldPubKey, req.NewPubKey, req.Version, req.Timestamp); err != nil {
		if errors.Is(err, ErrIdentityNotFound) {
			h.respondError(w, http.StatusNotFound, "Identity not found")
			return
		}
		if errors.Is(err, ErrIdentityRevoked) {
			h.respondError(w, http.StatusForbidden, "Cannot rotate key: identity is permanently revoked")
			return
		}
		if errors.Is(err, ErrVersionMismatch) {
			h.respondError(w, http.StatusConflict, "Version mismatch: outdated version specified")
			return
		}
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	clientIP := GetClientIP(r)
	_ = h.store.LogAudit(req.Username, string(protocol.ActionRotate), req.OldPubKey, req.NewPubKey, req.Sig, clientIP, req.Timestamp)

	h.respondJSON(w, http.StatusOK, protocol.ApiResponse{
		Success: true,
		Message: "Key rotation successful",
		Data: map[string]any{
			"username": req.Username,
			"pubkey":   req.NewPubKey,
			"version":  req.Version,
		},
	})
}

// HandleRevoke permanently marks an identity as revoked.
func (h *Handler) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req protocol.RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}

	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	req.PubKey = strings.ToLower(strings.TrimSpace(req.PubKey))

	if err := protocol.ValidateUsername(req.Username); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	serverNow := protocol.CurrentUnix()
	if err := protocol.ValidateTimestamp(req.Timestamp, serverNow, protocol.MaxTimestampDriftSeconds); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := protocol.ValidateNonce(req.Nonce); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Verify existence and key match
	id, err := h.store.GetIdentity(req.Username)
	if err != nil {
		if errors.Is(err, ErrIdentityNotFound) {
			h.respondError(w, http.StatusNotFound, "Identity not found")
			return
		}
		h.respondError(w, http.StatusInternalServerError, "Database error retrieving identity")
		return
	}

	if id.Status == protocol.StatusRevoked {
		h.respondError(w, http.StatusConflict, "Identity is already revoked")
		return
	}

	if id.PubKey != req.PubKey {
		h.respondError(w, http.StatusForbidden, "Public key mismatch with active identity")
		return
	}

	// Replay protection
	if err := h.store.CheckAndRecordNonce(req.Nonce, req.Timestamp); err != nil {
		h.respondError(w, http.StatusConflict, err.Error())
		return
	}

	// Verify signature
	msg := protocol.FormatRevokePayload(req.Username, req.PubKey, req.Timestamp, req.Nonce)
	if err := protocol.VerifySignature(req.PubKey, msg, req.Sig); err != nil {
		h.respondError(w, http.StatusUnauthorized, "Signature verification failed")
		return
	}

	// Revoke in database
	if err := h.store.RevokeIdentity(req.Username, req.Timestamp); err != nil {
		h.respondError(w, http.StatusInternalServerError, "Failed to revoke identity")
		return
	}

	clientIP := GetClientIP(r)
	_ = h.store.LogAudit(req.Username, string(protocol.ActionRevoke), req.PubKey, "", req.Sig, clientIP, req.Timestamp)

	h.respondJSON(w, http.StatusOK, protocol.ApiResponse{
		Success: true,
		Message: "Identity successfully revoked",
		Data: map[string]any{
			"username": req.Username,
			"status":   protocol.StatusRevoked,
		},
	})
}

// HandleSend queues an encrypted message for a recipient.
func (h *Handler) HandleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req protocol.SendMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}

	req.Recipient = strings.ToLower(strings.TrimSpace(req.Recipient))
	req.Sender = strings.ToLower(strings.TrimSpace(req.Sender))

	if err := protocol.ValidateUsername(req.Recipient); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid recipient username")
		return
	}
	if err := protocol.ValidateUsername(req.Sender); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid sender username")
		return
	}

	if strings.TrimSpace(req.Payload) == "" {
		h.respondError(w, http.StatusBadRequest, "Payload cannot be empty")
		return
	}

	serverNow := protocol.CurrentUnix()
	if err := protocol.ValidateTimestamp(req.Timestamp, serverNow, protocol.MaxTimestampDriftSeconds); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := protocol.ValidateNonce(req.Nonce); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Verify sender identity and active status
	senderId, err := h.store.GetIdentity(req.Sender)
	if err != nil {
		if errors.Is(err, ErrIdentityNotFound) {
			h.respondError(w, http.StatusNotFound, "Sender identity not found")
			return
		}
		h.respondError(w, http.StatusInternalServerError, "Database error retrieving sender")
		return
	}
	if senderId.Status != protocol.StatusActive {
		h.respondError(w, http.StatusForbidden, "Sender identity is revoked")
		return
	}

	// Verify recipient exists and is active
	recipientId, err := h.store.GetIdentity(req.Recipient)
	if err != nil {
		if errors.Is(err, ErrIdentityNotFound) {
			h.respondError(w, http.StatusNotFound, "Recipient identity not found")
			return
		}
		h.respondError(w, http.StatusInternalServerError, "Database error retrieving recipient")
		return
	}
	if recipientId.Status != protocol.StatusActive {
		h.respondError(w, http.StatusForbidden, "Recipient identity is revoked")
		return
	}

	// Replay protection
	if err := h.store.CheckAndRecordNonce(req.Nonce, req.Timestamp); err != nil {
		h.respondError(w, http.StatusConflict, err.Error())
		return
	}

	// Verify sender's signature over canonical message
	payloadHash := protocol.Sha256Hex(req.Payload)
	msg := protocol.FormatSendPayload(req.Recipient, req.Sender, payloadHash, req.Timestamp, req.Nonce)
	if err := protocol.VerifySignature(senderId.PubKey, msg, req.Sig); err != nil {
		h.respondError(w, http.StatusUnauthorized, "Sender signature verification failed")
		return
	}

	// Queue message in database
	msgID, err := h.store.QueueMessage(req.Recipient, req.Sender, req.Payload, req.Sig, req.Timestamp)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, "Failed to queue message")
		return
	}

	// Real-time instant push to active subscriber
	h.broker.Publish(req.Recipient, protocol.QueuedMessage{
		ID:        msgID,
		Sender:    req.Sender,
		Payload:   req.Payload,
		Timestamp: req.Timestamp,
	})

	h.respondJSON(w, http.StatusOK, protocol.ApiResponse{
		Success: true,
		Message: "Message queued successfully",
		Data: map[string]any{
			"message_id": msgID,
		},
	})
}

// HandleInbox allows recipient to fetch their pending messages.
func (h *Handler) HandleInbox(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req protocol.InboxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}

	req.Recipient = strings.ToLower(strings.TrimSpace(req.Recipient))
	if err := protocol.ValidateUsername(req.Recipient); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid recipient username")
		return
	}

	serverNow := protocol.CurrentUnix()
	if err := protocol.ValidateTimestamp(req.Timestamp, serverNow, protocol.MaxTimestampDriftSeconds); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := protocol.ValidateNonce(req.Nonce); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Verify recipient identity
	recipId, err := h.store.GetIdentity(req.Recipient)
	if err != nil {
		if errors.Is(err, ErrIdentityNotFound) {
			h.respondError(w, http.StatusNotFound, "Identity not found")
			return
		}
		h.respondError(w, http.StatusInternalServerError, "Database error retrieving recipient")
		return
	}

	// Replay protection
	if err := h.store.CheckAndRecordNonce(req.Nonce, req.Timestamp); err != nil {
		h.respondError(w, http.StatusConflict, err.Error())
		return
	}

	// Verify recipient's signature over challenge
	msg := protocol.FormatInboxPayload(req.Recipient, req.Timestamp, req.Nonce)
	if err := protocol.VerifySignature(recipId.PubKey, msg, req.Sig); err != nil {
		h.respondError(w, http.StatusUnauthorized, "Recipient signature verification failed")
		return
	}

	messages, err := h.store.GetPendingMessages(req.Recipient, 50)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, "Database error reading inbox")
		return
	}

	h.respondJSON(w, http.StatusOK, protocol.InboxResponse{
		Messages: messages,
	})
}

// HandleAck allows recipient to acknowledge and delete delivered messages.
func (h *Handler) HandleAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req protocol.AckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid JSON payload")
		return
	}

	req.Recipient = strings.ToLower(strings.TrimSpace(req.Recipient))
	if err := protocol.ValidateUsername(req.Recipient); err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid recipient username")
		return
	}

	serverNow := protocol.CurrentUnix()
	if err := protocol.ValidateTimestamp(req.Timestamp, serverNow, protocol.MaxTimestampDriftSeconds); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := protocol.ValidateNonce(req.Nonce); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	recipId, err := h.store.GetIdentity(req.Recipient)
	if err != nil {
		if errors.Is(err, ErrIdentityNotFound) {
			h.respondError(w, http.StatusNotFound, "Identity not found")
			return
		}
		h.respondError(w, http.StatusInternalServerError, "Database error retrieving recipient")
		return
	}

	// Format summary of IDs: "1,2,3"
	var idStrs []string
	for _, id := range req.MessageIDs {
		idStrs = append(idStrs, strconv.FormatInt(id, 10))
	}
	idsSummary := strings.Join(idStrs, ",")

	// Replay protection
	if err := h.store.CheckAndRecordNonce(req.Nonce, req.Timestamp); err != nil {
		h.respondError(w, http.StatusConflict, err.Error())
		return
	}

	// Verify signature
	msg := protocol.FormatAckPayload(req.Recipient, idsSummary, req.Timestamp, req.Nonce)
	if err := protocol.VerifySignature(recipId.PubKey, msg, req.Sig); err != nil {
		h.respondError(w, http.StatusUnauthorized, "Recipient signature verification failed")
		return
	}

	if err := h.store.AckMessages(req.Recipient, req.MessageIDs); err != nil {
		h.respondError(w, http.StatusInternalServerError, "Failed to acknowledge messages")
		return
	}

	h.respondJSON(w, http.StatusOK, protocol.ApiResponse{
		Success: true,
		Message: "Messages acknowledged and deleted from queue",
	})
}

// HandleEvents provides an instant SSE stream for sub-millisecond message delivery.
func (h *Handler) HandleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		h.respondError(w, http.StatusInternalServerError, "Streaming unsupported")
		return
	}

	// Disable any write deadlines for persistent SSE streaming
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})

	recipient := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("recipient")))
	tsStr := r.URL.Query().Get("ts")
	nonce := r.URL.Query().Get("nonce")
	sig := r.URL.Query().Get("sig")

	if recipient == "" || tsStr == "" || nonce == "" || sig == "" {
		h.respondError(w, http.StatusBadRequest, "Missing authentication query parameters")
		return
	}

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "Invalid timestamp")
		return
	}

	if err := protocol.ValidateUsername(recipient); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	serverNow := protocol.CurrentUnix()
	if err := protocol.ValidateTimestamp(ts, serverNow, protocol.MaxTimestampDriftSeconds); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	recipId, err := h.store.GetIdentity(recipient)
	if err != nil {
		h.respondError(w, http.StatusNotFound, "Recipient identity not found")
		return
	}

	// Replay protection
	if err := h.store.CheckAndRecordNonce(nonce, ts); err != nil {
		h.respondError(w, http.StatusConflict, err.Error())
		return
	}

	// Verify cryptographic signature
	msg := protocol.FormatInboxPayload(recipient, ts, nonce)
	if err := protocol.VerifySignature(recipId.PubKey, msg, sig); err != nil {
		h.respondError(w, http.StatusUnauthorized, "Signature verification failed")
		return
	}

	// Parse optional since_id for gap-fill / catch-up
	var sinceID int64
	if sinceStr := r.URL.Query().Get("since_id"); sinceStr != "" {
		sinceID, _ = strconv.ParseInt(sinceStr, 10, 64)
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Subscribe to live broker channel
	ch := h.broker.Subscribe(recipient)
	defer h.broker.Unsubscribe(recipient, ch)

	// Send initial connected event with cursor acknowledgment
	fmt.Fprintf(w, "event: connected\ndata: {\"status\":\"connected\",\"recipient\":\"%s\",\"since_id\":%d}\n\n", recipient, sinceID)
	flusher.Flush()

	// Immediately deliver any queued messages in database (gap fill)
	var pending []protocol.QueuedMessage
	if sinceID > 0 {
		pending, _ = h.store.GetMessagesSince(recipient, sinceID, 50)
	} else {
		pending, _ = h.store.GetPendingMessages(recipient, 50)
	}

	for _, m := range pending {
		data, _ := json.Marshal(m)
		fmt.Fprintf(w, "event: message\ndata: %s\n\n", string(data))
		flusher.Flush()
	}

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case m, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(m)
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", string(data))
			flusher.Flush()
		}
	}
}
