package client

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"author/pkg/protocol"
)

type Client struct {
	relayURL   string
	httpClient *http.Client
}

func NewClient(relayURL string) *Client {
	if relayURL == "" {
		relayURL = "http://localhost:8080"
	}
	relayURL = strings.TrimRight(relayURL, "/")

	return &Client{
		relayURL: relayURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *Client) Health() (*protocol.HealthResponse, error) {
	resp, err := c.httpClient.Get(fmt.Sprintf("%s/health", c.relayURL))
	if err != nil {
		return nil, fmt.Errorf("relay health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("relay returned status %d", resp.StatusCode)
	}

	var res protocol.HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c *Client) Claim(username string, privKey ed25519.PrivateKey) (*protocol.ResolveResponse, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	pubKey := privKey.Public().(ed25519.PublicKey)
	pubHex := protocol.PublicKeyToHex(pubKey)

	nonce, err := protocol.GenerateNonce(16)
	if err != nil {
		return nil, err
	}
	ts := protocol.CurrentUnix()

	msg := protocol.FormatClaimPayload(username, pubHex, ts, nonce)
	sig := protocol.SignMessage(privKey, msg)

	reqBody := protocol.ClaimRequest{
		Username:  username,
		PubKey:    pubHex,
		Timestamp: ts,
		Nonce:     nonce,
		Sig:       sig,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Post(fmt.Sprintf("%s/v1/claim", c.relayURL), "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("network request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		var apiErr protocol.ApiResponse
		if err := json.Unmarshal(bodyBytes, &apiErr); err == nil && apiErr.Error != "" {
			return nil, errors.New(apiErr.Error)
		}
		return nil, fmt.Errorf("relay rejected claim (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	return c.Resolve(username)
}

func (c *Client) Resolve(username string) (*protocol.ResolveResponse, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	resp, err := c.httpClient.Get(fmt.Sprintf("%s/v1/resolve/%s", c.relayURL, username))
	if err != nil {
		return nil, fmt.Errorf("resolve request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("identity %q not found", username)
		}
		var apiErr protocol.ApiResponse
		if err := json.Unmarshal(bodyBytes, &apiErr); err == nil && apiErr.Error != "" {
			return nil, errors.New(apiErr.Error)
		}
		return nil, fmt.Errorf("relay error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var res protocol.ResolveResponse
	if err := json.Unmarshal(bodyBytes, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c *Client) Rotate(username string, oldPrivKey, newPrivKey ed25519.PrivateKey, targetVersion int64) error {
	username = strings.ToLower(strings.TrimSpace(username))
	oldPubHex := protocol.PublicKeyToHex(oldPrivKey.Public().(ed25519.PublicKey))
	newPubHex := protocol.PublicKeyToHex(newPrivKey.Public().(ed25519.PublicKey))

	nonce, err := protocol.GenerateNonce(16)
	if err != nil {
		return err
	}
	ts := protocol.CurrentUnix()

	msg := protocol.FormatRotatePayload(username, oldPubHex, newPubHex, targetVersion, ts, nonce)
	sig := protocol.SignMessage(oldPrivKey, msg)
	newSig := protocol.SignMessage(newPrivKey, msg)

	reqBody := protocol.RotateRequest{
		Username:  username,
		OldPubKey: oldPubHex,
		NewPubKey: newPubHex,
		Version:   targetVersion,
		Timestamp: ts,
		Nonce:     nonce,
		Sig:       sig,
		NewSig:    newSig,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Post(fmt.Sprintf("%s/v1/rotate", c.relayURL), "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("network request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var apiErr protocol.ApiResponse
		if err := json.Unmarshal(bodyBytes, &apiErr); err == nil && apiErr.Error != "" {
			return errors.New(apiErr.Error)
		}
		return fmt.Errorf("relay rejected rotate (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

func (c *Client) Revoke(username string, privKey ed25519.PrivateKey) error {
	username = strings.ToLower(strings.TrimSpace(username))
	pubHex := protocol.PublicKeyToHex(privKey.Public().(ed25519.PublicKey))

	nonce, err := protocol.GenerateNonce(16)
	if err != nil {
		return err
	}
	ts := protocol.CurrentUnix()

	msg := protocol.FormatRevokePayload(username, pubHex, ts, nonce)
	sig := protocol.SignMessage(privKey, msg)

	reqBody := protocol.RevokeRequest{
		Username:  username,
		PubKey:    pubHex,
		Timestamp: ts,
		Nonce:     nonce,
		Sig:       sig,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Post(fmt.Sprintf("%s/v1/revoke", c.relayURL), "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("network request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var apiErr protocol.ApiResponse
		if err := json.Unmarshal(bodyBytes, &apiErr); err == nil && apiErr.Error != "" {
			return errors.New(apiErr.Error)
		}
		return fmt.Errorf("relay rejected revoke (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// Send submits an encrypted payload to the relay destined for recipient.
func (c *Client) Send(senderUsername string, senderPriv ed25519.PrivateKey, recipient string, payload string) error {
	senderUsername = strings.ToLower(strings.TrimSpace(senderUsername))
	recipient = strings.ToLower(strings.TrimSpace(recipient))

	nonce, err := protocol.GenerateNonce(16)
	if err != nil {
		return err
	}
	ts := protocol.CurrentUnix()
	payloadHash := protocol.Sha256Hex(payload)

	msg := protocol.FormatSendPayload(recipient, senderUsername, payloadHash, ts, nonce)
	sig := protocol.SignMessage(senderPriv, msg)

	reqBody := protocol.SendMessageRequest{
		Recipient: recipient,
		Sender:    senderUsername,
		Payload:   payload,
		Timestamp: ts,
		Nonce:     nonce,
		Sig:       sig,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Post(fmt.Sprintf("%s/v1/send", c.relayURL), "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("network request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var apiErr protocol.ApiResponse
		if err := json.Unmarshal(bodyBytes, &apiErr); err == nil && apiErr.Error != "" {
			return errors.New(apiErr.Error)
		}
		return fmt.Errorf("relay rejected send (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// Inbox authenticates using recipient's private key and retrieves queued messages.
func (c *Client) Inbox(recipientUsername string, recipientPriv ed25519.PrivateKey) ([]protocol.QueuedMessage, error) {
	recipientUsername = strings.ToLower(strings.TrimSpace(recipientUsername))

	nonce, err := protocol.GenerateNonce(16)
	if err != nil {
		return nil, err
	}
	ts := protocol.CurrentUnix()

	msg := protocol.FormatInboxPayload(recipientUsername, ts, nonce)
	sig := protocol.SignMessage(recipientPriv, msg)

	reqBody := protocol.InboxRequest{
		Recipient: recipientUsername,
		Timestamp: ts,
		Nonce:     nonce,
		Sig:       sig,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Post(fmt.Sprintf("%s/v1/inbox", c.relayURL), "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("network request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var apiErr protocol.ApiResponse
		if err := json.Unmarshal(bodyBytes, &apiErr); err == nil && apiErr.Error != "" {
			return nil, errors.New(apiErr.Error)
		}
		return nil, fmt.Errorf("relay rejected inbox (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var inboxRes protocol.InboxResponse
	if err := json.Unmarshal(bodyBytes, &inboxRes); err != nil {
		return nil, err
	}
	return inboxRes.Messages, nil
}

// Ack confirms delivery and deletes messages from the relay.
func (c *Client) Ack(recipientUsername string, recipientPriv ed25519.PrivateKey, messageIDs []int64) error {
	recipientUsername = strings.ToLower(strings.TrimSpace(recipientUsername))
	if len(messageIDs) == 0 {
		return nil
	}

	nonce, err := protocol.GenerateNonce(16)
	if err != nil {
		return err
	}
	ts := protocol.CurrentUnix()

	var idStrs []string
	for _, id := range messageIDs {
		idStrs = append(idStrs, strconv.FormatInt(id, 10))
	}
	idsSummary := strings.Join(idStrs, ",")

	msg := protocol.FormatAckPayload(recipientUsername, idsSummary, ts, nonce)
	sig := protocol.SignMessage(recipientPriv, msg)

	reqBody := protocol.AckRequest{
		Recipient:  recipientUsername,
		MessageIDs: messageIDs,
		Timestamp:  ts,
		Nonce:      nonce,
		Sig:        sig,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Post(fmt.Sprintf("%s/v1/ack", c.relayURL), "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("network request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var apiErr protocol.ApiResponse
		if err := json.Unmarshal(bodyBytes, &apiErr); err == nil && apiErr.Error != "" {
			return errors.New(apiErr.Error)
		}
		return fmt.Errorf("relay rejected ack (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

