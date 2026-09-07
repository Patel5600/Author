package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"author/pkg/client"
	"author/pkg/protocol"
)

const version = "0.1.0"

func printUsage() {
	fmt.Printf(`Author Identity CLI (v%s)
Fast, cryptographic self-sovereign identity without phone or email.

Usage:
  author <command> [arguments] [flags]

Commands:
  keygen              Generate a standalone Ed25519 keypair
  claim <username>    Create & register a new identity on the relay (max 3/device)
  resolve <username>  Query the public identity binding from the relay
  list                Display all identities managed on this machine
  rotate <username>   Generate a new key and update the binding on the relay
  revoke <username>   Permanently revoke the identity on the relay
  send <to> <msg>     Send a signed message to another username
  inbox [username]    Fetch and decrypt queued messages for your identity
  export <username>   Export identity private key for offline recovery backup
  import <username> <privkey_hex>  Import an existing identity using private key

Flags:
  --relay <url>       Relay server endpoint (default: env AUTHOR_RELAY or http://localhost:8080)
  --help              Display help
`, version)
}

func getRelayURL(fs *flag.FlagSet) string {
	var relayFlag string
	fs.StringVar(&relayFlag, "relay", "", "Relay endpoint URL")
	_ = fs.Parse(os.Args[2:])

	if relayFlag != "" {
		return relayFlag
	}
	if env := os.Getenv("AUTHOR_RELAY"); env != "" {
		return env
	}
	return "http://localhost:8080"
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := strings.ToLower(os.Args[1])

	switch command {
	case "keygen":
		handleKeygen()
	case "claim":
		handleClaim()
	case "resolve":
		handleResolve()
	case "list":
		handleList()
	case "rotate":
		handleRotate()
	case "revoke":
		handleRevoke()
	case "send":
		handleSend()
	case "inbox":
		handleInbox()
	case "export":
		handleExport()
	case "import":
		handleImport()
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func handleKeygen() {
	pub, priv, err := protocol.GenerateKeyPair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating keypair: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Generated Ed25519 Keypair:")
	fmt.Printf("  Public Key (32B):  %s\n", protocol.PublicKeyToHex(pub))
	fmt.Printf("  Private Key (64B): %s\n", protocol.PrivateKeyToHex(priv))
}

func handleClaim() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Error: username is required. Usage: author claim <username> [--relay=<url>]")
		os.Exit(1)
	}
	username := strings.ToLower(os.Args[2])

	fs := flag.NewFlagSet("claim", flag.ExitOnError)
	relayURL := getRelayURL(fs)

	ks, err := client.NewKeyStore("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Keystore error: %v\n", err)
		os.Exit(1)
	}

	// Check device cap before key generation
	identities, err := ks.ListIdentities()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read local keystore: %v\n", err)
		os.Exit(1)
	}
	if len(identities) >= protocol.MaxIdentitiesPerDevice {
		fmt.Fprintf(os.Stderr, "Device limit reached (%d/%d identities). Cannot claim more on this device.\n", len(identities), protocol.MaxIdentitiesPerDevice)
		os.Exit(1)
	}

	// Generate keypair for this identity
	pub, priv, err := protocol.GenerateKeyPair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Crypto error: %v\n", err)
		os.Exit(1)
	}
	pubHex := protocol.PublicKeyToHex(pub)

	c := client.NewClient(relayURL)
	fmt.Printf("Claiming %q on relay %s...\n", username, relayURL)
	res, err := c.Claim(username, priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Claim failed: %v\n", err)
		os.Exit(1)
	}

	// Persist to local keystore
	if err := ks.SaveNewIdentity(username, priv, pubHex); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: claim succeeded on relay, but failed to save locally: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nSUCCESS: Identity claimed!\n")
	fmt.Printf("  Username: %s\n", res.Username)
	fmt.Printf("  Pubkey:   %s\n", res.PubKey)
	fmt.Printf("  Status:   %s\n", res.Status)
	fmt.Printf("  Version:  %d\n", res.Version)
	fmt.Printf("  Saved:    Local profile registered (%d/%d slots used)\n", len(identities)+1, protocol.MaxIdentitiesPerDevice)
}

func handleResolve() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Error: username is required. Usage: author resolve <username> [--relay=<url>]")
		os.Exit(1)
	}
	username := strings.ToLower(os.Args[2])

	fs := flag.NewFlagSet("resolve", flag.ExitOnError)
	relayURL := getRelayURL(fs)

	c := client.NewClient(relayURL)
	res, err := c.Resolve(username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Resolve failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Resolved Identity Binding:")
	fmt.Printf("  Username:   %s\n", res.Username)
	fmt.Printf("  Public Key: %s\n", res.PubKey)
	fmt.Printf("  Status:     %s\n", res.Status)
	fmt.Printf("  Version:    %d\n", res.Version)
	fmt.Printf("  Created:    %s\n", res.CreatedAt.Format(time.RFC3339))
	fmt.Printf("  Updated:    %s\n", res.UpdatedAt.Format(time.RFC3339))
}

func handleList() {
	ks, err := client.NewKeyStore("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Keystore error: %v\n", err)
		os.Exit(1)
	}

	identities, err := ks.ListIdentities()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list identities: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Local Identities (%d/%d slots used):\n", len(identities), protocol.MaxIdentitiesPerDevice)
	if len(identities) == 0 {
		fmt.Println("  (No identities configured yet. Run 'author claim <username>' to get started)")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "USERNAME\tSTATUS\tVERSION\tPUBLIC KEY\tUPDATED")
	for _, id := range identities {
		shortKey := id.PubKey
		if len(shortKey) > 16 {
			shortKey = shortKey[:8] + "..." + shortKey[len(shortKey)-8:]
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n", id.Username, id.Status, id.Version, shortKey, id.UpdatedAt.Format("2006-01-02 15:04"))
	}
	w.Flush()
}

func handleRotate() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Error: username is required. Usage: author rotate <username> [--relay=<url>]")
		os.Exit(1)
	}
	username := strings.ToLower(os.Args[2])

	fs := flag.NewFlagSet("rotate", flag.ExitOnError)
	relayURL := getRelayURL(fs)

	ks, err := client.NewKeyStore("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Keystore error: %v\n", err)
		os.Exit(1)
	}

	oldPriv, err := ks.GetKey(username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load private key for %q: %v\n", username, err)
		os.Exit(1)
	}

	c := client.NewClient(relayURL)
	curr, err := c.Resolve(username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to fetch current binding from relay: %v\n", err)
		os.Exit(1)
	}

	if curr.Status == protocol.StatusRevoked {
		fmt.Fprintf(os.Stderr, "Cannot rotate key: identity %q is permanently revoked.\n", username)
		os.Exit(1)
	}

	newPub, newPriv, err := protocol.GenerateKeyPair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate new keypair: %v\n", err)
		os.Exit(1)
	}
	newPubHex := protocol.PublicKeyToHex(newPub)

	targetVersion := curr.Version + 1
	fmt.Printf("Rotating key for %q to version %d...\n", username, targetVersion)
	if err := c.Rotate(username, oldPriv, newPriv, targetVersion); err != nil {
		fmt.Fprintf(os.Stderr, "Rotation failed: %v\n", err)
		os.Exit(1)
	}

	// Update local keystore
	if err := ks.UpdateIdentityKey(username, newPriv, newPubHex, targetVersion); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: rotated on relay, but failed to update local keystore: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nSUCCESS: Key rotated!\n")
	fmt.Printf("  Username:   %s\n", username)
	fmt.Printf("  New Pubkey: %s\n", newPubHex)
	fmt.Printf("  Version:    %d\n", targetVersion)
}

func handleRevoke() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Error: username is required. Usage: author revoke <username> [--relay=<url>]")
		os.Exit(1)
	}
	username := strings.ToLower(os.Args[2])

	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	relayURL := getRelayURL(fs)

	ks, err := client.NewKeyStore("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Keystore error: %v\n", err)
		os.Exit(1)
	}

	priv, err := ks.GetKey(username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load private key for %q: %v\n", username, err)
		os.Exit(1)
	}

	c := client.NewClient(relayURL)
	fmt.Printf("Permanently revoking identity %q...\n", username)
	if err := c.Revoke(username, priv); err != nil {
		fmt.Fprintf(os.Stderr, "Revoke failed: %v\n", err)
		os.Exit(1)
	}

	if err := ks.MarkRevoked(username); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: revoked on relay, but failed to update local status: %v\n", err)
	}

	fmt.Printf("\nSUCCESS: Identity %q is permanently revoked.\n", username)
}

func handleExport() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Error: username is required. Usage: author export <username>")
		os.Exit(1)
	}
	username := strings.ToLower(os.Args[2])

	ks, err := client.NewKeyStore("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Keystore error: %v\n", err)
		os.Exit(1)
	}

	priv, err := ks.GetKey(username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load key: %v\n", err)
		os.Exit(1)
	}

	pubHex := protocol.PublicKeyToHex(priv.Public().(ed25519.PublicKey))
	privHex := protocol.PrivateKeyToHex(priv)

	fmt.Printf("RECOVERY EXPORT FOR %q:\n", username)
	fmt.Printf("  Public Key:  %s\n", pubHex)
	fmt.Printf("  Private Key: %s\n", privHex)
	fmt.Println("\nWARNING: Keep this private key secret! Anyone with this key can rotate or revoke your identity.")
}

func handleImport() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "Error: username and private key hex required. Usage: author import <username> <privkey_hex>")
		os.Exit(1)
	}
	username := strings.ToLower(os.Args[2])
	privHex := strings.TrimSpace(os.Args[3])

	priv, err := protocol.HexToPrivateKey(privHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid private key: %v\n", err)
		os.Exit(1)
	}

	ks, err := client.NewKeyStore("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Keystore error: %v\n", err)
		os.Exit(1)
	}

	pubHex := protocol.PublicKeyToHex(priv.Public().(ed25519.PublicKey))
	if err := ks.SaveNewIdentity(username, priv, pubHex); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to import identity: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Imported identity %q successfully.\n", username)
}

func handleSend() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "Error: recipient and message required. Usage: author send <recipient> <message> [--from=<user>] [--relay=<url>]")
		os.Exit(1)
	}
	recipient := strings.ToLower(os.Args[2])
	message := os.Args[3]

	fs := flag.NewFlagSet("send", flag.ExitOnError)
	var fromFlag string
	fs.StringVar(&fromFlag, "from", "", "Sender username")
	relayURL := getRelayURL(fs)

	ks, err := client.NewKeyStore("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Keystore error: %v\n", err)
		os.Exit(1)
	}

	identities, err := ks.ListIdentities()
	if err != nil || len(identities) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No local identities found. Run 'author claim <user>' first.")
		os.Exit(1)
	}

	var sender string
	if fromFlag != "" {
		sender = strings.ToLower(fromFlag)
	} else {
		// Pick first active identity
		for _, id := range identities {
			if id.Status == protocol.StatusActive {
				sender = id.Username
				break
			}
		}
	}

	if sender == "" {
		fmt.Fprintln(os.Stderr, "Error: No active sender identity available.")
		os.Exit(1)
	}

	priv, err := ks.GetKey(sender)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load private key for sender %q: %v\n", sender, err)
		os.Exit(1)
	}

	c := client.NewClient(relayURL)
	fmt.Printf("Resolving recipient @%s for end-to-end encryption...\n", recipient)
	recipBinding, err := c.Resolve(recipient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to resolve recipient @%s on relay: %v\n", recipient, err)
		os.Exit(1)
	}

	// Encrypt payload end-to-end using recipient's X25519 public key
	env, err := protocol.EncryptMessage(recipBinding.PubKey, message, sender)
	if err != nil {
		fmt.Fprintf(os.Stderr, "E2EE encryption failed: %v\n", err)
		os.Exit(1)
	}

	envBytes, err := json.Marshal(env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to serialize encrypted envelope: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Sending [🔒 E2EE] message from @%s to @%s...\n", sender, recipient)
	if err := c.Send(sender, priv, recipient, string(envBytes)); err != nil {
		fmt.Fprintf(os.Stderr, "Send failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Message encrypted with X25519 (🔒 E2EE) and queued on relay for @%s!\n", recipient)
}

func handleInbox() {
	fs := flag.NewFlagSet("inbox", flag.ExitOnError)
	var userFlag string
	fs.StringVar(&userFlag, "user", "", "Identity username")
	relayURL := getRelayURL(fs)

	ks, err := client.NewKeyStore("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Keystore error: %v\n", err)
		os.Exit(1)
	}

	identities, err := ks.ListIdentities()
	if err != nil || len(identities) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No local identities found.")
		os.Exit(1)
	}

	username := userFlag
	if username == "" && len(os.Args) >= 3 && !strings.HasPrefix(os.Args[2], "-") {
		username = strings.ToLower(os.Args[2])
	}
	if username == "" {
		for _, id := range identities {
			if id.Status == protocol.StatusActive {
				username = id.Username
				break
			}
		}
	}

	if username == "" {
		fmt.Fprintln(os.Stderr, "Error: No identity specified.")
		os.Exit(1)
	}

	priv, err := ks.GetKey(username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load private key for %q: %v\n", username, err)
		os.Exit(1)
	}

	c := client.NewClient(relayURL)
	messages, err := c.Inbox(username, priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Inbox check failed: %v\n", err)
		os.Exit(1)
	}

	if len(messages) == 0 {
		fmt.Printf("Inbox for @%s: 0 pending messages.\n", username)
		return
	}

	fmt.Printf("Inbox for @%s (%d messages):\n\n", username, len(messages))
	var deliveredIDs []int64
	for _, m := range messages {
		deliveredIDs = append(deliveredIDs, m.ID)
		t := time.Unix(m.Timestamp, 0).Format("15:04:05")

		displayText := m.Payload
		badge := ""

		if env, ok := protocol.ParseEncryptedEnvelope(m.Payload); ok {
			decrypted, err := protocol.DecryptMessage(priv, env)
			if err == nil {
				displayText = decrypted
				badge = " [🔒 E2EE]"
			} else {
				badge = " [⚠️ Decryption Failed]"
			}
		}

		fmt.Printf("  [%s] From @%s (msg #%d)%s:\n    %s\n\n", t, m.Sender, m.ID, badge, displayText)
	}

	// Ack messages so relay cleans them up
	if err := c.Ack(username, priv, deliveredIDs); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to acknowledge messages: %v\n", err)
	} else {
		fmt.Println("(Delivered messages acknowledged and cleared from relay)")
	}
}

