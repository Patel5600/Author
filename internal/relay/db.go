package relay

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"author/pkg/protocol"
)

var (
	ErrIdentityNotFound = errors.New("identity not found")
	ErrIdentityExists   = errors.New("username is already claimed")
	ErrIdentityRevoked  = errors.New("identity is permanently revoked")
	ErrVersionMismatch  = errors.New("version conflict: outdated or incorrect version")
	ErrReplayDetected   = errors.New("nonce has already been processed (replay detected)")
)

type Identity struct {
	Username  string
	PubKey    string
	Status    protocol.IdentityStatus
	Version   int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Store struct {
	db *sql.DB
}

// NewStore opens or creates an SQLite database at dbPath and runs migrations.
func NewStore(dbPath string) (*Store, error) {
	if dbPath != ":memory:" {
		dir := filepath.Dir(dbPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create db directory: %w", err)
		}
	}

	db, err := sql.Open(sqliteDriverName, dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// Apply WAL, busy timeout, and sync settings
	_, _ = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA synchronous=NORMAL;`)

	db.SetMaxOpenConns(1) // SQLite single-writer safe configuration
	db.SetMaxIdleConns(1)

	s := &Store{db: db}
	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS identities (
		username TEXT PRIMARY KEY,
		pubkey TEXT NOT NULL,
		status TEXT NOT NULL CHECK(status IN ('active', 'revoked')),
		version INTEGER NOT NULL DEFAULT 1,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_identities_pubkey ON identities(pubkey);

	CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		action TEXT NOT NULL,
		prev_pubkey TEXT,
		new_pubkey TEXT,
		signature TEXT NOT NULL,
		timestamp INTEGER NOT NULL,
		ip_address TEXT
	);

	CREATE TABLE IF NOT EXISTS processed_nonces (
		nonce TEXT PRIMARY KEY,
		timestamp INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS messages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		recipient TEXT NOT NULL,
		sender TEXT NOT NULL,
		payload TEXT NOT NULL,
		timestamp INTEGER NOT NULL,
		signature TEXT NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient);
	`
	_, err := s.db.Exec(schema)
	return err
}

// GetIdentity retrieves an identity record by username or blinded handle token.
func (s *Store) GetIdentity(identifier string) (*Identity, error) {
	blindToken := protocol.DeriveHandleToken(identifier)
	row := s.db.QueryRow(`
		SELECT username, pubkey, status, version, created_at, updated_at
		FROM identities WHERE username = ? OR username = ?
		ORDER BY CASE WHEN username = ? THEN 1 ELSE 2 END
		LIMIT 1
	`, identifier, blindToken, identifier)

	var id Identity
	var createdUnix, updatedUnix int64
	var statusStr string

	if err := row.Scan(&id.Username, &id.PubKey, &statusStr, &id.Version, &createdUnix, &updatedUnix); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrIdentityNotFound
		}
		return nil, err
	}

	id.Status = protocol.IdentityStatus(statusStr)
	id.CreatedAt = time.Unix(createdUnix, 0).UTC()
	id.UpdatedAt = time.Unix(updatedUnix, 0).UTC()
	return &id, nil
}

// CreateIdentity claims a new username binding with version 1.
func (s *Store) CreateIdentity(username, pubkey string, timestamp int64) error {
	_, err := s.db.Exec(`
		INSERT INTO identities (username, pubkey, status, version, created_at, updated_at)
		VALUES (?, ?, 'active', 1, ?, ?)
	`, username, pubkey, timestamp, timestamp)

	if err != nil {
		// If already exists
		return ErrIdentityExists
	}
	return nil
}

// RotateIdentity updates the public key and increments version.
func (s *Store) RotateIdentity(username, oldPubkey, newPubkey string, expectedVersion int64, timestamp int64) error {
	res, err := s.db.Exec(`
		UPDATE identities
		SET pubkey = ?, version = version + 1, updated_at = ?
		WHERE username = ? AND pubkey = ? AND status = 'active' AND version = ?
	`, newPubkey, timestamp, username, oldPubkey, expectedVersion-1)

	if err != nil {
		return err
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		// Determine root cause
		id, err := s.GetIdentity(username)
		if err != nil {
			return err
		}
		if id.Status == protocol.StatusRevoked {
			return ErrIdentityRevoked
		}
		if id.PubKey != oldPubkey {
			return errors.New("current public key mismatch")
		}
		if id.Version != expectedVersion-1 {
			return ErrVersionMismatch
		}
		return errors.New("rotate operation rejected")
	}
	return nil
}

// RevokeIdentity marks an identity permanently revoked.
func (s *Store) RevokeIdentity(username string, timestamp int64) error {
	res, err := s.db.Exec(`
		UPDATE identities
		SET status = 'revoked', updated_at = ?
		WHERE username = ? AND status = 'active'
	`, timestamp, username)

	if err != nil {
		return err
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		id, err := s.GetIdentity(username)
		if err != nil {
			return err
		}
		if id.Status == protocol.StatusRevoked {
			return ErrIdentityRevoked
		}
		return errors.New("unable to revoke identity")
	}
	return nil
}

// CheckAndRecordNonce atomically checks if a nonce exists, and if not, stores it.
func (s *Store) CheckAndRecordNonce(nonce string, timestamp int64) error {
	_, err := s.db.Exec(`INSERT INTO processed_nonces (nonce, timestamp) VALUES (?, ?)`, nonce, timestamp)
	if err != nil {
		return ErrReplayDetected
	}
	return nil
}

// LogAudit persists an audit trail entry for cryptographic state changes.
func (s *Store) LogAudit(username, action, prevPubkey, newPubkey, signature, ip string, timestamp int64) error {
	_, err := s.db.Exec(`
		INSERT INTO audit_log (username, action, prev_pubkey, new_pubkey, signature, timestamp, ip_address)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, username, action, prevPubkey, newPubkey, signature, timestamp, ip)
	return err
}

// CountIdentities returns the total number of claimed identities.
func (s *Store) CountIdentities() (int64, error) {
	var count int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM identities`).Scan(&count)
	return count, err
}

// PruneNonces removes expired nonces older than the given unix cutoff.
func (s *Store) PruneNonces(olderThan int64) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM processed_nonces WHERE timestamp < ?`, olderThan)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// QueueMessage inserts an encrypted message into the recipient's queue.
func (s *Store) QueueMessage(recipient, sender, payload, sig string, timestamp int64) (int64, error) {
	res, err := s.db.Exec(`
		INSERT INTO messages (recipient, sender, payload, timestamp, signature)
		VALUES (?, ?, ?, ?, ?)
	`, recipient, sender, payload, timestamp, sig)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetPendingMessages returns queued messages for a recipient, ordered by arrival.
func (s *Store) GetPendingMessages(recipient string, limit int) ([]protocol.QueuedMessage, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	rows, err := s.db.Query(`
		SELECT id, sender, payload, timestamp
		FROM messages
		WHERE recipient = ?
		ORDER BY id ASC
		LIMIT ?
	`, recipient, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []protocol.QueuedMessage
	for rows.Next() {
		var m protocol.QueuedMessage
		if err := rows.Scan(&m.ID, &m.Sender, &m.Payload, &m.Timestamp); err != nil {
			return nil, err
		}
		list = append(list, m)
	}

	if list == nil {
		list = []protocol.QueuedMessage{}
	}
	return list, rows.Err()
}

// GetMessagesSince returns messages with id > sinceID for catch-up after reconnect.
func (s *Store) GetMessagesSince(recipient string, sinceID int64, limit int) ([]protocol.QueuedMessage, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	rows, err := s.db.Query(`
		SELECT id, sender, payload, timestamp
		FROM messages
		WHERE recipient = ? AND id > ?
		ORDER BY id ASC
		LIMIT ?
	`, recipient, sinceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []protocol.QueuedMessage
	for rows.Next() {
		var m protocol.QueuedMessage
		if err := rows.Scan(&m.ID, &m.Sender, &m.Payload, &m.Timestamp); err != nil {
			return nil, err
		}
		list = append(list, m)
	}

	if list == nil {
		list = []protocol.QueuedMessage{}
	}
	return list, rows.Err()
}


// AckMessages deletes delivered messages from the queue for a recipient.
func (s *Store) AckMessages(recipient string, messageIDs []int64) error {
	if len(messageIDs) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`DELETE FROM messages WHERE id = ? AND recipient = ?`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, id := range messageIDs {
		if _, err := stmt.Exec(id, recipient); err != nil {
			return err
		}
	}

	return tx.Commit()
}

