package protocol

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
)

var (
	usernameRegex    = regexp.MustCompile(`^[a-z0-9_]{3,32}$`)
	handleTokenRegex = regexp.MustCompile(`^[a-f0-9]{64}$`)

	reservedUsernames = map[string]struct{}{
		"admin":         {},
		"administrator": {},
		"root":          {},
		"system":        {},
		"relay":         {},
		"null":          {},
		"undefined":     {},
		"author":        {},
		"anonymous":     {},
		"moderator":     {},
		"support":       {},
		"api":           {},
		"health":        {},
	}

	ErrUsernameTooShort    = errors.New("username must be at least 3 characters")
	ErrUsernameTooLong     = errors.New("username must not exceed 32 characters (or 64 hex characters for blinded tokens)")
	ErrUsernameInvalidChar = errors.New("username must contain only lowercase letters, digits, and underscores [a-z0-9_]")
	ErrUsernameReserved    = errors.New("username is reserved by the protocol")
	ErrTimestampDrift      = errors.New("request timestamp drift exceeds allowed window (5 minutes)")
	ErrNonceEmpty          = errors.New("nonce cannot be empty (min 16 hex chars)")
)

// ValidateUsername checks adherence to length, character set, reservation rules, or 64-char blinded tokens.
func ValidateUsername(username string) error {
	username = strings.TrimSpace(username)
	if handleTokenRegex.MatchString(username) {
		return nil
	}
	if len(username) < 3 {
		return ErrUsernameTooShort
	}
	if len(username) > 32 {
		return ErrUsernameTooLong
	}
	if !usernameRegex.MatchString(username) {
		return ErrUsernameInvalidChar
	}
	if _, isReserved := reservedUsernames[username]; isReserved {
		return ErrUsernameReserved
	}
	return nil
}

// ValidateTimestamp checks if a client's unix timestamp is within maxDriftSec of server time.
func ValidateTimestamp(clientTs int64, serverTs int64, maxDriftSec int64) error {
	if maxDriftSec <= 0 {
		maxDriftSec = MaxTimestampDriftSeconds
	}
	diff := math.Abs(float64(serverTs - clientTs))
	if diff > float64(maxDriftSec) {
		return fmt.Errorf("%w: drift is %.0fs, limit is %ds", ErrTimestampDrift, diff, maxDriftSec)
	}
	return nil
}

// ValidateNonce ensures nonce meets minimum randomness criteria.
func ValidateNonce(nonce string) error {
	if len(strings.TrimSpace(nonce)) < 16 {
		return ErrNonceEmpty
	}
	return nil
}


// CurrentUnix returns the current UTC timestamp in seconds.
func CurrentUnix() int64 {
	return time.Now().UTC().Unix()
}
