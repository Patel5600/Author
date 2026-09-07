//go:build !cgo

package relay

import _ "modernc.org/sqlite"

const sqliteDriverName = "sqlite"
