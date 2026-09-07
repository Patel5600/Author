//go:build cgo

package relay

import _ "github.com/mattn/go-sqlite3"

const sqliteDriverName = "sqlite3"
