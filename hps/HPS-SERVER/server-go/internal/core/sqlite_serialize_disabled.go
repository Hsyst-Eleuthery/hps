//go:build !cgo || !sqlite_serialize

package core

import (
	"errors"

	"github.com/mattn/go-sqlite3"
)

func sqliteSerialize(conn *sqlite3.SQLiteConn, schema string) ([]byte, error) {
	return nil, errors.New("sqlite serialize support unavailable: build with CGO_ENABLED=1 and -tags sqlite_serialize")
}

func sqliteDeserialize(conn *sqlite3.SQLiteConn, buf []byte, schema string) error {
	return errors.New("sqlite deserialize support unavailable: build with CGO_ENABLED=1 and -tags sqlite_serialize")
}
