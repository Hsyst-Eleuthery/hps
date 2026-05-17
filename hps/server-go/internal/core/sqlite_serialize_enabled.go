//go:build cgo && sqlite_serialize

package core

import "github.com/mattn/go-sqlite3"

func sqliteSerialize(conn *sqlite3.SQLiteConn, schema string) ([]byte, error) {
	return conn.Serialize(schema)
}

func sqliteDeserialize(conn *sqlite3.SQLiteConn, buf []byte, schema string) error {
	return conn.Deserialize(buf, schema)
}
