//go:build cgo && sqlite_serialize

package core

import (
	"context"
	"database/sql"
	"errors"

	"github.com/mattn/go-sqlite3"
)

func sqliteSerialize(db *sql.DB, schema string) ([]byte, error) {
	if schema == "" {
		schema = "main"
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var out []byte
	err = conn.Raw(func(driverConn any) error {
		sqliteConn, ok := driverConn.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("expected *sqlite3.SQLiteConn")
		}
		_, _ = sqliteConn.Exec("ROLLBACK", nil)
		var innerErr error
		out, innerErr = sqliteConn.Serialize(schema)
		return innerErr
	})
	return out, err
}

func sqliteDeserialize(db *sql.DB, buf []byte, schema string) error {
	if schema == "" {
		schema = "main"
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		return err
	}
	defer conn.Close()

	return conn.Raw(func(driverConn any) error {
		sqliteConn, ok := driverConn.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("expected *sqlite3.SQLiteConn")
		}
		return sqliteConn.Deserialize(buf, schema)
	})
}

func hasSQLiteSerialize() bool { return true }
