//go:build !cgo || !sqlite_serialize

package core

import (
	"database/sql/driver"
	"fmt"
	"os"
	"strings"

	"github.com/mattn/go-sqlite3"
)

func sqliteSerialize(conn *sqlite3.SQLiteConn, schema string) ([]byte, error) {
	if schema == "" {
		schema = "main"
	}
	tmpFile, err := os.CreateTemp("", "hps-serialize-*.db")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	q := fmt.Sprintf("VACUUM INTO '%s'", strings.ReplaceAll(tmpPath, "'", "''"))
	if _, err := conn.Exec(q, nil); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("vacuum into: %w", err)
	}

	data, err := os.ReadFile(tmpPath)
	os.Remove(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("read temp file: %w", err)
	}
	return data, nil
}

func sqliteDeserialize(conn *sqlite3.SQLiteConn, buf []byte, schema string) error {
	if schema == "" {
		schema = "main"
	}
	tmpFile, err := os.CreateTemp("", "hps-deserialize-*.db")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	if err := os.WriteFile(tmpPath, buf, 0o600); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}

	escapedPath := strings.ReplaceAll(tmpPath, "'", "''")
	attachSQL := fmt.Sprintf("ATTACH DATABASE '%s' AS restore_db", escapedPath)
	if _, err := conn.Exec(attachSQL, nil); err != nil {
		return fmt.Errorf("attach: %w", err)
	}
	defer conn.Exec("DETACH DATABASE restore_db", nil)

	rows, err := conn.Query("SELECT name FROM restore_db.sqlite_master WHERE type='table' ORDER BY name", nil)
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}
	var tables []string
	dest := make([]driver.Value, 1)
	for {
		if err := rows.Next(dest); err != nil {
			break
		}
		if name, ok := dest[0].(string); ok {
			tables = append(tables, name)
		}
	}
	rows.Close()

	for _, t := range tables {
		sql := fmt.Sprintf("INSERT OR IGNORE INTO \"%s\" SELECT * FROM restore_db.\"%s\"", t, t)
		if _, err := conn.Exec(sql, nil); err != nil {
			return fmt.Errorf("restore %s: %w", t, err)
		}
	}
	return nil
}

func hasSQLiteSerialize() bool { return false }
