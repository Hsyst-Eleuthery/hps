//go:build !cgo || !sqlite_serialize

package core

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
)

func sqliteSerialize(db *sql.DB, schema string) ([]byte, error) {
	if schema == "" {
		schema = "main"
	}
	tmpFile, err := os.CreateTemp("", "hps-serialize-*.db")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	db.ExecContext(context.Background(), "ROLLBACK")
	q := fmt.Sprintf("VACUUM INTO '%s'", strings.ReplaceAll(tmpPath, "'", "''"))
	if _, err := db.ExecContext(context.Background(), q); err != nil {
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

func sqliteDeserialize(db *sql.DB, buf []byte, schema string) error {
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

	ctx := context.Background()
	escapedPath := strings.ReplaceAll(tmpPath, "'", "''")
	attachSQL := fmt.Sprintf("ATTACH DATABASE '%s' AS restore_db", escapedPath)
	if _, err := db.ExecContext(ctx, attachSQL); err != nil {
		return fmt.Errorf("attach: %w", err)
	}
	defer db.ExecContext(ctx, "DETACH DATABASE restore_db")

	rows, err := db.QueryContext(ctx, "SELECT name FROM restore_db.sqlite_master WHERE type='table' ORDER BY name")
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			break
		}
		tables = append(tables, name)
	}
	rows.Close()

	for _, t := range tables {
		sql := fmt.Sprintf("INSERT OR IGNORE INTO \"%s\" SELECT * FROM restore_db.\"%s\"", t, t)
		if _, err := db.ExecContext(ctx, sql); err != nil {
			return fmt.Errorf("restore %s: %w", t, err)
		}
	}
	return nil
}

func hasSQLiteSerialize() bool { return false }
