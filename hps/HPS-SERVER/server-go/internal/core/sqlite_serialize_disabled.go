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
	defer os.Remove(tmpPath)

	dst, err := sql.Open("sqlite", tmpPath)
	if err != nil {
		return nil, fmt.Errorf("open temp db: %w", err)
	}
	defer dst.Close()

	ctx := context.Background()

	// Get all CREATE statements from source master
	masterRows, err := db.QueryContext(ctx,
		"SELECT sql, type, name FROM sqlite_master WHERE sql IS NOT NULL AND type IN ('table','index','view','trigger') ORDER BY type='table' DESC, rowid")
	if err != nil {
		return nil, fmt.Errorf("query master: %w", err)
	}
	type stmt struct{ sql, typ, name string }
	var stmts []stmt
	for masterRows.Next() {
		var s stmt
		if err := masterRows.Scan(&s.sql, &s.typ, &s.name); err != nil {
			masterRows.Close()
			return nil, fmt.Errorf("scan master: %w", err)
		}
		stmts = append(stmts, s)
	}
	masterRows.Close()

	// Execute schema on destination
	for _, s := range stmts {
		if _, err := dst.ExecContext(ctx, s.sql); err != nil {
			return nil, fmt.Errorf("create %s %s: %w", s.typ, s.name, err)
		}
	}

	// Disable FK constraints during data copy to avoid ordering issues
	if _, err := dst.ExecContext(ctx, "PRAGMA foreign_keys=OFF"); err != nil {
		return nil, fmt.Errorf("disable FK: %w", err)
	}

	// Copy data for each table
	tables, err := dst.QueryContext(ctx,
		"SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	var tableNames []string
	for tables.Next() {
		var name string
		if err := tables.Scan(&name); err != nil {
			tables.Close()
			return nil, fmt.Errorf("scan table: %w", err)
		}
		tableNames = append(tableNames, name)
	}
	tables.Close()

	for _, name := range tableNames {
		q := fmt.Sprintf("INSERT INTO \"%s\" SELECT * FROM \"%s\"", name, name)
		if _, err := dst.ExecContext(ctx, q); err != nil {
			return nil, fmt.Errorf("copy %s: %w", name, err)
		}
	}

	// Copy sqlite_sequence to preserve AUTOINCREMENT state
	seqRows, err := db.QueryContext(ctx, "SELECT name, seq FROM sqlite_sequence")
	if err == nil {
		var names []string
		var seqVals []int64
		for seqRows.Next() {
			var n string
			var s int64
			if seqRows.Scan(&n, &s) == nil {
				names = append(names, n)
				seqVals = append(seqVals, s)
			}
		}
		seqRows.Close()
		for i := range names {
			if _, err := dst.ExecContext(ctx, "INSERT OR REPLACE INTO sqlite_sequence VALUES (?, ?)", names[i], seqVals[i]); err != nil {
				return nil, fmt.Errorf("copy seq %s: %w", names[i], err)
			}
		}
	}

	if _, err := dst.ExecContext(ctx, "PRAGMA foreign_keys=ON"); err != nil {
		return nil, fmt.Errorf("re-enable FK: %w", err)
	}

	data, err := os.ReadFile(tmpPath)
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
