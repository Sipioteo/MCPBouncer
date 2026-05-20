package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

type DB struct {
	*sql.DB
}

func Open(path string) (*DB, error) {
	dsn := path + "?_journal_mode=WAL&_busy_timeout=10000&_foreign_keys=on&_synchronous=NORMAL"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store.Open: %w", err)
	}
	// Serialize writes through a single connection. SQLite is one-writer-at-a-time;
	// using >1 connection just produces SQLITE_BUSY for low-traffic workloads
	// like ours. With max=1 + busy_timeout=10s, write contention disappears.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("store.Open ping: %w", err)
	}
	d := &DB{db}
	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("store.Open migrate: %w", err)
	}
	return d, nil
}

func (db *DB) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS signing_keys (
			kid TEXT PRIMARY KEY,
			alg TEXT NOT NULL,
			private_pem BLOB NOT NULL,
			public_pem BLOB NOT NULL,
			created_at INTEGER NOT NULL,
			retires_at INTEGER NOT NULL,
			status TEXT NOT NULL CHECK(status IN ('next','active','retiring'))
		)`,
		`CREATE TABLE IF NOT EXISTS clients (
			client_id TEXT PRIMARY KEY,
			client_secret_hash TEXT NOT NULL,
			redirect_uris_json TEXT NOT NULL,
			registration_access_token_hash TEXT NOT NULL,
			resource TEXT NOT NULL,
			scopes TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			last_used_at INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS auth_sessions (
			state TEXT PRIMARY KEY,
			code_challenge TEXT NOT NULL,
			code_challenge_method TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			client_id TEXT NOT NULL,
			resource TEXT NOT NULL,
			scopes TEXT NOT NULL,
			provider_issuer TEXT NOT NULL,
			public_base TEXT NOT NULL,
			upstream_state TEXT NOT NULL,
			upstream_pkce_verifier TEXT NOT NULL,
			original_state TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires ON auth_sessions(expires_at)`,
		`CREATE TABLE IF NOT EXISTS codes (
			code TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			resource TEXT NOT NULL,
			sub TEXT NOT NULL,
			claims_json TEXT NOT NULL,
			upstream_refresh_enc BLOB,
			scopes TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			code_challenge TEXT NOT NULL,
			code_challenge_method TEXT NOT NULL,
			expires_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_codes_expires ON codes(expires_at)`,
		`CREATE TABLE IF NOT EXISTS refresh_tokens (
			token_hash TEXT PRIMARY KEY,
			sub TEXT NOT NULL,
			resource TEXT NOT NULL,
			client_id TEXT NOT NULL,
			claims_json TEXT NOT NULL DEFAULT '',
			upstream_refresh_enc BLOB,
			scopes TEXT NOT NULL,
			expires_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at)`,
		`CREATE TABLE IF NOT EXISTS resource_configs (
			name TEXT PRIMARY KEY,
			provider_issuer TEXT NOT NULL,
			client_id TEXT NOT NULL,
			client_secret_enc BLOB NOT NULL,
			scopes TEXT NOT NULL,
			audience TEXT NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS audit_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event_type TEXT NOT NULL,
			client_id TEXT NOT NULL DEFAULT '',
			sub TEXT NOT NULL DEFAULT '',
			ip TEXT NOT NULL DEFAULT '',
			success INTEGER NOT NULL,
			details_json TEXT NOT NULL DEFAULT '{}',
			timestamp INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_events_ts ON audit_events(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(event_type, timestamp)`,
		`CREATE TABLE IF NOT EXISTS encryption_keys (
			key_id TEXT PRIMARY KEY,
			material BLOB NOT NULL,
			status TEXT NOT NULL CHECK(status IN ('active','retired')),
			created_at INTEGER NOT NULL
		)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("migrate exec: %w", err)
		}
	}
	if err := addColumnIfMissing(db, "refresh_tokens", "claims_json", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := addColumnIfMissing(db, "clients", "last_used_at", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	return nil
}

func addColumnIfMissing(db *DB, table, column, decl string) error {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return fmt.Errorf("table_info %s: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return fmt.Errorf("table_info scan: %w", err)
		}
		if name == column {
			return nil
		}
	}
	if _, err := db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, decl)); err != nil {
		return fmt.Errorf("add column %s.%s: %w", table, column, err)
	}
	return nil
}
