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
	dsn := path + "?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store.Open: %w", err)
	}
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
			created_at INTEGER NOT NULL
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
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("migrate exec: %w", err)
		}
	}
	return nil
}
