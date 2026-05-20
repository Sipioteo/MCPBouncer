package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type Store struct {
	db *DB
}

func NewStore(db *DB) *Store {
	return &Store{db: db}
}

// --- Types ---

type SigningKey struct {
	Kid        string
	Alg        string
	PrivatePEM []byte
	PublicPEM  []byte
	CreatedAt  time.Time
	RetiresAt  time.Time
	Status     string
}

type Client struct {
	ClientID                    string
	ClientSecretHash            string
	RedirectURIsJSON            string
	RegistrationAccessTokenHash string
	Resource                    string
	Scopes                      string
	CreatedAt                   time.Time
	LastUsedAt                  time.Time
}

type AuthSession struct {
	State                string
	CodeChallenge        string
	CodeChallengeMethod  string
	RedirectURI          string
	ClientID             string
	Resource             string
	Scopes               string
	ProviderIssuer       string
	PublicBase           string
	UpstreamState        string
	UpstreamPKCEVerifier string
	OriginalState        string
	CreatedAt            time.Time
	ExpiresAt            time.Time
}

type Code struct {
	Code                string
	ClientID            string
	Resource            string
	Sub                 string
	ClaimsJSON          string
	UpstreamRefreshEnc  []byte
	Scopes              string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

type RefreshToken struct {
	TokenHash          string
	Sub                string
	Resource           string
	ClientID           string
	ClaimsJSON         string
	UpstreamRefreshEnc []byte
	Scopes             string
	ExpiresAt          time.Time
}

type ResourceConfig struct {
	Name            string
	ProviderIssuer  string
	ClientID        string
	ClientSecretEnc []byte
	Scopes          string
	Audience        string
	UpdatedAt       time.Time
}

// --- SigningKeys ---

func (s *Store) InsertSigningKey(ctx context.Context, kid, alg string, privPEM, pubPEM []byte, retiresAt time.Time, status string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO signing_keys(kid,alg,private_pem,public_pem,created_at,retires_at,status) VALUES(?,?,?,?,?,?,?)`,
		kid, alg, privPEM, pubPEM, time.Now().Unix(), retiresAt.Unix(), status,
	)
	if err != nil {
		return fmt.Errorf("InsertSigningKey: %w", err)
	}
	return nil
}

func (s *Store) ListSigningKeys(ctx context.Context) ([]SigningKey, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT kid,alg,private_pem,public_pem,created_at,retires_at,status FROM signing_keys WHERE status IN ('active','next','retiring')`,
	)
	if err != nil {
		return nil, fmt.Errorf("ListSigningKeys: %w", err)
	}
	defer rows.Close()
	var keys []SigningKey
	for rows.Next() {
		var k SigningKey
		var createdAt, retiresAt int64
		if err := rows.Scan(&k.Kid, &k.Alg, &k.PrivatePEM, &k.PublicPEM, &createdAt, &retiresAt, &k.Status); err != nil {
			return nil, fmt.Errorf("ListSigningKeys scan: %w", err)
		}
		k.CreatedAt = time.Unix(createdAt, 0)
		k.RetiresAt = time.Unix(retiresAt, 0)
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (s *Store) GetActiveSigningKey(ctx context.Context) (*SigningKey, error) {
	var k SigningKey
	var createdAt, retiresAt int64
	err := s.db.QueryRowContext(ctx,
		`SELECT kid,alg,private_pem,public_pem,created_at,retires_at,status FROM signing_keys WHERE status='active' LIMIT 1`,
	).Scan(&k.Kid, &k.Alg, &k.PrivatePEM, &k.PublicPEM, &createdAt, &retiresAt, &k.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetActiveSigningKey: %w", err)
	}
	k.CreatedAt = time.Unix(createdAt, 0)
	k.RetiresAt = time.Unix(retiresAt, 0)
	return &k, nil
}

func (s *Store) UpdateSigningKeyStatus(ctx context.Context, kid, status string, retiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE signing_keys SET status=?, retires_at=? WHERE kid=?`,
		status, retiresAt.Unix(), kid,
	)
	if err != nil {
		return fmt.Errorf("UpdateSigningKeyStatus: %w", err)
	}
	return nil
}

func (s *Store) DeleteExpiredSigningKeys(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM signing_keys WHERE status='retiring' AND retires_at <= ?`,
		time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("DeleteExpiredSigningKeys: %w", err)
	}
	return nil
}

// --- Clients ---

func (s *Store) InsertClient(ctx context.Context, c Client) error {
	if c.LastUsedAt.IsZero() {
		c.LastUsedAt = time.Now()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO clients(client_id,client_secret_hash,redirect_uris_json,registration_access_token_hash,resource,scopes,created_at,last_used_at) VALUES(?,?,?,?,?,?,?,?)`,
		c.ClientID, c.ClientSecretHash, c.RedirectURIsJSON, c.RegistrationAccessTokenHash, c.Resource, c.Scopes, c.CreatedAt.Unix(), c.LastUsedAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("InsertClient: %w", err)
	}
	return nil
}

func (s *Store) GetClient(ctx context.Context, clientID string) (*Client, error) {
	var c Client
	var createdAt, lastUsedAt int64
	err := s.db.QueryRowContext(ctx,
		`SELECT client_id,client_secret_hash,redirect_uris_json,registration_access_token_hash,resource,scopes,created_at,last_used_at FROM clients WHERE client_id=?`,
		clientID,
	).Scan(&c.ClientID, &c.ClientSecretHash, &c.RedirectURIsJSON, &c.RegistrationAccessTokenHash, &c.Resource, &c.Scopes, &createdAt, &lastUsedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetClient: %w", err)
	}
	c.CreatedAt = time.Unix(createdAt, 0)
	c.LastUsedAt = time.Unix(lastUsedAt, 0)
	return &c, nil
}

// TouchClient updates last_used_at to now for the given client.
func (s *Store) TouchClient(ctx context.Context, clientID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE clients SET last_used_at=? WHERE client_id=?`,
		time.Now().Unix(), clientID,
	)
	if err != nil {
		return fmt.Errorf("TouchClient: %w", err)
	}
	return nil
}

// DeleteStaleClients deletes clients whose last_used_at is older than olderThan ago.
// Rows with last_used_at=0 (epoch, pre-migration) are compared against created_at instead.
func (s *Store) DeleteStaleClients(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan).Unix()
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM clients WHERE
			CASE WHEN last_used_at = 0 THEN created_at ELSE last_used_at END < ?`,
		cutoff,
	)
	if err != nil {
		return 0, fmt.Errorf("DeleteStaleClients: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("DeleteStaleClients rows: %w", err)
	}
	return n, nil
}

// --- AuthSessions ---

func (s *Store) InsertAuthSession(ctx context.Context, sess AuthSession) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_sessions(state,code_challenge,code_challenge_method,redirect_uri,client_id,resource,scopes,provider_issuer,public_base,upstream_state,upstream_pkce_verifier,original_state,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		sess.State, sess.CodeChallenge, sess.CodeChallengeMethod, sess.RedirectURI, sess.ClientID, sess.Resource, sess.Scopes, sess.ProviderIssuer, sess.PublicBase, sess.UpstreamState, sess.UpstreamPKCEVerifier, sess.OriginalState, sess.CreatedAt.Unix(), sess.ExpiresAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("InsertAuthSession: %w", err)
	}
	return nil
}

func (s *Store) GetAuthSession(ctx context.Context, state string) (*AuthSession, error) {
	var sess AuthSession
	var createdAt, expiresAt int64
	err := s.db.QueryRowContext(ctx,
		`SELECT state,code_challenge,code_challenge_method,redirect_uri,client_id,resource,scopes,provider_issuer,public_base,upstream_state,upstream_pkce_verifier,original_state,created_at,expires_at FROM auth_sessions WHERE state=?`,
		state,
	).Scan(&sess.State, &sess.CodeChallenge, &sess.CodeChallengeMethod, &sess.RedirectURI, &sess.ClientID, &sess.Resource, &sess.Scopes, &sess.ProviderIssuer, &sess.PublicBase, &sess.UpstreamState, &sess.UpstreamPKCEVerifier, &sess.OriginalState, &createdAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetAuthSession: %w", err)
	}
	sess.CreatedAt = time.Unix(createdAt, 0)
	sess.ExpiresAt = time.Unix(expiresAt, 0)
	return &sess, nil
}

func (s *Store) DeleteAuthSession(ctx context.Context, state string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_sessions WHERE state=?`, state)
	if err != nil {
		return fmt.Errorf("DeleteAuthSession: %w", err)
	}
	return nil
}

func (s *Store) DeleteExpiredAuthSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_sessions WHERE expires_at <= ?`, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("DeleteExpiredAuthSessions: %w", err)
	}
	return nil
}

// --- Codes ---

func (s *Store) InsertCode(ctx context.Context, c Code) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO codes(code,client_id,resource,sub,claims_json,upstream_refresh_enc,scopes,redirect_uri,code_challenge,code_challenge_method,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		c.Code, c.ClientID, c.Resource, c.Sub, c.ClaimsJSON, nullBytes(c.UpstreamRefreshEnc), c.Scopes, c.RedirectURI, c.CodeChallenge, c.CodeChallengeMethod, c.ExpiresAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("InsertCode: %w", err)
	}
	return nil
}

func (s *Store) GetCode(ctx context.Context, code string) (*Code, error) {
	var c Code
	var expiresAt int64
	var upstreamRefreshEnc []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT code,client_id,resource,sub,claims_json,upstream_refresh_enc,scopes,redirect_uri,code_challenge,code_challenge_method,expires_at FROM codes WHERE code=?`,
		code,
	).Scan(&c.Code, &c.ClientID, &c.Resource, &c.Sub, &c.ClaimsJSON, &upstreamRefreshEnc, &c.Scopes, &c.RedirectURI, &c.CodeChallenge, &c.CodeChallengeMethod, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetCode: %w", err)
	}
	c.UpstreamRefreshEnc = upstreamRefreshEnc
	c.ExpiresAt = time.Unix(expiresAt, 0)
	return &c, nil
}

func (s *Store) DeleteCode(ctx context.Context, code string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM codes WHERE code=?`, code)
	if err != nil {
		return fmt.Errorf("DeleteCode: %w", err)
	}
	return nil
}

func (s *Store) DeleteExpiredCodes(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM codes WHERE expires_at <= ?`, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("DeleteExpiredCodes: %w", err)
	}
	return nil
}

// --- RefreshTokens ---

func (s *Store) InsertRefreshToken(ctx context.Context, rt RefreshToken) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO refresh_tokens(token_hash,sub,resource,client_id,claims_json,upstream_refresh_enc,scopes,expires_at) VALUES(?,?,?,?,?,?,?,?)`,
		rt.TokenHash, rt.Sub, rt.Resource, rt.ClientID, rt.ClaimsJSON, nullBytes(rt.UpstreamRefreshEnc), rt.Scopes, rt.ExpiresAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("InsertRefreshToken: %w", err)
	}
	return nil
}

func (s *Store) GetRefreshTokenByHash(ctx context.Context, hash string) (*RefreshToken, error) {
	var rt RefreshToken
	var expiresAt int64
	var upstreamRefreshEnc []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT token_hash,sub,resource,client_id,claims_json,upstream_refresh_enc,scopes,expires_at FROM refresh_tokens WHERE token_hash=?`,
		hash,
	).Scan(&rt.TokenHash, &rt.Sub, &rt.Resource, &rt.ClientID, &rt.ClaimsJSON, &upstreamRefreshEnc, &rt.Scopes, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetRefreshTokenByHash: %w", err)
	}
	rt.UpstreamRefreshEnc = upstreamRefreshEnc
	rt.ExpiresAt = time.Unix(expiresAt, 0)
	return &rt, nil
}

func (s *Store) DeleteRefreshTokenByHash(ctx context.Context, hash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE token_hash=?`, hash)
	if err != nil {
		return fmt.Errorf("DeleteRefreshTokenByHash: %w", err)
	}
	return nil
}

func (s *Store) DeleteExpiredRefreshTokens(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE expires_at <= ?`, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("DeleteExpiredRefreshTokens: %w", err)
	}
	return nil
}

// --- ResourceConfigs ---

func (s *Store) UpsertResourceConfig(ctx context.Context, rc ResourceConfig) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO resource_configs(name,provider_issuer,client_id,client_secret_enc,scopes,audience,updated_at) VALUES(?,?,?,?,?,?,?)
		 ON CONFLICT(name) DO UPDATE SET provider_issuer=excluded.provider_issuer, client_id=excluded.client_id, client_secret_enc=excluded.client_secret_enc, scopes=excluded.scopes, audience=excluded.audience, updated_at=excluded.updated_at`,
		rc.Name, rc.ProviderIssuer, rc.ClientID, rc.ClientSecretEnc, rc.Scopes, rc.Audience, rc.UpdatedAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("UpsertResourceConfig: %w", err)
	}
	return nil
}

func (s *Store) GetResourceConfig(ctx context.Context, name string) (*ResourceConfig, error) {
	var rc ResourceConfig
	var updatedAt int64
	err := s.db.QueryRowContext(ctx,
		`SELECT name,provider_issuer,client_id,client_secret_enc,scopes,audience,updated_at FROM resource_configs WHERE name=?`,
		name,
	).Scan(&rc.Name, &rc.ProviderIssuer, &rc.ClientID, &rc.ClientSecretEnc, &rc.Scopes, &rc.Audience, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetResourceConfig: %w", err)
	}
	rc.UpdatedAt = time.Unix(updatedAt, 0)
	return &rc, nil
}

// --- AuditEvents ---

// CountAuditEvents returns the total number of rows in audit_events.
// Intended for use in tests.
func (s *Store) CountAuditEvents(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("CountAuditEvents: %w", err)
	}
	return n, nil
}

func (s *Store) InsertAuditEvent(ctx context.Context, eventType, clientID, sub, ip, detailsJSON string, success bool) error {
	successInt := 0
	if success {
		successInt = 1
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_events(event_type,client_id,sub,ip,success,details_json,timestamp) VALUES(?,?,?,?,?,?,?)`,
		eventType, clientID, sub, ip, successInt, detailsJSON, time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("InsertAuditEvent: %w", err)
	}
	return nil
}

// --- EncryptionKeys ---

// EncryptionKey is a row from the encryption_keys table. Material is the raw
// 32-byte AES-256 key (BLOB), Status is "active" or "retired".
type EncryptionKey struct {
	KeyID     string
	Material  []byte
	Status    string
	CreatedAt time.Time
}

func (s *Store) ListEncryptionKeys(ctx context.Context) ([]EncryptionKey, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT key_id,material,status,created_at FROM encryption_keys`,
	)
	if err != nil {
		return nil, fmt.Errorf("ListEncryptionKeys: %w", err)
	}
	defer rows.Close()
	var keys []EncryptionKey
	for rows.Next() {
		var k EncryptionKey
		var createdAt int64
		if err := rows.Scan(&k.KeyID, &k.Material, &k.Status, &createdAt); err != nil {
			return nil, fmt.Errorf("ListEncryptionKeys scan: %w", err)
		}
		k.CreatedAt = time.Unix(createdAt, 0)
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (s *Store) InsertEncryptionKey(ctx context.Context, k EncryptionKey) error {
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO encryption_keys(key_id,material,status,created_at) VALUES(?,?,?,?)`,
		k.KeyID, k.Material, k.Status, k.CreatedAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("InsertEncryptionKey: %w", err)
	}
	return nil
}

func (s *Store) SetEncryptionKeyStatus(ctx context.Context, keyID, status string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE encryption_keys SET status=? WHERE key_id=?`,
		status, keyID,
	)
	if err != nil {
		return fmt.Errorf("SetEncryptionKeyStatus: %w", err)
	}
	return nil
}

// nullBytes returns nil if b is empty, otherwise b (for nullable BLOB columns).
func nullBytes(b []byte) interface{} {
	if len(b) == 0 {
		return nil
	}
	return b
}
