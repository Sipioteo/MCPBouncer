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
}

type AuthSession struct {
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	RedirectURI         string
	ClientID            string
	Resource            string
	Scopes              string
	ProviderIssuer      string
	PublicBase          string
	UpstreamState       string
	UpstreamPKCEVerifier string
	OriginalState       string
	CreatedAt           time.Time
	ExpiresAt           time.Time
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
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO clients(client_id,client_secret_hash,redirect_uris_json,registration_access_token_hash,resource,scopes,created_at) VALUES(?,?,?,?,?,?,?)`,
		c.ClientID, c.ClientSecretHash, c.RedirectURIsJSON, c.RegistrationAccessTokenHash, c.Resource, c.Scopes, c.CreatedAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("InsertClient: %w", err)
	}
	return nil
}

func (s *Store) GetClient(ctx context.Context, clientID string) (*Client, error) {
	var c Client
	var createdAt int64
	err := s.db.QueryRowContext(ctx,
		`SELECT client_id,client_secret_hash,redirect_uris_json,registration_access_token_hash,resource,scopes,created_at FROM clients WHERE client_id=?`,
		clientID,
	).Scan(&c.ClientID, &c.ClientSecretHash, &c.RedirectURIsJSON, &c.RegistrationAccessTokenHash, &c.Resource, &c.Scopes, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetClient: %w", err)
	}
	c.CreatedAt = time.Unix(createdAt, 0)
	return &c, nil
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
		`INSERT INTO refresh_tokens(token_hash,sub,resource,client_id,upstream_refresh_enc,scopes,expires_at) VALUES(?,?,?,?,?,?,?)`,
		rt.TokenHash, rt.Sub, rt.Resource, rt.ClientID, nullBytes(rt.UpstreamRefreshEnc), rt.Scopes, rt.ExpiresAt.Unix(),
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
		`SELECT token_hash,sub,resource,client_id,upstream_refresh_enc,scopes,expires_at FROM refresh_tokens WHERE token_hash=?`,
		hash,
	).Scan(&rt.TokenHash, &rt.Sub, &rt.Resource, &rt.ClientID, &upstreamRefreshEnc, &rt.Scopes, &expiresAt)
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

// nullBytes returns nil if b is empty, otherwise b (for nullable BLOB columns).
func nullBytes(b []byte) interface{} {
	if len(b) == 0 {
		return nil
	}
	return b
}
