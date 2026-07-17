// Package auth implements API key + JWT authentication for the fraud API.
//
// Two modes are supported:
//
//   - API key: a static bearer token (configured via FRAUD_API_KEY env var)
//     suitable for service-to-service auth.
//   - JWT: a signed JWT carrying claims (sub, role, tenant_id) suitable for
//     user-facing requests. HMAC-SHA256 with a shared secret.
//
// The middleware attaches the authenticated principal to the gin.Context
// so handlers can enforce RBAC (e.g. only admins can close cases).
package auth

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Role is the RBAC role attached to a principal.
type Role string

const (
	RoleAdmin    Role = "admin"    // Full access: configure rules, close cases, view all data
	RoleAnalyst  Role = "analyst"  // Review queue access: assign/resolve cases
	RoleService  Role = "service"  // Programmatic: score transactions, read stats
	RoleReadOnly Role = "readonly" // Read-only: view stats and cases, no mutations
)

// Principal is the authenticated entity making a request.
type Principal struct {
	ID       string `json:"id"`
	Role     Role   `json:"role"`
	TenantID string `json:"tenant_id"`
	APIKey   bool   `json:"-"` // true if authenticated via API key (not JWT)
}

// Verifier checks a bearer token and returns the principal.
type Verifier interface {
	Verify(token string) (*Principal, error)
}

// Config holds the auth configuration.
type Config struct {
	APIKeySecret string // Static API key for service-to-service auth
	JWTSecret    string // HMAC secret for signing JWTs
	JWTIssuer    string // Expected "iss" claim
}

// JWTVerifier verifies JWT tokens (HMAC-SHA256).
type JWTVerifier struct {
	secret []byte
	issuer string
}

// NewJWTVerifier builds a verifier.
func NewJWTVerifier(secret, issuer string) *JWTVerifier {
	return &JWTVerifier{secret: []byte(secret), issuer: issuer}
}

// Verify implements Verifier.
func (v *JWTVerifier) Verify(token string) (*Principal, error) {
	if token == "" {
		return nil, ErrNoToken
	}
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return v.secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse jwt: %w", err)
	}
	if !parsed.Valid {
		return nil, ErrInvalidToken
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}
	if v.issuer != "" {
		if iss, _ := claims.GetIssuer(); iss != v.issuer {
			return nil, ErrInvalidIssuer
		}
	}
	if exp, _ := claims.GetExpirationTime(); exp != nil && time.Now().After(exp.Time) {
		return nil, ErrExpired
	}
	sub, _ := claims.GetSubject()
	// Guard against malformed JWTs: a missing or non-string "role" claim
	// used to panic with a type-assertion fault, taking the whole request
	// down. Treat it as an invalid token instead.
	roleStr, ok := claims["role"].(string)
	if !ok || roleStr == "" {
		return nil, ErrInvalidToken
	}
	role := Role(roleStr)
	tenant, _ := claims["tenant_id"].(string)
	return &Principal{
		ID:       sub,
		Role:     role,
		TenantID: tenant,
		APIKey:   false,
	}, nil
}

// APIKeyVerifier checks a static API key.
type APIKeyVerifier struct {
	key string
}

// NewAPIKeyVerifier builds a verifier.
func NewAPIKeyVerifier(key string) *APIKeyVerifier {
	return &APIKeyVerifier{key: key}
}

// Verify implements Verifier.
func (v *APIKeyVerifier) Verify(token string) (*Principal, error) {
	if token == "" {
		return nil, ErrNoToken
	}
	// Constant-time comparison guards the API key against timing side
	// channels. The empty-key check happens *before* the comparison so a
	// misconfigured verifier (no key set) cannot be brute-forced into
	// accepting an empty token — subtle.ConstantTimeCompare returns 1 for
	// two empty byte slices, which is exactly the footgun we want to avoid.
	if v.key == "" || subtle.ConstantTimeCompare([]byte(token), []byte(v.key)) != 1 {
		return nil, ErrInvalidToken
	}
	return &Principal{
		ID:     "api-key",
		Role:   RoleService,
		APIKey: true,
	}, nil
}

// MultiVerifier tries each verifier in order. The first one that returns a
// non-error principal wins. This lets the API accept both API keys and JWTs
// on the same endpoint.
type MultiVerifier struct {
	verifiers []Verifier
}

// NewMultiVerifier combines several verifiers.
func NewMultiVerifier(verifiers ...Verifier) *MultiVerifier {
	return &MultiVerifier{verifiers: verifiers}
}

// Verify implements Verifier.
func (m *MultiVerifier) Verify(token string) (*Principal, error) {
	var lastErr error
	for _, v := range m.verifiers {
		p, err := v.Verify(token)
		if err == nil {
			return p, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		return nil, ErrNoToken
	}
	return nil, lastErr
}

// Issuer mints JWTs for testing or for a future /api/auth/login endpoint.
type Issuer struct {
	secret []byte
	issuer string
	mu     sync.Mutex
}

// NewIssuer builds a JWT issuer.
func NewIssuer(secret, issuer string) *Issuer {
	return &Issuer{secret: []byte(secret), issuer: issuer}
}

// IssueToken signs a JWT with the given principal and TTL.
func (i *Issuer) IssueToken(p Principal, ttl time.Duration) (string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":       p.ID,
		"role":      string(p.Role),
		"tenant_id": p.TenantID,
		"iss":       i.issuer,
		"iat":       now.Unix(),
		"exp":       now.Add(ttl).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(i.secret)
}

// ExtractBearer pulls the token out of an "Authorization: Bearer <token>" header.
func ExtractBearer(header string) string {
	if header == "" {
		return ""
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimPrefix(header, prefix)
}

// Auth errors.
var (
	ErrNoToken       = errors.New("no bearer token provided")
	ErrInvalidToken  = errors.New("invalid token")
	ErrExpired       = errors.New("token expired")
	ErrInvalidIssuer = errors.New("invalid token issuer")
)
