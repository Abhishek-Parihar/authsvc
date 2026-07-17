// Package authclient validates authsvc JWT access tokens via JWKS.
package authclient

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Validator caches JWKS keys and validates Bearer tokens locally.
type Validator struct {
	issuer   string
	jwksURL  string
	client   *http.Client
	mu       sync.RWMutex
	keys     map[string]*rsa.PublicKey
	refreshed time.Time
}

// Claims represents validated token claims from authsvc.
type Claims struct {
	Subject  string
	TenantID string
	Scope    string
	ClientID string
	jwt.RegisteredClaims
}

// New creates a JWKS-backed validator.
func New(issuer, jwksURL string) *Validator {
	return &Validator{
		issuer:  issuer,
		jwksURL: jwksURL,
		client:  &http.Client{Timeout: 10 * time.Second},
		keys:    make(map[string]*rsa.PublicKey),
	}
}

// Validate parses and validates a Bearer access token.
func (v *Validator) Validate(ctx context.Context, token string) (*Claims, error) {
	if err := v.refreshKeys(ctx); err != nil {
		return nil, err
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	var claims Claims
	parsed, err := jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method")
		}
		kid, _ := t.Header["kid"].(string)
		key, ok := v.keys[kid]
		if !ok {
			return nil, fmt.Errorf("unknown kid")
		}
		return key, nil
	}, jwt.WithIssuer(v.issuer), jwt.WithAudience("authsvc"))
	if err != nil || !parsed.Valid {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	return &claims, nil
}

// Middleware returns HTTP middleware that requires a valid Bearer token.
func (v *Validator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if _, err := v.Validate(r.Context(), token); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (v *Validator) refreshKeys(ctx context.Context) error {
	v.mu.RLock()
	stale := time.Since(v.refreshed) > 5*time.Minute || len(v.keys) == 0
	v.mu.RUnlock()
	if !stale {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var body struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return err
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, k := range body.Keys {
		pub, err := rsaPublicKeyFromModExp(k.N, k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}

	v.mu.Lock()
	v.keys = keys
	v.refreshed = time.Now()
	v.mu.Unlock()
	return nil
}

func rsaPublicKeyFromModExp(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}
