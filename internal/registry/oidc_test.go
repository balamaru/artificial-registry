package registry

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

func TestOIDCLoginIntegration(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer, nonce, challenge string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}})
		case "/token":
			r.ParseForm()
			if r.Form.Get("code") != "valid-code" || oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier")) != challenge {
				http.Error(w, "bad PKCE", 400)
				return
			}
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"))
			if err != nil {
				t.Error(err)
				return
			}
			signed, err := jwt.Signed(signer).Claims(jwt.Claims{Issuer: issuer, Subject: "oidc-test-user", Audience: jwt.Audience{"registry-test"}, Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour))}).Claims(map[string]any{"nonce": nonce}).Serialize()
			if err != nil {
				t.Error(err)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "unused", "token_type": "Bearer", "id_token": signed})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	issuer = provider.URL
	t.Setenv("DATABASE_URL", dsn)
	t.Setenv("AUTH_MODE", "hybrid")
	t.Setenv("PUBLIC_URL", "http://localhost:8080")
	t.Setenv("OIDC_ISSUER", issuer)
	t.Setenv("OIDC_CLIENT_ID", "registry-test")
	t.Setenv("OIDC_AUDIENCE", "registry-test")
	t.Setenv("OIDC_CLIENT_SECRET", "")
	a, err := New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	handler := a.Handler()
	start := httptest.NewRecorder()
	handler.ServeHTTP(start, httptest.NewRequest("GET", "/auth/oidc/login", nil))
	if start.Code != 302 {
		t.Fatal(start.Body.String())
	}
	authURL, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := authURL.Query()
	nonce = q.Get("nonce")
	challenge = q.Get("code_challenge")
	if q.Get("code_challenge_method") != "S256" || nonce == "" || challenge == "" {
		t.Fatal("missing PKCE or nonce")
	}
	callback := func(state string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/auth/oidc/callback?code=valid-code&state="+url.QueryEscape(state), nil)
		for _, c := range start.Result().Cookies() {
			req.AddCookie(c)
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	if bad := callback("wrong-state"); bad.Code != 400 {
		t.Fatal("invalid state accepted")
	}
	savedNonce := nonce
	nonce = "wrong-nonce"
	if bad := callback(q.Get("state")); bad.Code != 401 {
		t.Fatalf("invalid nonce accepted: %d %s", bad.Code, bad.Body.String())
	}
	nonce = savedNonce
	valid := callback(q.Get("state"))
	if valid.Code != 303 {
		t.Fatalf("callback: %d %s", valid.Code, valid.Body.String())
	}
	var session *http.Cookie
	for _, c := range valid.Result().Cookies() {
		if c.Name == "registry_session" {
			session = c
		}
	}
	if session == nil {
		t.Fatal("no session")
	}
	req := httptest.NewRequest("GET", "/auth/me", nil)
	req.AddCookie(session)
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	if out.Code != 200 {
		t.Fatal(out.Body.String())
	}
	var profile map[string]string
	json.Unmarshal(out.Body.Bytes(), &profile)
	if profile["subject"] != "oidc-test-user" {
		t.Fatal(profile)
	}
}
