package registry

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

const authSchema = `
CREATE TABLE IF NOT EXISTS users (subject text PRIMARY KEY, email text NOT NULL UNIQUE, username text NOT NULL UNIQUE, password_hash bytea NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS sessions (hash text PRIMARY KEY, subject text NOT NULL, expires_at timestamptz NOT NULL);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS auth_limits (key text PRIMARY KEY, attempts integer NOT NULL, reset_at timestamptz NOT NULL);
`

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func tokenHash(s string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(s))) }
func (a *App) cookie(w http.ResponseWriter, name, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(a.publicURL, "https://"), SameSite: http.SameSiteLaxMode, MaxAge: age})
}
func (a *App) newSession(w http.ResponseWriter, r *http.Request, subject string) bool {
	token := randomToken()
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		problem(w, 500, "database error")
		return false
	}
	defer tx.Rollback(r.Context())
	_, err = tx.Exec(r.Context(), "DELETE FROM sessions WHERE expires_at < now()")
	if err == nil {
		if old, e := r.Cookie("registry_session"); e == nil {
			_, err = tx.Exec(r.Context(), "DELETE FROM sessions WHERE hash=$1", tokenHash(old.Value))
		}
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), "INSERT INTO sessions(hash,subject,expires_at) VALUES($1,$2,now()+interval '24 hours')", tokenHash(token), subject)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		problem(w, 500, "database error")
		return false
	}
	a.cookie(w, "registry_session", token, 86400)
	return true
}
func (a *App) auth(next endpoint) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h := strings.Fields(r.Header.Get("Authorization")); len(h) > 0 {
			if len(h) != 2 || !strings.EqualFold(h[0], "Bearer") {
				problem(w, 401, "invalid authorization")
				return
			}
			if a.mode == "dev" && subtle.ConstantTimeCompare([]byte(h[1]), []byte(a.devToken)) == 1 {
				a.serveActor(w, r, "dev-user", next, true)
				return
			}
			if a.verifier != nil {
				token, err := a.verifier.Verify(r.Context(), h[1])
				if err == nil && token.Subject != "" && !strings.HasPrefix(token.Subject, "local:") {
					a.serveActor(w, r, token.Subject, next, true)
					return
				}
			}
			problem(w, 401, "invalid token")
			return
		}
		c, err := r.Cookie("registry_session")
		if err != nil {
			problem(w, 401, "login required")
			return
		}
		var subject string
		if a.db.QueryRow(r.Context(), "SELECT subject FROM sessions WHERE hash=$1 AND expires_at>now()", tokenHash(c.Value)).Scan(&subject) != nil {
			problem(w, 401, "session expired")
			return
		}
		a.serveActor(w, r, subject, next, false)
	}
}

// Custom header plus an exact Origin check prevents cross-origin cookie writes.
func (a *App) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
			if origin := r.Header.Get("Origin"); origin != "" && origin != a.publicURL {
				problem(w, 403, "invalid origin")
				return
			}
			if _, err := r.Cookie("registry_session"); err == nil && r.Header.Get("Authorization") == "" && r.Header.Get("X-Registry-CSRF") != "1" {
				problem(w, 403, "CSRF header required")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
func (a *App) authLimit(w http.ResponseWriter, r *http.Request) bool {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	var n int
	err = a.db.QueryRow(r.Context(), `INSERT INTO auth_limits(key,attempts,reset_at) VALUES($1,1,now()+interval '15 minutes') ON CONFLICT(key) DO UPDATE SET attempts=CASE WHEN auth_limits.reset_at<now() THEN 1 ELSE auth_limits.attempts+1 END, reset_at=CASE WHEN auth_limits.reset_at<now() THEN now()+interval '15 minutes' ELSE auth_limits.reset_at END RETURNING attempts`, tokenHash(ip)).Scan(&n)
	if err != nil {
		problem(w, 503, "authentication unavailable")
		return false
	}
	if n > 20 {
		w.Header().Set("Retry-After", "900")
		problem(w, 429, "too many attempts; try again in 15 minutes")
		return false
	}
	return true
}
func (a *App) register(w http.ResponseWriter, r *http.Request) {
	if a.mode == "oidc" || !a.registration {
		problem(w, 403, "local registration disabled")
		return
	}
	if !a.authLimit(w, r) {
		return
	}
	var v newUser
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&v) != nil || !v.validate() {
		problem(w, 400, "valid email, username, and password of 12–72 bytes required")
		return
	}
	// Public registration cannot assign roles or grants.
	v.SystemRole = ""
	v.Grants = nil
	sub, err := a.createLocalAccount(r.Context(), v, nil)
	if err != nil {
		accountError(w, err)
		return
	}
	if a.newSession(w, r, sub) {
		respond(w, 201, map[string]string{"subject": sub, "username": v.Username, "email": v.Email})
	}

}

var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password-for-timing"), 12)

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if a.mode == "oidc" {
		problem(w, 403, "use SSO login")
		return
	}
	if !a.authLimit(w, r) {
		return
	}
	var v struct{ Login, Password string }
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&v) != nil || len(v.Password) > 72 {
		problem(w, 400, "invalid login")
		return
	}
	var sub string
	var hash []byte
	err := a.db.QueryRow(r.Context(), "SELECT u.subject,u.password_hash FROM users u JOIN principals p USING(subject) WHERE (email=$1 OR username=$1) AND NOT p.disabled", strings.ToLower(strings.TrimSpace(v.Login))).Scan(&sub, &hash)
	if err != nil {
		hash = dummyHash
	}
	valid := bcrypt.CompareHashAndPassword(hash, []byte(v.Password))
	if err != nil || valid != nil {
		problem(w, 401, "invalid credentials")
		return
	}
	if a.newSession(w, r, sub) {
		respond(w, 200, map[string]string{"subject": sub})
	}
}
func (a *App) me(w http.ResponseWriter, r *http.Request, u actor) {
	var email, username string
	_ = a.db.QueryRow(r.Context(), "SELECT email,username FROM users WHERE subject=$1", u.Subject).Scan(&email, &username)
	respond(w, 200, map[string]any{"subject": u.Subject, "email": email, "username": username, "system_role": map[bool]string{true: "super-admin", false: "user"}[a.systemAdmin(r.Context(), u)], "can_create_namespace": a.canCreateNamespace(r.Context(), u)})
}
func (a *App) logout(w http.ResponseWriter, r *http.Request, u actor) {
	if c, err := r.Cookie("registry_session"); err == nil {
		if _, err = a.db.Exec(r.Context(), "DELETE FROM sessions WHERE hash=$1", tokenHash(c.Value)); err != nil {
			problem(w, 500, "database error")
			return
		}
	}
	a.cookie(w, "registry_session", "", -1)
	w.WriteHeader(204)
}
func (a *App) oidcLogin(w http.ResponseWriter, r *http.Request) {
	if a.oauth == nil {
		problem(w, 404, "SSO not configured")
		return
	}
	state, nonce, verifier := randomToken(), randomToken(), oauth2.GenerateVerifier()
	a.cookie(w, "oidc_state", state, 600)
	a.cookie(w, "oidc_nonce", nonce, 600)
	a.cookie(w, "oidc_verifier", verifier, 600)
	http.Redirect(w, r, a.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce)), http.StatusFound)
}
func (a *App) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if a.oauth == nil {
		problem(w, 404, "SSO not configured")
		return
	}
	state, e1 := r.Cookie("oidc_state")
	nonce, e2 := r.Cookie("oidc_nonce")
	verifier, e3 := r.Cookie("oidc_verifier")
	for _, name := range []string{"oidc_state", "oidc_nonce", "oidc_verifier"} {
		a.cookie(w, name, "", -1)
	}
	if e1 != nil || e2 != nil || e3 != nil || state.Value == "" || subtle.ConstantTimeCompare([]byte(state.Value), []byte(r.URL.Query().Get("state"))) != 1 {
		problem(w, 400, "invalid SSO state")
		return
	}
	token, err := a.oauth.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(verifier.Value))
	if err != nil {
		problem(w, 401, "SSO exchange failed")
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		problem(w, 401, "missing ID token")
		return
	}
	id, err := a.loginVerifier.Verify(r.Context(), raw)
	if err != nil || id.Subject == "" || id.Nonce != nonce.Value || strings.HasPrefix(id.Subject, "local:") {
		problem(w, 401, "invalid ID token")
		return
	}
	a.serveActor(w, r, id.Subject, func(w http.ResponseWriter, r *http.Request, u actor) {
		if a.newSession(w, r, u.Subject) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
	}, true)
}
func validatePublicURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("PUBLIC_URL must be an origin without a trailing slash")
	}
	return nil
}
