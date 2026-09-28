package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Existing feature tests use explicitly provisioned fixture accounts, never the
// public registration endpoint. Bootstrap behavior is tested separately below.
func provisionFixture(t *testing.T, a *App, name, password, role string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	var admin string
	if err := a.db.QueryRow(context.Background(), "SELECT subject FROM principals WHERE system_role='super-admin' AND NOT disabled LIMIT 1").Scan(&admin); err != nil {
		t.Fatal(err)
	}
	subject, err := a.createLocalAccount(context.Background(), newUser{Email: name + "@example.test", Username: name, Password: password, SystemRole: role}, &actor{admin})
	if err != nil {
		t.Fatal(err)
	}
	c := accountClient{t: t, app: a}
	w := c.request("POST", "/auth/login", map[string]string{"login": name, "password": password}, 200)
	return w, subject
}
func TestBootstrapMandatoryPasswordAndRestart(t *testing.T) {
	var logs bytes.Buffer
	old := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(old)
	a := testApp(t)
	matches := regexp.MustCompile(`temporary_password=([a-f0-9]{32})`).FindStringSubmatch(logs.String())
	if len(matches) != 2 {
		t.Fatal("missing one-time bootstrap password")
	}
	initial := matches[1]
	anon := accountClient{t: t, app: a}
	anon.request("POST", "/auth/register", map[string]string{"username": "attacker", "password": "attacker-password"}, 403)
	login := anon.request("POST", "/auth/login", map[string]string{"login": "admin", "password": initial}, 200)
	admin := accountClient{t: t, app: a, cookie: login.Result().Cookies()[0]}
	me := decodeAccount(t, admin.request("GET", "/auth/me", nil, 200))
	if me["must_change_password"] != true || me["system_role"] != "super-admin" || me["email"] != "" {
		t.Fatal("incorrect bootstrap profile")
	}
	for _, path := range []string{"/v1/namespaces", "/v1/admin/users", "/auth/tokens", "/v1/roles"} {
		admin.request("GET", path, nil, 403)
	}
	admin.request("POST", "/v1/namespaces", map[string]string{"name": "blocked"}, 403)
	admin.request("POST", "/auth/tokens", tokenRequest("blocked", "*", "admin", ""), 403)
	admin.request("POST", "/auth/password", map[string]string{"current_password": initial, "new_password": initial}, 400)
	admin.request("POST", "/auth/password", map[string]string{"current_password": "incorrect", "new_password": "new-admin-password"}, 403)
	admin.request("POST", "/auth/password", map[string]string{"current_password": initial, "new_password": "new-admin-password", "email": "bad-email"}, 400)
	admin.request("POST", "/auth/password", map[string]string{"current_password": initial, "new_password": "new-admin-password", "email": "owner@example.test"}, 204)
	admin.request("GET", "/auth/me", nil, 401)
	anon.request("POST", "/auth/login", map[string]string{"login": "admin", "password": initial}, 401)
	login = anon.request("POST", "/auth/login", map[string]string{"login": "owner@example.test", "password": "new-admin-password"}, 200)
	admin.cookie = login.Result().Cookies()[0]
	me = decodeAccount(t, admin.request("GET", "/auth/me", nil, 200))
	if me["must_change_password"] != false {
		t.Fatal("gate not cleared")
	}
	admin.request("POST", "/v1/namespaces", map[string]string{"name": "allowed"}, 201)
	admin.request("POST", "/v1/admin/users", map[string]any{"email": "member@example.test", "username": "member", "password": "member-password", "grants": []grant{{"allowed", []string{"read-only"}}}}, 201)
	admin.request("POST", "/auth/password", map[string]string{"current_password": "new-admin-password", "new_password": "third-admin-password", "email": "member@example.test"}, 409)
	admin.request("GET", "/v1/admin/users", nil, 200) // duplicate email rolls back password/session mutations
	logs.Reset()
	restarted, err := New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if strings.Contains(logs.String(), "temporary_password") {
		t.Fatal("password repeated on restart")
	}
	var hash []byte
	var count int
	if err = restarted.db.QueryRow(context.Background(), "SELECT password_hash FROM users WHERE username='admin'").Scan(&hash); err != nil || bcrypt.CompareHashAndPassword(hash, []byte("new-admin-password")) != nil {
		t.Fatal("restart replaced password")
	}
	if err = restarted.db.QueryRow(context.Background(), "SELECT count(*) FROM principals WHERE system_role='super-admin'").Scan(&count); err != nil || count != 1 {
		t.Fatal("duplicate admin")
	}
}
func TestBootstrapConcurrentStartup(t *testing.T) {
	t.Setenv("DATABASE_URL", isolatedDatabase(t))
	t.Setenv("AUTH_MODE", "local")
	t.Setenv("PUBLIC_URL", "http://localhost:8080")
	var logs bytes.Buffer
	old := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(old)
	var wg sync.WaitGroup
	apps := make(chan *App, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); a, err := New(context.Background()); apps <- a; errs <- err }()
	}
	wg.Wait()
	close(apps)
	close(errs)
	for a := range apps {
		if a != nil {
			defer a.Close()
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if strings.Count(logs.String(), "temporary_password=") != 1 {
		t.Fatal("bootstrap must print exactly once across replicas")
	}
}
func TestBootstrapOptionalEmailAndOIDCProvisioning(t *testing.T) {
	var logs bytes.Buffer
	old := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(old)
	a := testApp(t)
	password := regexp.MustCompile(`temporary_password=([a-f0-9]{32})`).FindStringSubmatch(logs.String())[1]
	a.mode = "oidc" // Test local admin exception and external provisioning without a provider network call.
	c := accountClient{t: t, app: a}
	w := c.request("POST", "/auth/login", map[string]string{"login": "admin", "password": password}, 200)
	c.cookie = w.Result().Cookies()[0]
	c.request("POST", "/auth/password", map[string]string{"current_password": password, "new_password": "changed-admin-password"}, 204)
	var email *string
	if err := a.db.QueryRow(context.Background(), "SELECT email FROM users WHERE username='admin'").Scan(&email); err != nil || email != nil {
		t.Fatal("optional email not null")
	}
	r := httptest.NewRequest("GET", "/auth/me", nil)
	w = httptest.NewRecorder()
	a.serveActor(w, r, "oidc-new-user", a.me, true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var profile map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &profile)
	if profile["system_role"] != "user" || profile["must_change_password"] != false {
		t.Fatal("OIDC identity incorrectly elevated or gated")
	}
}
