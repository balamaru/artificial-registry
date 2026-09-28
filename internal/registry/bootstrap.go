package registry

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

const bootstrapSchema = `
ALTER TABLE users ALTER COLUMN email DROP NOT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password boolean NOT NULL DEFAULT false;
`

// Run inside the serialized schema transaction. Existing installations are never
// assigned a new admin or password, including installations with deleted users.
func bootstrapAdmin(ctx context.Context, tx pgx.Tx) (string, error) {
	var initialized bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM principals) OR EXISTS(SELECT 1 FROM registry_settings WHERE key='bootstrap-admin')").Scan(&initialized); err != nil {
		return "", err
	}
	if initialized {
		return "", nil
	}
	password := randomToken()[:32]
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", err
	}
	subject := "local:" + randomToken()
	if _, err = tx.Exec(ctx, "INSERT INTO users(subject,email,username,password_hash,must_change_password) VALUES($1,NULL,'admin',$2,true)", subject, hash); err != nil {
		return "", err
	}
	if err = ensurePrincipal(ctx, tx, subject); err != nil {
		return "", err
	}
	if err = auditTx(ctx, tx, actor{subject}, "user.bootstrap", "*", "", map[string]string{"username": "admin"}); err != nil {
		return "", err
	}
	return password, nil
}

// Enforce the first-login restriction before dispatching any protected endpoint.
func (a *App) passwordGate(w http.ResponseWriter, r *http.Request, subject string) bool {
	var required bool
	err := a.db.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM users WHERE subject=$1 AND must_change_password)", subject).Scan(&required)
	if err != nil {
		problem(w, 503, "authentication unavailable")
		return false
	}
	if !required {
		return true
	}
	if requestToken(r.Context()) == nil && ((r.Method == "GET" && r.URL.Path == "/auth/me") || (r.Method == "POST" && (r.URL.Path == "/auth/password" || r.URL.Path == "/auth/logout"))) {
		return true
	}
	respond(w, 403, map[string]any{"error": "change your initial password before continuing", "code": "password_change_required"})
	return false
}
