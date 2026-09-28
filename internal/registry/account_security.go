package registry

import (
	"encoding/json"
	"net/http"
	"net/mail"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const accountSchema = `
ALTER TABLE principals DROP CONSTRAINT IF EXISTS principals_system_role_check;
ALTER TABLE principals ADD CONSTRAINT principals_system_role_check CHECK(system_role IN ('user','super-admin','user-delete'));
ALTER TABLE principals ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
CREATE TABLE IF NOT EXISTS personal_tokens (id text PRIMARY KEY, subject text NOT NULL REFERENCES principals(subject), name text NOT NULL, hash text NOT NULL UNIQUE, prefix text NOT NULL, grants jsonb NOT NULL, system_roles jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL, revoked_at timestamptz, last_used_at timestamptz);
ALTER TABLE personal_tokens ADD COLUMN IF NOT EXISTS parent_id text REFERENCES personal_tokens(id);
CREATE INDEX IF NOT EXISTS personal_tokens_parent ON personal_tokens(parent_id);
CREATE INDEX IF NOT EXISTS personal_tokens_subject ON personal_tokens(subject,created_at DESC);
`

func (a *App) canDeleteUsers(r *http.Request, u actor) bool {
	if p := requestToken(r.Context()); p != nil && !has(p.SystemRoles, "user-delete") && !has(p.SystemRoles, "super-admin") {
		return false
	}
	var yes bool
	_ = a.db.QueryRow(r.Context(), "SELECT system_role IN ('super-admin','user-delete') AND NOT disabled FROM principals WHERE subject=$1", u.Subject).Scan(&yes)
	return yes
}
func (a *App) deleteUser(w http.ResponseWriter, r *http.Request, u actor) {
	if !a.canDeleteUsers(r, u) {
		problem(w, 403, "super-admin or user-delete required")
		return
	}
	sub := r.PathValue("sub")
	if sub == u.Subject {
		problem(w, 409, "cannot delete yourself")
		return
	}
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer tx.Rollback(r.Context())
	if _, err = tx.Exec(r.Context(), "SELECT pg_advisory_xact_lock(741923106)"); err != nil {
		problem(w, 500, "database error")
		return
	}
	var actingRole string
	if tx.QueryRow(r.Context(), "SELECT system_role FROM principals WHERE subject=$1 AND NOT disabled", u.Subject).Scan(&actingRole) != nil || (actingRole != "super-admin" && actingRole != "user-delete") {
		problem(w, 403, "forbidden")
		return
	}
	var targetRole string
	if tx.QueryRow(r.Context(), "SELECT system_role FROM principals WHERE subject=$1 AND deleted_at IS NULL FOR UPDATE", sub).Scan(&targetRole) != nil {
		problem(w, 404, "user not found")
		return
	}
	fullAdmin := actingRole == "super-admin" && (requestToken(r.Context()) == nil || has(requestToken(r.Context()).SystemRoles, "super-admin"))
	if targetRole != "user" && !fullAdmin {
		problem(w, 403, "only super-admin may delete privileged users")
		return
	}
	// Retain only a disabled identity tombstone, preventing OIDC re-provisioning
	// and retaining skill/audit attribution. Credentials and memberships are removed.
	for _, query := range []string{
		"DELETE FROM sessions WHERE subject=$1",
		"UPDATE personal_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE subject=$1",
		"DELETE FROM role_bindings WHERE subject=$1",
		"DELETE FROM memberships WHERE subject=$1",
		"DELETE FROM users WHERE subject=$1",
		"UPDATE principals SET disabled=true,deleted_at=now(),system_role='user' WHERE subject=$1",
	} {
		if _, err = tx.Exec(r.Context(), query, sub); err != nil {
			problem(w, 500, "database error")
			return
		}
	}
	if auditTx(r.Context(), tx, u, "user.delete", "*", "", map[string]string{"subject": sub}) != nil || tx.Commit(r.Context()) != nil {
		problem(w, 500, "database error")
		return
	}
	w.WriteHeader(204)
}

func (a *App) changePassword(w http.ResponseWriter, r *http.Request, u actor) {
	if requestToken(r.Context()) != nil {
		problem(w, 403, "sign in interactively to change your password")
		return
	}
	if !a.authLimit(w, r) {
		return
	}
	var v struct {
		Current string  `json:"current_password"`
		New     string  `json:"new_password"`
		Email   *string `json:"email"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&v) != nil || len(v.Current) > 72 || len(v.New) < 12 || len(v.New) > 72 || v.Current == v.New {
		problem(w, 400, "provide current password and a different new password of 12–72 bytes")
		return
	}
	if v.Email != nil {
		email := strings.ToLower(strings.TrimSpace(*v.Email))
		v.Email = &email
		if email != "" {
			parsed, err := mail.ParseAddress(email)
			if err != nil || parsed.Address != email || len(email) > 254 {
				problem(w, 400, "invalid email")
				return
			}
		}
	}
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer tx.Rollback(r.Context())
	var hash []byte
	if tx.QueryRow(r.Context(), "SELECT u.password_hash FROM users u JOIN principals p USING(subject) WHERE u.subject=$1 AND NOT p.disabled FOR UPDATE OF p,u", u.Subject).Scan(&hash) != nil {
		problem(w, 409, "external passwords must be changed at your identity provider")
		return
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(v.Current)) != nil {
		problem(w, 403, "current password is incorrect")
		return
	}
	hash, err = bcrypt.GenerateFromPassword([]byte(v.New), 12)
	if err != nil {
		problem(w, 500, "password error")
		return
	}
	if _, err = tx.Exec(r.Context(), "UPDATE users SET password_hash=$2,must_change_password=false,email=CASE WHEN $3::text IS NULL THEN email ELSE NULLIF($3,'') END WHERE subject=$1", u.Subject, hash, v.Email); err != nil {
		accountError(w, err)
		return
	}
	if _, err = tx.Exec(r.Context(), "DELETE FROM sessions WHERE subject=$1", u.Subject); err != nil {
		problem(w, 500, "database error")
		return
	}
	if _, err = tx.Exec(r.Context(), "UPDATE personal_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE subject=$1", u.Subject); err != nil {
		problem(w, 500, "database error")
		return
	}
	if auditTx(r.Context(), tx, u, "user.password-change", "*", "", map[string]string{"subject": u.Subject}) != nil || tx.Commit(r.Context()) != nil {
		problem(w, 500, "database error")
		return
	}
	a.cookie(w, "registry_session", "", -1)
	w.WriteHeader(204)
}
