package registry

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"
)

type newUser struct {
	Email      string  `json:"email"`
	Username   string  `json:"username"`
	Password   string  `json:"password"`
	SystemRole string  `json:"system_role"`
	Grants     []grant `json:"grants"`
}

func (v *newUser) validate() bool {
	v.Email = strings.ToLower(strings.TrimSpace(v.Email))
	v.Username = strings.ToLower(strings.TrimSpace(v.Username))
	email, err := mail.ParseAddress(v.Email)
	return err == nil && email.Address == v.Email && len(v.Email) <= 254 && identifier.MatchString(v.Username) && len(v.Password) >= 12 && len(v.Password) <= 72
}
func (a *App) createLocalAccount(ctx context.Context, v newUser, creator *actor) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(v.Password), 12)
	if err != nil {
		return "", err
	}
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	// Serialize all first-account creation before inserting the account itself.
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(741923106)"); err != nil {
		return "", err
	}
	sub := "local:" + randomToken()
	if _, err = tx.Exec(ctx, "INSERT INTO users(subject,email,username,password_hash) VALUES($1,$2,$3,$4)", sub, v.Email, v.Username, hash); err != nil {
		return "", err
	}
	if err = ensurePrincipal(ctx, tx, sub); err != nil {
		return "", err
	}
	by := actor{sub}
	if creator != nil {
		by = *creator
		if v.SystemRole == "" {
			v.SystemRole = "user"
		}
		if _, err = tx.Exec(ctx, "UPDATE principals SET system_role=$2 WHERE subject=$1", sub, v.SystemRole); err != nil {
			return "", err
		}
		if err = replaceGrants(ctx, tx, sub, v.Grants); err != nil {
			return "", err
		}
	}
	if err = auditTx(ctx, tx, by, "user.create", "*", "", map[string]any{"subject": sub, "username": v.Username, "system_role": v.SystemRole, "grants": v.Grants}); err != nil {
		return "", err
	}
	if err = tx.Commit(ctx); err != nil {
		return "", err
	}
	return sub, nil
}
func accountError(w http.ResponseWriter, err error) {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		problem(w, 409, "email or username unavailable")
		return
	}
	if errors.As(err, &pg) {
		problem(w, 500, "database error")
		return
	}
	problem(w, 400, err.Error())
}
func (a *App) createUser(w http.ResponseWriter, r *http.Request, u actor) {
	if !a.systemAdmin(r.Context(), u) {
		problem(w, 403, "super-admin required")
		return
	}
	if a.mode == "oidc" {
		problem(w, 409, "create accounts in your identity provider; manage grants after their first login")
		return
	}
	var v newUser
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&v) != nil || !v.validate() || (v.SystemRole != "" && v.SystemRole != "user" && v.SystemRole != "super-admin") {
		problem(w, 400, "valid email, username, password of 12–72 bytes, and system role required")
		return
	}
	sub, err := a.createLocalAccount(r.Context(), v, &u)
	if err != nil {
		accountError(w, err)
		return
	}
	// Creating another account must never replace the administrator's session.
	respond(w, 201, map[string]string{"subject": sub, "email": v.Email, "username": v.Username})
}
func (a *App) listUsers(w http.ResponseWriter, r *http.Request, u actor) {
	if !a.systemAdmin(r.Context(), u) {
		problem(w, 403, "super-admin required")
		return
	}
	rows, err := a.db.Query(r.Context(), `SELECT p.subject,COALESCE(u.email,''),COALESCE(u.username,''),p.system_role,p.disabled,u.subject IS NOT NULL,
 COALESCE((SELECT jsonb_agg(jsonb_build_object('namespace',g.scope,'roles',g.roles) ORDER BY g.scope) FROM (SELECT scope,array_agg(role ORDER BY role) AS roles FROM role_bindings WHERE subject=p.subject GROUP BY scope) g),'[]'::jsonb)
 FROM principals p LEFT JOIN users u USING(subject) WHERE $1='' OR u.username ILIKE '%'||$1||'%' OR u.email ILIKE '%'||$1||'%' OR p.subject=$1 ORDER BY p.created_at,p.subject LIMIT $2 OFFSET $3`, r.URL.Query().Get("q"), pageLimit(r), pageOffset(r))
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := []any{}
	for rows.Next() {
		var sub, email, name, role string
		var disabled, local bool
		var grants json.RawMessage
		if rows.Scan(&sub, &email, &name, &role, &disabled, &local, &grants) != nil {
			problem(w, 500, "database error")
			return
		}
		items = append(items, map[string]any{"subject": sub, "email": email, "username": name, "system_role": role, "disabled": disabled, "local": local, "grants": grants})
	}
	if rows.Err() != nil {
		problem(w, 500, "database error")
		return
	}
	respond(w, 200, items)
}
func (a *App) updateUser(w http.ResponseWriter, r *http.Request, u actor) {
	if !a.systemAdmin(r.Context(), u) {
		problem(w, 403, "super-admin required")
		return
	}
	var v struct {
		SystemRole string `json:"system_role"`
		Disabled   *bool  `json:"disabled"`
		Password   string `json:"password"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&v) != nil || (v.SystemRole != "" && v.SystemRole != "user" && v.SystemRole != "super-admin") || (v.Password != "" && (len(v.Password) < 12 || len(v.Password) > 72)) {
		problem(w, 400, "invalid account update")
		return
	}
	sub := r.PathValue("sub")
	if sub == u.Subject && (v.SystemRole == "user" || (v.Disabled != nil && *v.Disabled)) {
		problem(w, 409, "cannot demote or disable yourself")
		return
	}
	var hash []byte
	var err error
	if v.Password != "" {
		hash, err = bcrypt.GenerateFromPassword([]byte(v.Password), 12)
		if err != nil {
			problem(w, 500, "password error")
			return
		}
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
	var authorized bool
	if tx.QueryRow(r.Context(), "SELECT system_role='super-admin' AND NOT disabled FROM principals WHERE subject=$1", u.Subject).Scan(&authorized) != nil || !authorized {
		problem(w, 403, "super-admin required")
		return
	}
	var role string
	var disabled bool
	if tx.QueryRow(r.Context(), "SELECT system_role,disabled FROM principals WHERE subject=$1 FOR UPDATE", sub).Scan(&role, &disabled) != nil {
		problem(w, 404, "user not found")
		return
	}
	if v.SystemRole != "" {
		role = v.SystemRole
	}
	if v.Disabled != nil {
		disabled = *v.Disabled
	}
	if len(hash) > 0 {
		tag, e := tx.Exec(r.Context(), "UPDATE users SET password_hash=$2 WHERE subject=$1", sub, hash)
		if e != nil {
			problem(w, 500, "database error")
			return
		}
		if tag.RowsAffected() == 0 {
			problem(w, 409, "external passwords must be changed at the identity provider")
			return
		}
	}
	if _, err = tx.Exec(r.Context(), "UPDATE principals SET system_role=$2,disabled=$3 WHERE subject=$1", sub, role, disabled); err != nil {
		problem(w, 500, "database error")
		return
	}
	if disabled || len(hash) > 0 {
		if _, err = tx.Exec(r.Context(), "DELETE FROM sessions WHERE subject=$1", sub); err != nil {
			problem(w, 500, "database error")
			return
		}
	}
	if auditTx(r.Context(), tx, u, "user.update", "*", "", map[string]any{"subject": sub, "system_role": role, "disabled": disabled, "password_reset": len(hash) > 0}) != nil || tx.Commit(r.Context()) != nil {
		problem(w, 500, "database error")
		return
	}
	w.WriteHeader(204)
}
func (a *App) userGrants(w http.ResponseWriter, r *http.Request, u actor) {
	if !a.systemAdmin(r.Context(), u) {
		problem(w, 403, "super-admin required")
		return
	}
	var v struct {
		Grants []grant `json:"grants"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&v) != nil {
		problem(w, 400, "invalid grants")
		return
	}
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer tx.Rollback(r.Context())
	var sub string
	if tx.QueryRow(r.Context(), "SELECT subject FROM principals WHERE subject=$1 FOR UPDATE", r.PathValue("sub")).Scan(&sub) != nil {
		problem(w, 404, "user not found")
		return
	}
	if err = replaceGrants(r.Context(), tx, sub, v.Grants); err != nil {
		accountError(w, err)
		return
	}
	if auditTx(r.Context(), tx, u, "user.grants", "*", "", map[string]any{"subject": sub, "grants": v.Grants}) != nil || tx.Commit(r.Context()) != nil {
		problem(w, 500, "database error")
		return
	}
	w.WriteHeader(204)
}
