package registry

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

type tokenContextKey struct{}
type tokenPolicy struct {
	ID          string
	Grants      []grant
	SystemRoles []string
	Expires     time.Time
	Depth       int
}

func requestToken(ctx context.Context) *tokenPolicy {
	p, _ := ctx.Value(tokenContextKey{}).(*tokenPolicy)
	return p
}
func tokenRoles(p *tokenPolicy, ns string) []string {
	roles := []string{}
	for _, g := range p.Grants {
		if g.Namespace == "*" || g.Namespace == ns {
			roles = append(roles, g.Roles...)
		}
	}
	return roles
}
func tokenAllows(ctx context.Context, ns, permission string) bool {
	p := requestToken(ctx)
	return p == nil || has(permissionsFor(tokenRoles(p, ns)), permission)
}
func (a *App) ownerSystemAdmin(ctx context.Context, u actor) bool {
	var yes bool
	_ = a.db.QueryRow(ctx, "SELECT system_role='super-admin' AND NOT disabled FROM principals WHERE subject=$1", u.Subject).Scan(&yes)
	return yes
}
func (a *App) ownerPermissions(ctx context.Context, u actor, ns string) ([]string, error) {
	if a.ownerSystemAdmin(ctx, u) {
		return permissionsFor([]string{"admin"}), nil
	}
	var roles []string
	err := a.db.QueryRow(ctx, "SELECT COALESCE(array_agg(b.role),'{}') FROM role_bindings b JOIN principals p USING(subject) WHERE b.subject=$1 AND b.scope IN ('*',$2) AND NOT p.disabled", u.Subject, ns).Scan(&roles)
	return permissionsFor(roles), err
}

// Tokens are immutable capability snapshots. Validate the entire chain on every
// request so revoking or expiring any ancestor immediately disables descendants.
func (a *App) loadToken(ctx context.Context, id, subject string) (*tokenPolicy, error) {
	rows, err := a.db.Query(ctx, `WITH RECURSIVE chain AS (
 SELECT id,parent_id,grants,system_roles,expires_at,revoked_at,subject,0 AS depth FROM personal_tokens WHERE id=$1 AND subject=$2
 UNION ALL SELECT t.id,t.parent_id,t.grants,t.system_roles,t.expires_at,t.revoked_at,t.subject,c.depth+1 FROM personal_tokens t JOIN chain c ON t.id=c.parent_id WHERE c.depth<8
 ) SELECT id,parent_id,grants,system_roles,expires_at,revoked_at,subject,depth FROM chain ORDER BY depth`, id, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var policy *tokenPolicy
	var lastParent *string
	for rows.Next() {
		var current tokenPolicy
		var parent, revokedSubject *string
		var revoked *time.Time
		var grants, roles []byte
		if err = rows.Scan(&current.ID, &parent, &grants, &roles, &current.Expires, &revoked, &revokedSubject, &current.Depth); err != nil {
			return nil, err
		}
		if revoked != nil || !current.Expires.After(time.Now()) || revokedSubject == nil || *revokedSubject != subject || json.Unmarshal(grants, &current.Grants) != nil || json.Unmarshal(roles, &current.SystemRoles) != nil {
			return nil, errors.New("inactive token chain")
		}
		if policy == nil {
			policy = &current
		} else {
			policy.Depth = current.Depth
		}
		lastParent = parent
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if policy == nil || lastParent != nil {
		return nil, errors.New("invalid token chain")
	}
	return policy, nil
}
func (a *App) authenticatePAT(w http.ResponseWriter, r *http.Request, raw string, next endpoint) {
	var subject, id string
	err := a.db.QueryRow(r.Context(), "SELECT t.id,t.subject FROM personal_tokens t JOIN principals p USING(subject) WHERE t.hash=$1 AND NOT p.disabled", tokenHash(raw)).Scan(&id, &subject)
	if err != nil {
		problem(w, 401, "invalid or expired access token")
		return
	}
	policy, err := a.loadToken(r.Context(), id, subject)
	if err != nil {
		problem(w, 401, "invalid or expired access token")
		return
	}
	_, _ = a.db.Exec(r.Context(), "UPDATE personal_tokens SET last_used_at=now() WHERE id=$1", id)
	next(w, r.WithContext(context.WithValue(r.Context(), tokenContextKey{}, policy)), actor{subject})
}
func tokenAudit(ctx context.Context, detail any) any {
	if p := requestToken(ctx); p != nil {
		body, err := json.Marshal(detail)
		if err != nil {
			return detail
		}
		values := map[string]any{}
		if json.Unmarshal(body, &values) != nil {
			return detail
		}
		values["access_token_id"] = p.ID
		return values
	}
	return detail
}
func (a *App) tokenOptions(w http.ResponseWriter, r *http.Request, u actor) {
	parentID := r.URL.Query().Get("parent_id")
	if p := requestToken(r.Context()); p != nil {
		if parentID != "" && parentID != p.ID {
			problem(w, 403, "use your current token as parent")
			return
		}
		parentID = p.ID
	}
	if parentID != "" {
		parent, err := a.loadToken(r.Context(), parentID, u.Subject)
		if err != nil {
			problem(w, 404, "active parent token not found")
			return
		}
		respond(w, 200, map[string]any{"grants": parent.Grants, "system_roles": parent.SystemRoles, "expires_at": parent.Expires, "max_expiry_days": 365})
		return
	}
	rows, err := a.db.Query(r.Context(), "SELECT scope,array_agg(role ORDER BY role) FROM role_bindings WHERE subject=$1 GROUP BY scope ORDER BY scope", u.Subject)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer rows.Close()
	grants := []grant{}
	for rows.Next() {
		var g grant
		if rows.Scan(&g.Namespace, &g.Roles) != nil {
			problem(w, 500, "database error")
			return
		}
		grants = append(grants, g)
	}
	if rows.Err() != nil {
		problem(w, 500, "database error")
		return
	}
	system := []string{}
	if a.systemAdmin(r.Context(), u) {
		grants = []grant{{"*", []string{"admin"}}}
		system = []string{"super-admin", "user-delete"}
	} else if a.canDeleteUsers(r, u) {
		system = []string{"user-delete"}
	}
	respond(w, 200, map[string]any{"grants": grants, "system_roles": system, "max_expiry_days": 365})
}
func (a *App) createToken(w http.ResponseWriter, r *http.Request, u actor) {
	var v struct {
		ParentID    string   `json:"parent_id"`
		Name        string   `json:"name"`
		Grants      []grant  `json:"grants"`
		SystemRoles []string `json:"system_roles"`
		Days        int      `json:"expires_in_days"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&v) != nil {
		problem(w, 400, "invalid token request")
		return
	}
	v.Name = strings.TrimSpace(v.Name)
	if v.Days == 0 {
		v.Days = 30
	}
	if len(v.Name) < 1 || len(v.Name) > 80 || v.Days < 1 || v.Days > 365 || len(v.SystemRoles) > 2 || (len(v.Grants) == 0 && len(v.SystemRoles) == 0) {
		problem(w, 400, "name, explicit roles, and expiry of 1–365 days required")
		return
	}
	if p := requestToken(r.Context()); p != nil {
		if v.ParentID != "" && v.ParentID != p.ID {
			problem(w, 403, "use your current token as parent")
			return
		}
		v.ParentID = p.ID
	}
	var parent *tokenPolicy
	if v.ParentID != "" {
		var err error
		parent, err = a.loadToken(r.Context(), v.ParentID, u.Subject)
		if err != nil {
			problem(w, 404, "active parent token not found")
			return
		}
		if parent.Depth >= 8 {
			problem(w, 400, "maximum token depth is 8")
			return
		}
	}
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer tx.Rollback(r.Context())
	var subject string
	if tx.QueryRow(r.Context(), "SELECT subject FROM principals WHERE subject=$1 AND NOT disabled FOR UPDATE", u.Subject).Scan(&subject) != nil {
		problem(w, 403, "account unavailable")
		return
	}
	if err = validateGrants(r.Context(), tx, v.Grants); err != nil {
		problem(w, 400, "invalid namespace grants")
		return
	}
	for _, g := range v.Grants {
		owner, err := a.ownerPermissions(r.Context(), u, g.Namespace)
		if err != nil {
			problem(w, 500, "database error")
			return
		}
		for _, permission := range permissionsFor(g.Roles) {
			if !has(owner, permission) || (parent != nil && !has(permissionsFor(tokenRoles(parent, g.Namespace)), permission)) {
				problem(w, 403, "token permissions cannot exceed parent or current account permissions")
				return
			}
		}
	}
	for _, role := range v.SystemRoles {
		if (parent != nil && !has(parent.SystemRoles, role) && !(role == "user-delete" && has(parent.SystemRoles, "super-admin"))) || (role != "super-admin" && role != "user-delete") || (role == "super-admin" && !a.systemAdmin(r.Context(), u)) || (role == "user-delete" && !a.canDeleteUsers(r, u)) {
			problem(w, 403, "token registry role exceeds your privileges")
			return
		}
	}
	var count int
	if tx.QueryRow(r.Context(), "SELECT count(*) FROM personal_tokens WHERE subject=$1 AND revoked_at IS NULL AND expires_at>now()", u.Subject).Scan(&count) != nil {
		problem(w, 500, "database error")
		return
	}
	if count >= 20 {
		problem(w, 409, "revoke an active token before creating more (limit 20)")
		return
	}
	if v.Grants == nil {
		v.Grants = []grant{}
	}
	if v.SystemRoles == nil {
		v.SystemRoles = []string{}
	}
	id, raw := randomToken()[:32], "ar_pat_"+randomToken()
	expires := time.Now().UTC().Add(time.Duration(v.Days) * 24 * time.Hour)
	// Clamp requested lifetime to the remaining parent lifetime.
	if parent != nil && expires.After(parent.Expires) {
		expires = parent.Expires
	}
	var parentID any
	if parent != nil {
		parentID = parent.ID
	}
	grants, _ := json.Marshal(v.Grants)
	system, _ := json.Marshal(v.SystemRoles)
	_, err = tx.Exec(r.Context(), "INSERT INTO personal_tokens(id,subject,name,hash,prefix,grants,system_roles,expires_at,parent_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)", id, u.Subject, v.Name, tokenHash(raw), raw[:15], grants, system, expires, parentID)
	if err != nil || auditTx(r.Context(), tx, u, "token.create", "*", "", map[string]any{"token_id": id, "name": v.Name, "grants": v.Grants, "system_roles": v.SystemRoles, "expires_at": expires, "parent_id": parentID}) != nil || tx.Commit(r.Context()) != nil {
		problem(w, 500, "database error")
		return
	}
	respond(w, 201, map[string]any{"id": id, "token": raw, "expires_at": expires, "grants": v.Grants, "system_roles": v.SystemRoles, "parent_id": parentID})
}
func (a *App) listTokens(w http.ResponseWriter, r *http.Request, u actor) {
	root := ""
	if p := requestToken(r.Context()); p != nil {
		root = p.ID
	}
	rows, err := a.db.Query(r.Context(), `WITH RECURSIVE subtree AS (SELECT id FROM personal_tokens WHERE id=$2 AND subject=$1 UNION ALL SELECT t.id FROM personal_tokens t JOIN subtree s ON t.parent_id=s.id) SELECT id,name,prefix,grants,system_roles,created_at,expires_at,revoked_at,last_used_at,parent_id FROM personal_tokens WHERE subject=$1 AND ($2='' OR id IN (SELECT id FROM subtree)) ORDER BY created_at DESC LIMIT 100`, u.Subject, root)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := []any{}
	for rows.Next() {
		var id, name, prefix string
		var grants, roles json.RawMessage
		var created, expires time.Time
		var revoked, last *time.Time
		var parentID *string
		if rows.Scan(&id, &name, &prefix, &grants, &roles, &created, &expires, &revoked, &last, &parentID) != nil {
			problem(w, 500, "database error")
			return
		}
		items = append(items, map[string]any{"id": id, "name": name, "prefix": prefix, "grants": grants, "system_roles": roles, "created_at": created, "expires_at": expires, "revoked_at": revoked, "last_used_at": last, "parent_id": parentID})
	}
	if rows.Err() != nil {
		problem(w, 500, "database error")
		return
	}
	respond(w, 200, items)
}
func (a *App) revokeToken(w http.ResponseWriter, r *http.Request, u actor) {
	root := ""
	if p := requestToken(r.Context()); p != nil {
		root = p.ID
	}
	tx, err := a.db.Begin(r.Context())
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer tx.Rollback(r.Context())
	tag, err := tx.Exec(r.Context(), `WITH RECURSIVE subtree AS (SELECT id FROM personal_tokens WHERE id=$3 AND subject=$2 UNION ALL SELECT t.id FROM personal_tokens t JOIN subtree s ON t.parent_id=s.id), targets AS (SELECT id FROM personal_tokens WHERE id=$1 AND subject=$2 AND ($3='' OR id IN (SELECT id FROM subtree)) UNION ALL SELECT t.id FROM personal_tokens t JOIN targets s ON t.parent_id=s.id) UPDATE personal_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE subject=$2 AND id IN (SELECT id FROM targets)`, r.PathValue("id"), u.Subject, root)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	if tag.RowsAffected() == 0 {
		problem(w, 404, "token not found")
		return
	}
	if auditTx(r.Context(), tx, u, "token.revoke", "*", "", map[string]string{"token_id": r.PathValue("id")}) != nil || tx.Commit(r.Context()) != nil {
		problem(w, 500, "database error")
		return
	}
	w.WriteHeader(204)
}
