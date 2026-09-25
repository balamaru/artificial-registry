package registry

import (
	"net/http"
	"strings"
)

// Namespace administrators may discover active accounts to assign membership,
// without receiving registry roles, other namespace grants, or password data.
func (a *App) memberCandidates(w http.ResponseWriter, r *http.Request, u actor) {
	if !a.allowed(r, u, "members") {
		problem(w, 403, "forbidden")
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(query) > 254 {
		problem(w, 400, "search query too long")
		return
	}
	limit, offset := pageLimit(r), pageOffset(r)
	rows, err := a.db.Query(r.Context(), `SELECT p.subject,COALESCE(u.username,''),COALESCE(u.email,'')
FROM principals p LEFT JOIN users u USING(subject)
WHERE NOT p.disabled AND ($1='' OR strpos(lower(COALESCE(u.username,'')),lower($1))>0
 OR strpos(lower(COALESCE(u.email,'')),lower($1))>0 OR strpos(lower(p.subject),lower($1))>0)
ORDER BY lower(COALESCE(u.username,'')),p.subject LIMIT $2 OFFSET $3`, query, limit+1, offset)
	if err != nil {
		problem(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := []map[string]string{}
	for rows.Next() {
		var subject, username, email string
		if rows.Scan(&subject, &username, &email) != nil {
			problem(w, 500, "database error")
			return
		}
		items = append(items, map[string]string{"subject": subject, "username": username, "email": email})
	}
	if rows.Err() != nil {
		problem(w, 500, "database error")
		return
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	respond(w, 200, map[string]any{"items": items, "has_more": hasMore})
}
