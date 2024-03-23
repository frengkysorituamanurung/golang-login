package handlers

import "net/http"

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Handle logout logic here (e.g., clearing session, cookies, etc.).
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
