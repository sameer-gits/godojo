package routes

import (
	"net/http"

	"github.com/sameer-gits/godojo/auth"
)

func MyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		session, err := auth.Store.Get(req, "go-cookie-session-name")
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}

		userID, ok := session.Values["user_id"].(string)
		if !ok {
			http.Error(res, "User ID not found in session", http.StatusInternalServerError)
			return
		}

		if userID == "" {
			http.Redirect(res, req, "/login", http.StatusFound)
			return
		}

		next.ServeHTTP(res, req)
	})
}
