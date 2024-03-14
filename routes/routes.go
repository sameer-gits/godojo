package routes

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/markbates/goth/gothic"
)

// ContextKey represents a custom type for context keys to avoid collisions.
type ContextKey string

// Define some context keys.
const (
	ContextKeyProvider ContextKey = "provider"
)

type Server struct{}

func (s *Server) AuthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	provider := vars["provider"]
	r = r.WithContext(context.WithValue(r.Context(), ContextKeyProvider, provider))

	user, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		log.Println("Error completing user authentication:", err)
		http.Error(w, "Error completing user authentication", http.StatusInternalServerError)
		return
	}

	fmt.Println(user)
	// Handle authenticated user, for example, redirect or respond with user data.
}

func (s *Server) SetupRoutes() http.Handler {
	router := mux.NewRouter()
	router.HandleFunc("/auth/{provider}/callback", s.AuthCallbackHandler)
	return router
}
