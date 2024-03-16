package auth

import (
	"log"
	"os"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/github"
)

var store *sessions.CookieStore

func Auth() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	secretKey := os.Getenv("SECRET_KEY")
	githubKey := os.Getenv("GITHUB_KEY")
	githubSecret := os.Getenv("GITHUB_SECRET")

	key := secretKey     // Replace with your SESSION_SECRET or similar
	maxAge := 86400 * 30 // 30 days
	isProd := false      // Set to true when serving over HTTPS

	store = sessions.NewCookieStore([]byte(key))
	store.MaxAge(maxAge)
	store.Options.Path = "/"
	store.Options.HttpOnly = true // HttpOnly should always be enabled
	store.Options.Secure = isProd

	gothic.Store = store

	goth.UseProviders(
		github.New(githubKey, githubSecret, "http://localhost:3000/auth/github/callback"),
	)
}
