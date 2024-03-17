package routes

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"sort"

	"github.com/gorilla/pat"
	"github.com/gorilla/sessions" // Import Gorilla sessions package
	"github.com/joho/godotenv"
	"github.com/markbates/goth/gothic"
)

var store *sessions.CookieStore

func init() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	// Retrieve secret key from environment variable
	secretKey := os.Getenv("SECRET_KEY")

	// Initialize session store with secret key
	store = sessions.NewCookieStore([]byte(secretKey))
}

func AuthCallbackHandler() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	m := map[string]string{
		"github": "Github",
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	providerIndex := &ProviderIndex{Providers: keys, ProvidersMap: m}

	p := pat.New()

	p.Get("/auth/{provider}/callback", func(res http.ResponseWriter, req *http.Request) {
		user, err := gothic.CompleteUserAuth(res, req)
		if err != nil {
			fmt.Fprintln(res, err)
			return
		}

		session, err := store.Get(req, "go-cookie-session-name")
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}

		if session.Values == nil {
			session.Values = make(map[interface{}]interface{})
		}

		session.Values["user_id"] = user.UserID
		session.Values["access_token"] = user.AccessToken // Store user's name in the session
		session.Save(req, res)

		http.Redirect(res, req, "/", http.StatusTemporaryRedirect)
		fmt.Printf("user info: %s\n", user)
	})

	p.Get("/logout/{provider}", func(res http.ResponseWriter, req *http.Request) {
		gothic.Logout(res, req)
		if err := godotenv.Load(); err != nil {
			log.Fatal("Error loading .env file")
		}

		clientID := os.Getenv("GITHUB_KEY")
		clientSecret := os.Getenv("GITHUB_SECRET")

		session, _ := store.Get(req, "go-cookie-session-name")

		AccessToken, ok := session.Values["access_token"].(string)
		if !ok {
			fmt.Println("Access Token not found in session")
			return
		}

		err := revokeAccessToken(clientID, clientSecret, AccessToken)
		if err != nil {
			fmt.Printf("Error revoking access token: %s\n", err)
			return
		}
		delete(session.Values, "user_id")
		session.Options.MaxAge = -1
		session.Save(req, res)

		res.Header().Set("Location", "/")
		res.WriteHeader(http.StatusTemporaryRedirect)
	})

	p.Get("/auth/{provider}", func(res http.ResponseWriter, req *http.Request) {
		if gothUser, err := gothic.CompleteUserAuth(res, req); err == nil {
			t, _ := template.New("foo").Parse(userTemplate)
			t.Execute(res, gothUser)
		} else {
			gothic.BeginAuthHandler(res, req)
		}
	})

	p.Get("/", func(res http.ResponseWriter, req *http.Request) {
		session, _ := store.Get(req, "go-cookie-session-name")
		_, loggedIn := session.Values["user_id"]
		accessToken := ""
		if loggedIn {
			accessToken = session.Values["access_token"].(string)
		}

		t, _ := template.New("foo").Parse(indexTemplate)
		t.Execute(res, struct {
			ProviderIndex *ProviderIndex
			LoggedIn      bool
			AccessToken   string
		}{providerIndex, loggedIn, accessToken})
	})

	log.Println("listening on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", p))
}

func revokeAccessToken(clientID, clientSecret, AccessToken string) error {
	// Revoke the token from the token endpoint
	tokenRevokeURL := fmt.Sprintf("https://api.github.com/applications/%s/token", clientID)

	// Create JSON payload for the request
	payload := []byte(fmt.Sprintf(`{"access_token":"%s"}`, AccessToken))

	// Create HTTP client
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest("DELETE", tokenRevokeURL, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	// Set basic auth
	req.SetBasicAuth(clientID, clientSecret)

	// Send request
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	// Check response status code
	if res.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to revoke access token. Status code: %d", res.StatusCode)
	}

	fmt.Println("Access token revoked successfully on GitHub API")
	fmt.Println("Access token revoked locally")

	return nil
}

type ProviderIndex struct {
	Providers    []string
	ProvidersMap map[string]string
}

var indexTemplate = `{{range $key,$value:=.ProviderIndex.Providers}}
<p><a href="/auth/{{$value}}">Log in with {{index $.ProviderIndex.ProvidersMap $value}}</a></p>
{{end}}
{{if .LoggedIn}}
<p>Access Token, {{.AccessToken}}!</p>
<p><a href="/logout/github">Logout</a></p>
{{end}}
`

var userTemplate = `
<p><a href="/logout/{{.Provider}}">logout</a></p>
<p>Name: {{.Name}} [{{.LastName}}, {{.FirstName}}]</p>
<p>Email: {{.Email}}</p>
<p>NickName: {{.NickName}}</p>
<p>Location: {{.Location}}</p>
<p>AvatarURL: {{.AvatarURL}} <img src="{{.AvatarURL}}"></p>
<p>Description: {{.Description}}</p>
<p>UserID: {{.UserID}}</p>
<p>AccessToken: {{.AccessToken}}</p>
<p>ExpiresAt: {{.ExpiresAt}}</p>
<p>RefreshToken: {{.RefreshToken}}</p>
`
