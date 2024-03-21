package routes

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sort"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/markbates/goth/gothic"
	"github.com/sameer-gits/godojo/auth"
)

func AuthCallbackHandler() {

	m := map[string]string{
		"github": "Github",
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	providerIndex := &ProviderIndex{Providers: keys, ProvidersMap: m}

	p := chi.NewRouter()

	p.Get("/auth/{provider}/callback", func(res http.ResponseWriter, req *http.Request) {

		q := req.URL.Query()
		q.Add("provider", chi.URLParam(req, "provider"))
		req.URL.RawQuery = q.Encode()

		user, err := gothic.CompleteUserAuth(res, req)
		if err != nil {
			fmt.Fprintln(res, err)
			return
		}

		session, err := auth.Store.Get(req, "go-cookie-session-name")
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}

		if session.Values == nil {
			session.Values = make(map[interface{}]interface{})
		}

		session.Values["user_id"] = user.UserID
		session.Values["access_token"] = user.AccessToken
		session.Values["name"] = user.Name
		session.Values["lastName"] = user.LastName
		session.Values["firstName"] = user.FirstName
		session.Values["email"] = user.Email
		session.Values["nickName"] = user.NickName
		session.Values["location"] = user.Location
		session.Values["avatarURL"] = user.AvatarURL
		session.Values["description"] = user.Description
		session.Values["expires_at"] = user.ExpiresAt
		session.Values["refresh_token"] = user.RefreshToken
		session.Save(req, res)

		log.Println(user)

		http.Redirect(res, req, "/", http.StatusTemporaryRedirect)
	})

	p.Get("/logout/{provider}", func(res http.ResponseWriter, req *http.Request) {

		session, err := auth.Store.Get(req, "go-cookie-session-name")
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}

		session.Options.MaxAge = -1
		session.Values = make(map[interface{}]interface{})
		err = session.Save(req, res)
		if err != nil {
			fmt.Sprintln(res, "Could not delete user session. error: %s", err)
		}

		res.Header().Set("Location", "/")
		res.WriteHeader(http.StatusTemporaryRedirect)
	})
	p.Get("/auth/{provider}", func(res http.ResponseWriter, req *http.Request) {
		q := req.URL.Query()
		q.Add("provider", chi.URLParam(req, "provider"))
		req.URL.RawQuery = q.Encode()

		session, err := auth.Store.Get(req, "go-cookie-session-name")
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}

		if _, loggedIn := session.Values["user_id"]; loggedIn {
			// If user is already logged in, redirect to the homepage
			http.Redirect(res, req, "/", http.StatusSeeOther)
			return
		}

		// If user is not logged in, initiate the authentication flow
		gothic.BeginAuthHandler(res, req)
	})

	p.Get("/", func(res http.ResponseWriter, req *http.Request) {

		session, err := auth.Store.Get(req, "go-cookie-session-name")
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}

		userID := ""
		loggedIn := false
		accessToken := ""
		var (
			name, lastName, firstName, email, nickName, location, avatarURL, description, refreshToken string
			expiresAt                                                                                  time.Time
		)

		if val, ok := session.Values["user_id"]; ok {
			loggedIn = true
			userID = val.(string)
			accessToken, _ = session.Values["access_token"].(string)
			name, _ = session.Values["name"].(string)
			lastName, _ = session.Values["lastName"].(string)
			firstName, _ = session.Values["firstName"].(string)
			email, _ = session.Values["email"].(string)
			nickName, _ = session.Values["nickName"].(string)
			location, _ = session.Values["location"].(string)
			avatarURL, _ = session.Values["avatarURL"].(string)
			description, _ = session.Values["description"].(string)
			expiresAt, _ = session.Values["expires_at"].(time.Time)
			refreshToken, _ = session.Values["refresh_token"].(string)
		}

		t, err := template.New("foo").Parse(indexTemplate)
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}

		t.Execute(res, struct {
			ProviderIndex *ProviderIndex
			LoggedIn      bool
			AccessToken   string
			UserID        string
			Name          string
			LastName      string
			FirstName     string
			Email         string
			NickName      string
			Location      string
			AvatarURL     string
			Description   string
			ExpiresAt     time.Time
			RefreshToken  string
		}{providerIndex, loggedIn, accessToken, userID, name, lastName, firstName, email, nickName, location, avatarURL, description, expiresAt, refreshToken})

	})
	log.Println("listening on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", p))
}

type ProviderIndex struct {
	Providers    []string
	ProvidersMap map[string]string
}

var indexTemplate = `
{{if not .LoggedIn}}
    {{range $key, $value := .ProviderIndex.Providers}}
        <p><a href="/auth/{{$value}}">Log in with {{index $.ProviderIndex.ProvidersMap $value}}</a></p>
    {{end}}
{{else}}
    {{range $key, $value := .ProviderIndex.Providers}}
        <p>User Id: {{$.UserID}}</p>
        <p>Access Token: {{$.AccessToken}}</p>
        <p>Name: {{$.Name}} [{{$.LastName}}, {{$.FirstName}}]</p>
        <p>Email: {{$.Email}}</p>
        <p>NickName: {{$.NickName}}</p>
        <p>Location: {{$.Location}}</p>
        <p>AvatarURL: {{$.AvatarURL}} <img src="{{$.AvatarURL}}"></p>
        <p>Description: {{$.Description}}</p>
        <p>ExpiresAt: {{$.ExpiresAt}}</p>
        <p>RefreshToken: {{$.RefreshToken}}</p>
        <p><a href="/logout/{{$value}}">Logout using {{index $.ProviderIndex.ProvidersMap $value}}</a></p>
    {{end}}
{{end}}
`
