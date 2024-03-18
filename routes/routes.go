package routes

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sort"

	"github.com/gorilla/pat"
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

	p := pat.New()

	p.Get("/auth/{provider}/callback", func(res http.ResponseWriter, req *http.Request) {
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
		session.Values["access_token"] = user.AccessToken // Store user's name in the session
		session.Save(req, res)

		http.Redirect(res, req, "/", http.StatusTemporaryRedirect)
	})

	p.Get("/logout/{provider}", func(res http.ResponseWriter, req *http.Request) {
		gothic.Logout(res, req)

		session, err := auth.Store.Get(req, "go-cookie-session-name")
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}

		session.Options.MaxAge = -1
		session.Save(req, res)

		res.Header().Set("Location", "/")
		res.WriteHeader(http.StatusTemporaryRedirect)
	})
	p.Get("/auth/{provider}", func(res http.ResponseWriter, req *http.Request) {
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

	// p.Get("/", func(res http.ResponseWriter, req *http.Request) {
	// 	session, err := auth.Store.Get(req, "go-cookie-session-name")
	// 	if err != nil {
	// 		http.Error(res, err.Error(), http.StatusInternalServerError)
	// 		return
	// 	}

	// 	_, loggedIn := session.Values["user_id"]
	// 	accessToken := ""
	// 	if loggedIn {
	// 		accessToken = session.Values["access_token"].(string)
	// 	}

	// 	t, _ := template.New("foo").Parse(indexTemplate)
	// 	t.Execute(res, struct {
	// 		ProviderIndex *ProviderIndex
	// 		LoggedIn      bool
	// 		AccessToken   string
	// 	}{providerIndex, loggedIn, accessToken})
	// })

	p.Get("/", func(res http.ResponseWriter, req *http.Request) {
		session, err := auth.Store.Get(req, "go-cookie-session-name")
		if err != nil {
			http.Error(res, err.Error(), http.StatusInternalServerError)
			return
		}

		userID := ""
		loggedIn := false
		accessToken := ""

		if val, ok := session.Values["user_id"]; ok {
			loggedIn = true
			userID = val.(string)
		}

		if loggedIn {
			accessToken = session.Values["access_token"].(string)
		}

		t, _ := template.New("foo").Parse(indexTemplate)
		t.Execute(res, struct {
			ProviderIndex *ProviderIndex
			LoggedIn      bool
			AccessToken   string
			UserID        string // Adding UserID field
		}{providerIndex, loggedIn, accessToken, userID})
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
    <p><a href="/logout/{{$value}}">Logout using {{index $.ProviderIndex.ProvidersMap $value}}</a></p>
  {{end}}
{{end}}
`
