package routes

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sort"

	"github.com/gorilla/pat"
	"github.com/gorilla/sessions" // Import Gorilla sessions package
	"github.com/markbates/goth/gothic"
)

var store = sessions.NewCookieStore([]byte("your-secret-key")) // Replace "your-secret-key" with your secret key

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

		session, _ := store.Get(req, "go-session")
		session.Values["user_id"] = user.UserID
		session.Save(req, res)

		t, _ := template.New("foo").Parse(userTemplate)
		t.Execute(res, user)
	})

	p.Get("/logout/{provider}", func(res http.ResponseWriter, req *http.Request) {
		gothic.Logout(res, req)

		session, _ := store.Get(req, "go-session")
		delete(session.Values, "user_id")
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
		session, _ := store.Get(req, "go-session")
		_, loggedIn := session.Values["user_id"]

		t, _ := template.New("foo").Parse(indexTemplate)
		t.Execute(res, struct {
			ProviderIndex *ProviderIndex
			LoggedIn      bool
		}{providerIndex, loggedIn})

	})

	log.Println("listening on localhost:3000")
	log.Fatal(http.ListenAndServe(":3000", p))
}

type ProviderIndex struct {
	Providers    []string
	ProvidersMap map[string]string
}

var indexTemplate = `{{range $key,$value:=.ProviderIndex.Providers}}
<p><a href="/auth/{{$value}}">Log in with {{index $.ProviderIndex.ProvidersMap $value}}</a></p>
{{end}}
{{if .LoggedIn}}
<p>Welcome, {{.UserName}}!</p>
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
