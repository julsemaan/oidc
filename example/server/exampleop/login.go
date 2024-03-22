package exampleop

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-chi/chi/v5"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

type login struct {
	authenticate authenticate
	router       chi.Router
	callback     func(context.Context, string) string
	oauth2Conf   *oauth2.Config
}

func NewLogin(authenticate authenticate, callback func(context.Context, string) string, issuerInterceptor *op.IssuerInterceptor) *login {
	l := &login{
		authenticate: authenticate,
		callback:     callback,
	}
	l.oauth2Conf = &oauth2.Config{
		ClientID:     "ef2a2bdb6f8888ccdf6c",
		ClientSecret: "f1e3d845909e3c9ae8092acb1a71536076e27318",
		RedirectURL:  "http://localhost:9998/login/github/callback",
		Scopes:       []string{"user", "user:email"},
		Endpoint:     github.Endpoint,
	}
	l.createRouter(issuerInterceptor)
	return l
}

func (l *login) createRouter(issuerInterceptor *op.IssuerInterceptor) {
	l.router = chi.NewRouter()
	l.router.Get("/username", l.loginHandler)
	l.router.Get("/github/callback", issuerInterceptor.HandlerFunc(l.checkLoginHandler))
}

type authenticate interface {
	CheckUsernamePassword(username, password, id string) error
}

func (l *login) loginHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, l.oauth2Conf.AuthCodeURL(r.FormValue(queryAuthRequestID), oauth2.AccessTypeOffline), http.StatusFound)
}

func renderLogin(w http.ResponseWriter, id string, err error) {
	data := &struct {
		ID    string
		Error string
	}{
		ID:    id,
		Error: errMsg(err),
	}
	err = templates.ExecuteTemplate(w, "login", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (l *login) checkLoginHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	tok, err := l.oauth2Conf.Exchange(context.Background(), code)
	if err != nil {
		renderLogin(w, err.Error(), err)
	}
	ts := l.oauth2Conf.TokenSource(context.Background(), tok)
	client := oauth2.NewClient(context.Background(), ts)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		renderLogin(w, err.Error(), err)
	}

	loginInfo := struct {
		Login string `json:"login"`
	}{}

	err = json.NewDecoder(resp.Body).Decode(&loginInfo)
	if err != nil {
		renderLogin(w, err.Error(), err)
	}

	spew.Dump(loginInfo)

	http.Redirect(w, r, l.callback(r.Context(), r.FormValue("state")), http.StatusFound)
}
