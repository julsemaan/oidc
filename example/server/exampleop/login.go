package exampleop

import (
	"context"
	"encoding/json"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/zitadel/oidc/v3/example/server/storage"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/oauth2"
)

var BitsEndpoint = oauth2.Endpoint{
	AuthURL:       "https://bits.linode.com/login/oauth/authorize",
	TokenURL:      "https://bits.linode.com/login/oauth/access_token",
	DeviceAuthURL: "https://bits.linode.com/login/device/code",
}

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
		ClientID:     os.Getenv("GH_CLIENT_ID"),
		ClientSecret: os.Getenv("GH_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:9998/login/github/callback",
		Scopes:       []string{"user", "user:email"},
		Endpoint:     BitsEndpoint,
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
	SetRequestAuthenticated(info *storage.GhUserInfo, id string) error
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
		return
	}
	ts := l.oauth2Conf.TokenSource(context.Background(), tok)
	client := oauth2.NewClient(context.Background(), ts)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		renderLogin(w, err.Error(), err)
		return
	}

	loginInfo := storage.GhUserInfo{}

	err = json.NewDecoder(resp.Body).Decode(&loginInfo)
	if err != nil {
		renderLogin(w, err.Error(), err)
		return
	}

	l.authenticate.SetRequestAuthenticated(&loginInfo, r.FormValue("state"))

	http.Redirect(w, r, l.callback(r.Context(), r.FormValue("state")), http.StatusFound)
}
