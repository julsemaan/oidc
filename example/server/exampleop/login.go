package exampleop

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/go-chi/chi/v5"
	"github.com/inverse-inc/go-utils/sharedutils"
	"github.com/zitadel/oidc/v3/example/server/storage"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/oauth2"
)

var BitsEndpoint = oauth2.Endpoint{
	AuthURL:       "https://bits.linode.com/login/oauth/authorize",
	TokenURL:      "https://bits.linode.com/login/oauth/access_token",
	DeviceAuthURL: "https://bits.linode.com/login/device/code",
}

var BitsApiURL = "https://bits.linode.com/api/v3"

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
		//RedirectURL:  "http://localhost:9998/login/github/callback",
		RedirectURL: os.Getenv("GH_REDIRECT_URL"),
		Scopes:      []string{"user", "user:email", "read:org"},
		Endpoint:    BitsEndpoint,
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
	sharedutils.CheckError(err)
	ts := l.oauth2Conf.TokenSource(context.Background(), tok)
	client := oauth2.NewClient(context.Background(), ts)
	resp, err := client.Get(BitsApiURL + "/user")
	sharedutils.CheckError(err)

	loginInfo := &storage.GhUserInfo{}

	err = json.NewDecoder(resp.Body).Decode(loginInfo)
	sharedutils.CheckError(err)

	resp, err = client.Get(loginInfo.OrganizationsUrl)

	var userOrgs = []*storage.GhUserOrgs{}

	err = json.NewDecoder(resp.Body).Decode(&userOrgs)
	sharedutils.CheckError(err)

	// This is very naive here, probably needs a cache or better filtering in the API calls?
	for _, org := range userOrgs {
		u := fmt.Sprintf("%s/orgs/%s/teams", BitsApiURL, org.OrgID)
		resp, err := client.Get(u)
		sharedutils.CheckError(err)

		var orgTeams = []struct {
			Name string `json:"name"`
			// Not using members_url because it contains {/member} that needs to be stripped at the end, feels easier to just concat /members on top of the team URL
			Url string `json:"url"`
		}{}

		err = json.NewDecoder(resp.Body).Decode(&orgTeams)
		sharedutils.CheckError(err)

		for _, team := range orgTeams {
			resp, err := client.Get(team.Url + "/members")
			sharedutils.CheckError(err)

			var teamMembers = []struct {
				Login string `json:"login"`
			}{}
			err = json.NewDecoder(resp.Body).Decode(&teamMembers)
			sharedutils.CheckError(err)

			for _, teamMember := range teamMembers {
				if teamMember.Login == loginInfo.Login {
					fmt.Println("Adding", loginInfo.Login, "to", org.OrgID, "team", team.Name)
					org.TeamMemberships = append(org.TeamMemberships, team.Name)
				}
			}
		}
	}

	loginInfo.UserOrgs = userOrgs

	spew.Dump(loginInfo)

	l.authenticate.SetRequestAuthenticated(loginInfo, r.FormValue("state"))

	http.Redirect(w, r, l.callback(r.Context(), r.FormValue("state")), http.StatusFound)
}
