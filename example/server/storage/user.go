package storage

import (
	"crypto/rsa"
	"strings"

	"golang.org/x/text/language"
)

type GhUserInfo struct {
	Login            string `json:"login"`
	Email            string `json:"email"`
	Name             string `json:"name"`
	OrganizationsUrl string `json:"organizations_url"`
	UserOrgs         []*GhUserOrgs
}

type GhUserOrgs struct {
	OrgID           string   `json:"login"`
	TeamMemberships []string // This is built manually, not directly from unmarshaling
}

type User struct {
	ID                string
	Username          string
	Password          string
	FirstName         string
	LastName          string
	Email             string
	EmailVerified     bool
	Phone             string
	PhoneVerified     bool
	PreferredLanguage language.Tag
	IsAdmin           bool
	OrgMemberships    []OrgMembership
	Roles             []string
}

type OrgMembership struct {
	Name            string `json:"name"`
	TeamMemberships string `json:"team_memberships"`
}

type Service struct {
	keys map[string]*rsa.PublicKey
}

type UserStore interface {
	GetUserByID(string) *User
	GetUserByUsername(string) *User
	ExampleClientID() string
	SetUserByID(string, *User)
}

type userStore struct {
	users map[string]*User
}

func NewUserStore(issuer string) UserStore {
	hostname := strings.Split(strings.Split(issuer, "://")[1], ":")[0]
	return userStore{
		users: map[string]*User{
			"id1": {
				ID:                "id1",
				Username:          "test-user@" + hostname,
				Password:          "verysecure",
				FirstName:         "Test",
				LastName:          "User",
				Email:             "test-user@zitadel.ch",
				EmailVerified:     true,
				Phone:             "",
				PhoneVerified:     false,
				PreferredLanguage: language.German,
				IsAdmin:           true,
			},
			"id2": {
				ID:                "id2",
				Username:          "test-user2",
				Password:          "verysecure",
				FirstName:         "Test",
				LastName:          "User2",
				Email:             "test-user2@zitadel.ch",
				EmailVerified:     true,
				Phone:             "",
				PhoneVerified:     false,
				PreferredLanguage: language.German,
				IsAdmin:           false,
			},
		},
	}
}

// ExampleClientID is only used in the example server
func (u userStore) ExampleClientID() string {
	return "service"
}

func (u userStore) GetUserByID(id string) *User {
	return u.users[id]
}

func (u userStore) SetUserByID(id string, user *User) {
	//TODO MUTEX
	u.users[id] = user
}

func (u userStore) GetUserByUsername(username string) *User {
	for _, user := range u.users {
		if user.Username == username {
			return user
		}
	}
	return nil
}
