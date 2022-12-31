package storage

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"

	api "github.com/turnly/oauth-middleware/internal/api"
	"github.com/turnly/oauth-middleware/internal/authentication"
)

type GorillaUserInfoStore struct {
	SessionStore sessions.Store
	SessionName  string

	Auth *authentication.Authenticator
}

func (c *GorillaUserInfoStore) Get(r *http.Request) (*api.UserInfo, error) {
	session, _ := c.SessionStore.Get(r, c.SessionName)
	if session == nil {
		return nil, api.UserDataStoreError(fmt.Sprintf("could not get session: %s", c.SessionName))
	}
	if session.IsNew {
		return nil, api.UserDataStoreError(fmt.Sprintf("session did not exist: %s", c.SessionName))
	}

	data, ok := session.Values[UserInfoKey]
	if !ok {
		return nil, nil
	}

	store := &api.UserInfo{}
	if err := json.Unmarshal(data.([]byte), store); err != nil {
		return nil, fmt.Errorf("error parsing store: %w", err)
	}

	return store, nil
}

func (c *GorillaUserInfoStore) Save(r *http.Request, w http.ResponseWriter, info *api.UserInfo) error {
	session, _ := c.SessionStore.Get(r, c.SessionName)
	if session == nil {
		// should never happen
		return api.UserDataStoreError("session is nil")
	}

	data, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("error mashelling store: %w", err)
	}

	session.Values[UserInfoKey] = data
	session.Options.Domain = c.Auth.GetCookieDomain(r)
	if err := session.Save(r, w); err != nil {
		return fmt.Errorf("error saving session: %w", err)
	}
	return nil
}

func (c *GorillaUserInfoStore) Clear(r *http.Request, w http.ResponseWriter) error {
	session, _ := c.SessionStore.Get(r, c.SessionName)
	if session != nil && session.Options != nil {
		session.Options.MaxAge = -1
		if err := session.Save(r, w); err != nil {
			return fmt.Errorf("error setting session options: %w", err)
		}
	}
	return nil
}
