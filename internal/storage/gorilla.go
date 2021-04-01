package storage

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"

	"github.com/mesosphere/traefik-forward-auth/internal/api/storage/v1alpha1"
	"github.com/mesosphere/traefik-forward-auth/internal/authentication"
)

type GorillaUserInfoStore struct {
	SessionStore sessions.Store
	SessionName  string

	Auth *authentication.Authenticator
}

func (c *GorillaUserInfoStore) Get(r *http.Request) (*v1alpha1.UserInfo, error) {
	session, _ := c.SessionStore.Get(r, c.SessionName)
	if session == nil {
		return nil, v1alpha1.UserDataStoreError(fmt.Sprintf("could not get session: %s", c.SessionName))
	}
	if session.IsNew {
		return nil, v1alpha1.UserDataStoreError(fmt.Sprintf("session did not exist: %s", c.SessionName))
	}

	data, ok := session.Values[UserInfoKey]
	if !ok {
		return nil, nil
	}

	userinfo := &v1alpha1.UserInfo{}
	if err := json.Unmarshal(data.([]byte), userinfo); err != nil {
		return nil, fmt.Errorf("error parsing userinfo: %w", err)
	}

	return userinfo, nil
}

func (c *GorillaUserInfoStore) Save(r *http.Request, w http.ResponseWriter, info *v1alpha1.UserInfo) error {
	session, _ := c.SessionStore.Get(r, c.SessionName)
	if session == nil {
		// should never happen
		return v1alpha1.UserDataStoreError("session is nil")
	}

	data, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("error mashelling userinfo: %w", err)
	}

	session.Values[UserInfoKey] = data
	session.Options.Domain = c.Auth.CookieDomain(r)
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
