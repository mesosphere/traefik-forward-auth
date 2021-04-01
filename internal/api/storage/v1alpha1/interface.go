package v1alpha1

import "net/http"

type UserInfoInterface interface {
	Clear(r *http.Request, w http.ResponseWriter) error
	Get(r *http.Request) (*UserInfo, error)
	Save(r *http.Request, w http.ResponseWriter, info *UserInfo) error
}
