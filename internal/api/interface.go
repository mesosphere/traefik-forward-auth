package api

import "net/http"

type StoreInterface interface {
	Clear(r *http.Request, w http.ResponseWriter) error
	Get(r *http.Request) (*UserInfo, error)
	Save(r *http.Request, w http.ResponseWriter, info *UserInfo) error
}
