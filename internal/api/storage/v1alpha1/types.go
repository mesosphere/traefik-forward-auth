package v1alpha1

type UserInfo struct {
	Subject  string   `json:"subject"`
	SID      string   `json:"sid"`
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Groups   []string `json:"groups"`
}
