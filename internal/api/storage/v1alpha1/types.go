package v1alpha1

type UserInfo struct {
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Groups   []string `json:"groups"`
}
