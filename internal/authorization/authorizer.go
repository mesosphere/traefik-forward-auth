package authorization

type Authorizer interface {
	Authorize(m map[string]interface{}) (bool, error)
}
