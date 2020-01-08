package authorization

type Authorizer interface {
	Authorize(user User, requestVerb, requestResource string) (bool, error)
}
