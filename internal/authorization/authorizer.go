package authorization

// Authorizer is the interface for implementing user authorization (check to see if the user can perform the action)
type Authorizer interface {
	Authorize(user User, requestVerb, requestResource string) (bool, error)
}
