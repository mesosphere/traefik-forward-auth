package authorization

type User struct {
	Name   string
	Groups []string
}

func (k *User) GetName() string {
	return k.Name
}

func (k *User) GetGroups() []string {
	return k.Groups
}
