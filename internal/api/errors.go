package api

import (
	"errors"
	"fmt"
)

var ErrUserDataStore = errors.New("Oops, something went wrong with the user data store")

func UserDataStoreError(msg string) error {
	return fmt.Errorf("%w: %s", ErrUserDataStore, msg)
}
