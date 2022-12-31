package api

import (
	"errors"
	"fmt"
)

var ErrUserDataStore = errors.New("userdata storage error")

func UserDataStoreError(msg string) error {
	return fmt.Errorf("%w: %s", ErrUserDataStore, msg)
}
