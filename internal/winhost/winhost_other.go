//go:build !windows

// Package winhost holds Windows host checks shared by Windows-hosted providers.
// Other hosts have no matching ACL model, so protection checks refuse.
package winhost

import (
	"errors"
	"os"
)

func CheckProtected(string) error {
	return errors.New("protected storage checks require Windows")
}

func CheckProtectedParents(string) error {
	return errors.New("protected storage checks require Windows")
}

func PrivateDirectory(base string) (string, error) {
	return os.MkdirTemp(base, "bivouac-transfer-")
}

func OpenSSH() (string, string, error) {
	return "", "", errors.New("windows guest transport requires Windows")
}
