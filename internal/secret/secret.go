// Package secret reads credentials from the host's credential store. The
// config file names items; values never touch the config, state, or logs.
package secret

import (
	"context"
	"errors"
)

// Service is the credential-store service (Keychain) or target (Credential
// Manager) name under which bivouac keeps its items.
const Service = "bivouac"

// ErrNotFound reports a missing item.
var ErrNotFound = errors.New("secret not found")

// Store is a named-item credential store.
type Store interface {
	Get(ctx context.Context, name string) ([]byte, error)
	Set(ctx context.Context, name string, value []byte) error
	Delete(ctx context.Context, name string) error
}

// Memory is an in-memory store for tests.
type Memory map[string][]byte

// Get implements Store.
func (m Memory) Get(_ context.Context, name string) ([]byte, error) {
	v, ok := m[name]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

// Set implements Store.
func (m Memory) Set(_ context.Context, name string, value []byte) error {
	m[name] = append([]byte(nil), value...)
	return nil
}

// Delete implements Store.
func (m Memory) Delete(_ context.Context, name string) error {
	delete(m, name)
	return nil
}
