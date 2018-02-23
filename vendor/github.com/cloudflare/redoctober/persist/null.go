package persist

import (
	"errors"

	"github.com/cloudflare/redoctober/config"
	"github.com/cloudflare/redoctober/keycache"
	"github.com/cloudflare/redoctober/passvault"
)

// Null is a non-persisting store. It is used when persistence is not
// activated.
type Null struct {
	config *config.Delegations
}

func newNull(config *config.Delegations) (Store, error) {
	return &Null{config: config}, nil
}

func (n *Null) Blob() []byte {
	return nil
}

func (n *Null) Policy() string {
	return n.config.Policy
}

func (n *Null) Users() []string {
	return n.config.Users
}

func (n *Null) Store(bs []byte) error {
	return nil
}

func (n *Null) Load() error {
	return nil
}

func (n *Null) Persist() {
	return
}

func (n *Null) Status() *Status {
	return &Status{
		State:   Disabled,
		Summary: nil,
	}
}

func (n *Null) Delegate(record passvault.PasswordRecord, name, password string, users, labels []string, uses int, slot, durationString string) error {
	return errors.New("persist: null store does not support delegations")
}

func (n *Null) Cache() *keycache.Cache {
	cache := keycache.NewCache()
	return &cache
}

func (n *Null) Purge() error {
	return nil
}
