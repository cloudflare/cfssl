package persist

import (
	"io/ioutil"
	"os"

	"github.com/cloudflare/redoctober/config"
	"github.com/cloudflare/redoctober/keycache"
	"github.com/cloudflare/redoctober/passvault"
)

// File implements a file-backed persistence store.
type File struct {
	config *config.Delegations
	cache  *keycache.Cache
	state  string
	blob   []byte
}

// Valid ensures the configuration is valid for a file store. Note
// that it won't validate the policy, it will just ensure that one
// is present.
func (f *File) Valid() bool {
	if f.config.Persist == false {
		return false
	}

	if f.config.Policy == "" {
		return false
	}

	if len(f.config.Users) == 0 {
		return false
	}

	if f.config.Mechanism != FileMechanism {
		return false
	}

	if f.config.Location == "" {
		return false
	}

	return true
}

// newFile returns a new file-backed persistence store.
func newFile(config *config.Delegations) (Store, error) {
	cache := keycache.NewCache()
	file := &File{
		config: config,
		cache:  &cache,
		state:  Inactive,
	}

	if !file.Valid() {
		return nil, ErrInvalidConfig
	}

	err := file.Load()
	if err != nil {
		return nil, err
	}
	return file, nil
}

func (f *File) Blob() []byte {
	return f.blob
}

func (f *File) Policy() string {
	return f.config.Policy
}

func (f *File) Users() []string {
	return f.config.Users
}

func (f *File) Store(blob []byte) error {
	if f.state == Active {
		f.blob = blob
		return ioutil.WriteFile(f.config.Location, blob, 0644)
	}
	return nil
}

func (f *File) Load() error {
	if fi, err := os.Stat(f.config.Location); err != nil {
		// If the file doesn't exist, it can be persisted
		// immediately.
		if os.IsNotExist(err) {
			f.state = Active
			return nil
		}

		return err
	} else if fi.Size() == 0 {
		f.state = Active
		return nil
	}

	in, err := ioutil.ReadFile(f.config.Location)
	if err != nil {
		return err
	}

	f.state = Inactive
	f.blob = in
	return nil
}

func (f *File) Persist() {
	f.state = Active
}

func (f *File) Cache() *keycache.Cache {
	return f.cache
}

func (f *File) Delegate(record passvault.PasswordRecord, name, password string, users, labels []string, uses int, slot, durationString string) error {
	return f.cache.AddKeyFromRecord(record, name, password, users, labels, uses, slot, durationString)
}

func (f *File) Status() *Status {
	return &Status{
		State:   f.state,
		Summary: f.cache.GetSummary(),
	}
}

func (f *File) Purge() error {
	f.state = Active
	f.blob = nil
	if err := os.Remove(f.config.Location); err != nil {
		return err
	}
	return nil
}
