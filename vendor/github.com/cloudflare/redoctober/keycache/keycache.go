// Package keycache provides the ability to hold active keys in memory
// for the Red October server.
//
// Copyright (c) 2013 CloudFlare, Inc.
package keycache

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/redoctober/ecdh"
	"github.com/cloudflare/redoctober/passvault"
)

// DelegateIndex is used to index the map of currently delegated keys.
// This is necessary to provide a way for a delegator to provide multiple
// delegations. It is also used to avoid the complexity of string parsing
// and enforcement of username and slot character requirements.
type DelegateIndex struct {
	Name string
	Slot string
}

// Usage holds the permissions of a delegated permission
type Usage struct {
	Uses   int       // Number of uses delegated
	Labels []string  // File labels allowed to decrypt
	Users  []string  // Set of users allows to decrypt
	Expiry time.Time // Expiration of usage
}

// ActiveUser holds the information about an actively delegated key.
type ActiveUser struct {
	Usage
	AltNames map[string]string
	Admin    bool
	Type     string
	Key      []byte

	rsaKey rsa.PrivateKey
	eccKey *ecdsa.PrivateKey
}

// Cache represents the current list of delegated keys in memory
type Cache struct {
	lock     *sync.Mutex
	UserKeys map[DelegateIndex]ActiveUser
}

// matchesLabel returns true if this usage applies the user and label
// an empty array of Users indicates that all users are valid
func (usage Usage) matchesLabel(labels []string) bool {
	// if asset has no labels always match
	if len(labels) == 0 {
		return true
	}

	for _, validLabel := range usage.Labels {
		for _, label := range labels {
			if label == validLabel {
				return true
			}
		}
	}
	return false
}

// matches returns true if this usage applies the user and label
// an empty array of Users indicates that all users are valid
func (usage Usage) matches(user string, labels []string) bool {
	if !usage.matchesLabel(labels) {
		return false
	}
	// if usage lists no users, always match
	if len(usage.Users) == 0 {
		return true
	}
	for _, validUser := range usage.Users {
		if user == validUser {
			return true
		}
	}
	return false
}

// NewCache initalizes a new cache.
func NewCache() Cache {
	return Cache{
		UserKeys: make(map[DelegateIndex]ActiveUser),
		lock:     new(sync.Mutex),
	}
}

// NewFrom takes the output of GetSummary and returns a new keycache.
func NewFrom(summary map[string]ActiveUser) *Cache {
	cache := &Cache{
		UserKeys: make(map[DelegateIndex]ActiveUser),
		lock:     new(sync.Mutex),
	}

	for di, user := range summary {
		diSplit := strings.SplitN(di, "-", 2)
		index := DelegateIndex{
			Name: diSplit[0],
		}

		if len(diSplit) == 2 {
			index.Slot = diSplit[1]
		}
		cache.UserKeys[index] = user
	}

	return cache
}

// setUser takes an ActiveUser and adds it to the cache.
func (cache *Cache) setUser(in ActiveUser, name, slot string) {
	cache.lock.Lock()
	cache.UserKeys[DelegateIndex{Name: name, Slot: slot}] = in
	cache.lock.Unlock()
}

// Valid returns true if matching active user is present.
func (cache *Cache) Valid(name, user string, labels []string) (present bool) {
	for d, key := range cache.UserKeys {
		if d.Name != name {
			continue
		}
		if key.Usage.matches(user, labels) {
			return true
		}
	}

	return false
}

// MatchUser returns the matching active user if present
// and a boolean to indicate its presence.
func (cache *Cache) MatchUser(name, user string, labels []string) (ActiveUser, string, bool) {
	var key ActiveUser
	for d, key := range cache.UserKeys {
		if d.Name != name {
			continue
		}
		if key.Usage.matches(user, labels) {
			return key, d.Slot, true
		}
	}

	return key, "", false
}

// useKey decrements the counter on an active key
// for decryption or symmetric encryption
func (cache *Cache) useKey(name, user, slot string, labels []string) {
	if val, slot, present := cache.MatchUser(name, user, labels); present {
		val.Usage.Uses--
		if val.Usage.Uses <= 0 {
			delete(cache.UserKeys, DelegateIndex{name, slot})
		} else {
			cache.setUser(val, name, slot)
		}
	}
}

// GetSummary returns the list of active user keys.
func (cache *Cache) GetSummary() map[string]ActiveUser {
	summaryData := make(map[string]ActiveUser)
	for d, activeUser := range cache.UserKeys {
		summaryInfo := d.Name
		if d.Slot != "" {
			summaryInfo = fmt.Sprintf("%s-%s", d.Name, d.Slot)
		}
		summaryData[summaryInfo] = activeUser
	}
	return summaryData
}

// Flush removes all delegated keys. It returns true if the cache
// wasn't empty (i.e. there were active users removed), and false if
// the cache was empty.
func (cache *Cache) Flush() bool {
	if len(cache.UserKeys) == 0 {
		return false
	}

	cache.lock.Lock()
	for d := range cache.UserKeys {
		delete(cache.UserKeys, d)
	}
	cache.lock.Unlock()

	return true
}

// Refresh purges all expired keys. It returns the number of
// delegations that were removed.
func (cache *Cache) Refresh() int {
	var removed int

	for d, active := range cache.UserKeys {
		if active.Usage.Expiry.Before(time.Now()) {
			log.Println("Record expired", d.Name, d.Slot, active.Usage.Users, active.Usage.Labels, active.Usage.Expiry)
			removed++
			delete(cache.UserKeys, d)
		}
	}

	return removed
}

// AddKeyFromRecord decrypts a key for a given record and adds it to the cache.
func (cache *Cache) AddKeyFromRecord(record passvault.PasswordRecord, name, password string, users, labels []string, uses int, slot, durationString string) (err error) {
	var current ActiveUser

	cache.Refresh()

	// compute exipiration
	duration, err := time.ParseDuration(durationString)
	if err != nil {
		return
	}
	current.Usage.Uses = uses
	current.Usage.Expiry = time.Now().Add(duration)
	current.Usage.Users = users
	current.Usage.Labels = labels

	// get decryption keys
	switch record.Type {
	case passvault.RSARecord:
		current.rsaKey, err = record.GetKeyRSA(password)
		if err != nil {
			return
		}
		current.Key = x509.MarshalPKCS1PrivateKey(&current.rsaKey)
	case passvault.ECCRecord:
		current.eccKey, err = record.GetKeyECC(password)
		if err != nil {
			return
		}
		current.Key, err = x509.MarshalECPrivateKey(current.eccKey)
	default:
		err = errors.New("Unknown record type")
	}

	if err != nil {
		return
	}

	// set types
	current.Type = record.Type
	current.Admin = record.Admin

	// add current to map (overwriting previous for this name)
	cache.setUser(current, name, slot)

	return
}

// DecryptKey decrypts a 16 byte key using the key corresponding to the name parameter
// For RSA and EC keys, the cached RSA/EC key is used to decrypt
// the pubEncryptedKey which is then used to decrypt the input
// buffer.
func (cache *Cache) DecryptKey(in []byte, name, user string, labels []string, pubEncryptedKey []byte) (out []byte, err error) {
	cache.Refresh()

	decryptKey, slot, ok := cache.MatchUser(name, user, labels)
	if !ok {
		return nil, errors.New("Key not delegated")
	}

	var aesKey []byte

	// pick the aesKey to use for decryption
	switch decryptKey.Type {
	case passvault.RSARecord:
		// extract the aes key from the pubEncryptedKey
		aesKey, err = rsa.DecryptOAEP(sha1.New(), rand.Reader, &decryptKey.rsaKey, pubEncryptedKey, nil)
		if err != nil {
			return out, err
		}
	case passvault.ECCRecord:
		// extract the aes key from the pubEncryptedKey
		aesKey, err = ecdh.Decrypt(decryptKey.eccKey, pubEncryptedKey)

		if err != nil {
			return out, err
		}
	default:
		return nil, errors.New("unknown type")
	}

	// decrypt
	aesSession, err := aes.NewCipher(aesKey)
	if err != nil {
		return out, err
	}
	out = make([]byte, 16)
	aesSession.Decrypt(out, in)

	cache.useKey(name, user, slot, labels)

	return
}

// DecryptShares decrypts an array of 16 byte shares using the key corresponding
// to the name parameter.
func (cache *Cache) DecryptShares(in [][]byte, name, user string, labels []string, pubEncryptedKey []byte) (out [][]byte, err error) {
	cache.Refresh()

	decryptKey, slot, ok := cache.MatchUser(name, user, labels)
	if !ok {
		return nil, errors.New("Key not delegated")
	}

	var aesKey []byte

	// pick the aesKey to use for decryption
	switch decryptKey.Type {
	case passvault.RSARecord:
		// extract the aes key from the pubEncryptedKey
		aesKey, err = rsa.DecryptOAEP(sha1.New(), rand.Reader, &decryptKey.rsaKey, pubEncryptedKey, nil)
		if err != nil {
			return
		}
	case passvault.ECCRecord:
		// extract the aes key from the pubEncryptedKey
		aesKey, err = ecdh.Decrypt(decryptKey.eccKey, pubEncryptedKey)

		if err != nil {
			return
		}
	default:
		return nil, errors.New("unknown type")
	}

	// decrypt
	aesSession, err := aes.NewCipher(aesKey)
	if err != nil {
		return
	}

	for _, encShare := range in {
		tmp := make([]byte, 16)
		aesSession.Decrypt(tmp, encShare)

		out = append(out, tmp)
	}

	cache.useKey(name, user, slot, labels)

	return
}

// DelegateStatus will return a list of admins who have delegated to a particular user, for a particular label.
// This is useful information to have when determining the status of an order and conveying order progress.
func (cache *Cache) DelegateStatus(name string, labels, admins []string) (adminsDelegated []string, hasDelegated int) {
	// Iterate over the admins of the ciphertext to look for users
	// who have already delegated the label to the delegatee.
	for _, admin := range admins {
		for di, use := range cache.UserKeys {
			if di.Name != admin {
				continue
			}
			nameFound := false
			for _, user := range use.Users {
				if user == name {
					nameFound = true
				}
			}
			for _, ol := range use.Labels {
				for _, il := range labels {
					if ol == il {
						if nameFound {
							adminsDelegated = append(adminsDelegated, admin)
							hasDelegated++
						}
					}
				}
			}
		}
	}
	return
}

// Restore unmarshals the private key stored in the delegator to the
// appropriate private structure.
func (cache *Cache) Restore() (err error) {
	for index, uk := range cache.UserKeys {
		if len(uk.Key) == 0 {
			return errors.New("keycache: no private key in active user")
		}

		rsaPriv, err := x509.ParsePKCS1PrivateKey(uk.Key)
		if err == nil {
			uk.rsaKey = *rsaPriv
			cache.UserKeys[index] = uk
			continue
		}

		ecPriv, err := x509.ParseECPrivateKey(uk.Key)
		if err == nil {
			uk.eccKey = ecPriv
			cache.UserKeys[index] = uk
			continue
		}

		return err
	}

	return nil
}
