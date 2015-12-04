// Package jwtauth implements an interface for providing CFSSL
// authentication.
package jwtauth

import (
	//"flag"
	"fmt"
	//"io"
	//"io/ioutil"
	//"os"
	"time"

	//"github.com/cloudflare/cfssl/helpers"
	"github.com/dgrijalva/jwt-go"
)

type Provider interface {
	Token(req []byte) (token []byte, err error)
	Verify(aReq *AuthenticatedRequest) bool
}

type AuthenticatedRequest struct {
	// An Authenticator decides whether to use this field.
	Timestamp     int64  `json:"timestamp,omitempty"`
	RemoteAddress []byte `json:"remote_address,omitempty"`
	Token         []byte `json:"token"`
	Request       []byte `json:"request"`
}

func New(mySigningKey []byte) (string, error) {

	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	tokenString, err := token.SignedString(mySigningKey)
	return tokenString, err
}

func Verify(pubkey []byte, myToken string) (bool, error) {
	token, err := jwt.Parse(string(myToken), func(t *jwt.Token) (interface{}, error) {
		return pubkey, nil
	})

	if err != nil {
		return false, err
	}
	if token.Valid {
		fmt.Println("claims == ", token.Claims)
		return true, err
	}
	return false, err
}
