// Currently this SDK only integrates with `github.com/richlj/passlib`

package neato

import (
	"github.com/richlj/passlib"
)

var (
	credentialsPassRE = ".*neatorobotics.*/.*"
)

type credentials struct {
	Username string
	Password string
}

func getCredentials() (*credentials, error) {
	return getCredentialsPass()
}

func getCredentialsPass() (*credentials, error) {
	a, err := pass.Get(credentialsPassRE)
	if err != nil {
		return nil, err
	}
	return &credentials{
		Username: a.Credentials.Username,
		Password: a.Credentials.Password,
	}, nil
}
