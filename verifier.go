package googleJWTVerifier

import (
	"time"
)

var (
	// Issuers is the allowed oauth token issuers
	issuers = []string{
		"accounts.google.com",
		"https://accounts.google.com",
	}
)

const (
	// MaxTokenLifetime is one day
	maxTokenLifetime = time.Second * 86400
)

func VerifyIDToken(token string, audiences []string) error {
	jwks, err := getFederatedSignonCerts()
	if err != nil {
		return err
	}
	return verifySignedJWTWithCerts(token, jwks, audiences, issuers, maxTokenLifetime)
}
