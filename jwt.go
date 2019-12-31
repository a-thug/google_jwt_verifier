package googleJWTVerifier

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"time"
)

// Header represents the header for the signed JWS payloads.
type Header struct {
	// The algorithm used for signature.
	Algorithm string `json:"alg"`

	// Represents the token type.
	Typ string `json:"typ"`

	// The optional hint of which key is being used.
	KeyID string `json:"kid,omitempty"`
}

// Import from https://github.com/golang/oauth2/blob/master/jws/jws.go
// ClaimSet contains information about the JWT signature including the
// permissions being requested (scopes), the target of the token, the issuer,
// the time the token was issued, and the lifetime of the token.
type ClaimSet struct {
	Iss   string `json:"iss"`             // email address of the client_id of the application making the access token request
	Scope string `json:"scope,omitempty"` // space-delimited list of the permissions the application requests
	Aud   string `json:"aud"`             // descriptor of the intended target of the assertion (Optional).
	Exp   int64  `json:"exp"`             // the expiration time of the assertion (seconds since Unix epoch)
	Iat   int64  `json:"iat"`             // the time the assertion was issued (seconds since Unix epoch)
	Typ   string `json:"typ,omitempty"`   // token type (Optional).

	// Email for which the application is requesting delegated access (Optional).
	Sub string `json:"sub,omitempty"`

	// The old name of Sub. Client keeps setting Prn to be
	// complaint with legacy OAuth 2.0 providers. (Optional)
	Prn string `json:"prn,omitempty"`

	// See http://tools.ietf.org/html/draft-jones-json-web-token-10#section-4.3
	// This array is marshalled using custom code (see (c *ClaimSet) encode()).
	PrivateClaims map[string]interface{} `json:"-"`
}

const (
	// ClockSkew - five minutes
	ClockSkew = time.Minute * 5
)

func parseJWT(token string) (*Header, *ClaimSet, error) {
	s := strings.Split(token, ".")
	if len(s) != 3 {
		return nil, nil, errors.New("Invalid token received")
	}
	decodedHeader, err := base64.RawURLEncoding.DecodeString(s[0])
	if err != nil {
		return nil, nil, err
	}
	header := &Header{}
	err = json.NewDecoder(bytes.NewBuffer(decodedHeader)).Decode(header)
	if err != nil {
		return nil, nil, err
	}
	decodedClaimSet, err := base64.RawURLEncoding.DecodeString(s[1])
	if err != nil {
		return nil, nil, err
	}
	claimSet := &ClaimSet{}
	err = json.NewDecoder(bytes.NewBuffer(decodedClaimSet)).Decode(claimSet)

	if err != nil {
		return nil, nil, err
	}
	return header, claimSet, nil
}

// verifySignedJWTWithCerts is golang port of OAuth2Client.prototype.verifySignedJwtWithCerts
func verifySignedJWTWithCerts(token string, jwks *JWKs, allowedAuds []string, issuers []string, maxExpiry time.Duration) error {
	header, claimSet, err := parseJWT(token)
	if err != nil {
		return err
	}
	key := jwks.Keys[header.KeyID]
	if key == nil {
		return ErrPublicKeyNotFound
	}
	err = verifyToken(token, key)
	if err != nil {
		return ErrWrongSignature
	}
	if claimSet.Iat < 1 {
		return ErrNoIssueTimeInToken
	}
	if claimSet.Exp < 1 {
		return ErrNoExpirationTimeInToken
	}
	now := time.Now()
	if claimSet.Exp > now.Unix()+int64(maxExpiry.Seconds()) {
		return ErrExpirationTimeTooFarInFuture
	}

	earliest := claimSet.Iat - int64(ClockSkew.Seconds())
	latest := claimSet.Exp + int64(ClockSkew.Seconds())

	if now.Unix() < earliest {
		return ErrTokenUsedTooEarly
	}

	if now.Unix() > latest {
		return ErrTokenUsedTooLate
	}

	found := false
	for _, issuer := range issuers {
		if issuer == claimSet.Iss {
			found = true
			break
		}
	}
	if !found {
		log.Printf("Invalid issuer: %s", claimSet.Aud)
		return ErrInvalidIssuer
	}

	audFound := false
	for _, aud := range allowedAuds {
		if aud == claimSet.Aud {
			audFound = true
			break
		}
	}
	if !audFound {
		log.Printf("Invalid aud: %s", claimSet.Aud)
		return ErrInvalidAudience
	}

	return nil
}

// Import from https://github.com/golang/oauth2/blob/master/jws/jws.go
func verifyToken(token string, key *rsa.PublicKey) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ErrInvalidToken
	}

	signedContent := parts[0] + "." + parts[1]
	signatureString, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}

	h := sha256.New()
	h.Write([]byte(signedContent))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, h.Sum(nil), []byte(signatureString))
}
