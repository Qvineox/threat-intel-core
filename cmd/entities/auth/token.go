package auth

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"time"
)

type Token struct {
	// A unique identifier for the JWT, often used to prevent replay attacks.
	TokenUUID uuid.UUID `json:"jti"`

	// The Issuer of the JWT. Identifies the principal that issued the JWT (e.g., the authentication server)
	Issuer string `json:"iss"`

	// The Subject of the JWT (the user). Identifies the principal that is the subject of the JWT (e.g., the user ID).
	Subject string `json:"sub"`

	// Identifies the recipients that the JWT is intended for (e.g., the client application).
	Audience []string `json:"aud"`

	// Timestamps
	NotBefore time.Time `json:"nbf"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`

	// Custom permissions model
	Permissions Permissions `json:"perm"`
}

func (t *Token) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(t.ExpiresAt), nil
}

func (t *Token) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(t.IssuedAt), nil
}

func (t *Token) GetNotBefore() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(t.NotBefore), nil
}

func (t *Token) GetIssuer() (string, error) {
	return t.Issuer, nil
}

func (t *Token) GetSubject() (string, error) {
	return t.Subject, nil
}

func (t *Token) GetAudience() (jwt.ClaimStrings, error) {
	return t.Audience, nil
}

type DomsnailAudience string
