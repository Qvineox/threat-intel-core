package auth

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"time"
)

type Issuer struct {
	secret []byte
	method jwt.SigningMethod

	domain   string
	audience []string
}

func NewIssuer(secret []byte, method jwt.SigningMethod, domain string, audience []string) *Issuer {
	return &Issuer{
		secret:   secret,
		method:   method,
		domain:   domain,
		audience: audience,
	}
}

func (i *Issuer) IssueToken(subject string, expiresAt time.Time, permissions Permissions) (string, error) {
	jti, err := uuid.NewV7()
	if err != nil {
		return "", err
	}

	t := Token{
		TokenUUID:   jti,
		Issuer:      i.domain,
		Subject:     subject,
		Audience:    i.audience,
		NotBefore:   time.Now(),
		IssuedAt:    time.Now(),
		ExpiresAt:   expiresAt,
		Permissions: permissions,
	}

	token := jwt.NewWithClaims(i.method, &t)
	return token.SignedString(i.secret)
}
