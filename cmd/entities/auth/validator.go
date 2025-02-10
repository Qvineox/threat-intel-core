package auth

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
)

type Validator struct {
	*jwt.Parser

	secret []byte
	domain string
	method jwt.SigningMethod
}

func NewValidator(secret []byte, domain string, method jwt.SigningMethod) *Validator {
	return &Validator{
		Parser: jwt.NewParser(
			jwt.WithIssuer(domain),
			jwt.WithIssuedAt(),
			jwt.WithExpirationRequired(),
		),
		secret: secret,
		method: method,
	}
}

func (v *Validator) Validate(tokenStr string) (*Token, error) {
	var claims Token

	token, err := v.ParseWithClaims(tokenStr, &claims, func(token *jwt.Token) (interface{}, error) {
		return v.secret, nil
	})

	if err != nil {
		return nil, err
	} else if token.Valid {
		return &claims, nil
	}

	switch {
	case errors.Is(err, jwt.ErrTokenMalformed):
		return nil, errors.New("token is malformed")
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return nil, errors.New("token signature is invalid")
	default:
		return nil, errors.New("token is invalid")
	}
}
