package config

import (
	"os"
	"strings"
)

type Auth struct {
	Token    string
	Domain   string
	Audience []string
	Secret   []byte
}

func NewAuthConfigFromEnv() (config Auth) {
	config.Token = os.Getenv("AUTH_TOKEN")
	config.Domain = os.Getenv("AUTH_TOKEN_DOMAIN")
	config.Audience = strings.Split(os.Getenv("AUTH_TOKEN_AUDIENCE"), ",")

	config.Secret = []byte(os.Getenv("AUTH_TOKEN_SECRET"))

	return
}
