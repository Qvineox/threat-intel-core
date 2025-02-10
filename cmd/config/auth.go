package config

import "os"

type Auth struct {
	Token  string
	Domain string
	Secret []byte
}

func NewAuthConfigFromEnv() (config Auth) {
	config.Token = os.Getenv("AUTH_TOKEN")
	config.Domain = os.Getenv("AUTH_TOKEN_DOMAIN")

	config.Secret = []byte(os.Getenv("AUTH_TOKEN_SECRET"))

	return
}
