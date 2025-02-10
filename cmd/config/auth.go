package config

import "os"

type Auth struct {
	Token  string
	Secret []byte
}

func NewAuthConfigFromEnv() (config Auth) {
	config.Token = os.Getenv("AUTH_TOKEN")
	config.Secret = []byte(os.Getenv("AUTH_TOKEN_SECRET"))

	return
}
