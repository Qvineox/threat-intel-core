package config

import "os"

type Auth struct {
	Token string
}

func NewAuthConfigFromEnv() (config Auth) {
	config.Token = os.Getenv("AUTH_TOKEN")

	return
}
