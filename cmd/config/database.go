package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Database struct {
	Host string
	Port uint64

	Name string
	User string
	Pass string

	Timezone string

	UseSSL bool
}

func NewDatabaseConfigFromEnv() (config Database) {
	var err error

	config.Host, _ = os.LookupEnv("DB_HOST")
	config.User, _ = os.LookupEnv("DB_USER")
	config.Pass, _ = os.LookupEnv("DB_PASS")

	config.Name, _ = os.LookupEnv("DB_NAME")
	config.Timezone, _ = os.LookupEnv("DB_TZ")

	port, ok := os.LookupEnv("DB_PORT")
	if ok && port != "" {

		config.Port, err = strconv.ParseUint(port, 10, 64)
		if err != nil {
			panic("DB_PORT env variable is invalid: " + err.Error())
		}
	}

	ssl, ok := os.LookupEnv("DB_SSL")
	if ok {
		switch strings.ToLower(ssl) {
		case "true":
			config.UseSSL = true
		case "false":
			config.UseSSL = false
		default:
			panic("DB_SSL env variable is invalid (required true/false)")
		}
	}

	return
}

func (config Database) String() string {
	return fmt.Sprintf(
		"\n---\nDatabase configuration:\n\tRemote address: %s\n\tRemote port: %d\n\tUser: %s",
		config.Host,
		config.Port,
		config.User,
	)
}
