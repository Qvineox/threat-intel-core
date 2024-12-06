package config

import (
	"fmt"
	"os"
	"strconv"
)

type REST struct {
	Host string
	Port uint64
}

func NewRESTConfigFromEnv() (config REST) {
	config.Host = defaultHost

	port, ok := os.LookupEnv("REST_PORT")
	if ok && port != "" {
		var err error

		config.Port, err = strconv.ParseUint(port, 10, 64)
		if err != nil {
			panic("REST_PORT env variable is invalid: " + err.Error())
		}
	}

	host, ok := os.LookupEnv("REST_HOST")
	if ok && host != "" {
		config.Host = host
	}

	return
}

func (config REST) String() string {
	return fmt.Sprintf(
		"\n---\nREST server configuration:\n\tHost: %s\n\tPort: %d",
		config.Host,
		config.Port)
}
