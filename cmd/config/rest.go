package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type REST struct {
	Host string
	Port uint64

	CORS CORS
}

type CORS struct {
	AllowedOrigins []string
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

	config.CORS = CORS{}
	origins, ok := os.LookupEnv("REST_CORS_ORIGINS")
	if ok && origins != "" {
		config.CORS.AllowedOrigins = strings.Split(origins, ",")
	}

	return
}

func (config REST) String() string {
	return fmt.Sprintf(
		"\n---\nREST server configuration:\n\tHost: %s\n\tPort: %d\n\tAllowed origins: [%s]",
		config.Host,
		config.Port,
		strings.Join(config.CORS.AllowedOrigins, ", "),
	)
}
