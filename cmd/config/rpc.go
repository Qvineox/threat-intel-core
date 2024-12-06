package config

import (
	"fmt"
	"os"
	"strconv"
)

type RPC struct {
	Host string
	Port uint64
}

func NewRPCConfigFromEnv() (config RPC) {
	config.Host = defaultHost

	port, ok := os.LookupEnv("RPC_PORT")
	if ok && port != "" {
		var err error

		config.Port, err = strconv.ParseUint(port, 10, 64)
		if err != nil {
			panic("RPC_PORT env variable is invalid: " + err.Error())
		}
	}

	host, ok := os.LookupEnv("RPC_HOST")
	if ok && host != "" {
		config.Host = host
	}

	return
}

func (config RPC) String() string {
	return fmt.Sprintf(
		"\n---\nRPC server configuration:\n\tHost: %s\n\tPort: %d",
		config.Host,
		config.Port)
}
