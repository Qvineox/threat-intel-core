package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"google.golang.org/grpc/credentials"
	"os"
)

type TLS struct {
	IsEnabled bool

	Cert string
	Key  string
}

func NewTLSConfigFromEnv() (config TLS) {
	useTLS, ok := os.LookupEnv("TLS_ENABLED")
	if ok {
		config.IsEnabled = useTLS == "true"
	}

	if config.IsEnabled {
		config.Cert, _ = os.LookupEnv("TLS_CRT")
		config.Key, _ = os.LookupEnv("TLS_KEY")

		if len(config.Cert) == 0 || len(config.Key) == 0 {
			panic("missing TLS_CRT or TLS_KEY in process environment")
		}
	}

	return
}

func (config TLS) String() string {
	return fmt.Sprintf(
		"\n---\nTransport security configuration:\n\tTLS enabled: %t",
		config.IsEnabled,
	)
}

func (config TLS) GetCredentials() (credentials.TransportCredentials, error) {
	pair, err := tls.X509KeyPair([]byte(config.Cert), []byte(config.Key))
	if err != nil {
		return nil, errors.New("failed to load transport credentials")
	}

	return credentials.NewServerTLSFromCert(&pair), nil
}
