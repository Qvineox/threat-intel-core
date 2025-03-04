package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"google.golang.org/grpc/credentials"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type TLS struct {
	IsEnabled bool

	CertFilePath, KeyFilePath string
	Cert, Key                 []byte
}

func NewTLSConfigFromEnv(tryFiles bool) (config TLS) {
	useTLS, ok := os.LookupEnv("TLS_ENABLED")
	if ok {
		config.IsEnabled = useTLS == "true"
	}

	if config.IsEnabled {
		if tryFiles {
			// try to load from filesystem
			err := config.LoadFromFiles()
			if err != nil {
				slog.Warn("failed to load tls config from filesystem: " + err.Error())
				slog.Info("trying to load tls config from environment variables...")
			} else {
				return config
			}
		}

		crt, _ := os.LookupEnv("TLS_CRT")
		if len(crt) > 0 {
			config.Cert = []byte(crt)
		}

		key, _ := os.LookupEnv("TLS_KEY")
		if len(key) > 0 {
			config.Key = []byte(key)
		}

		if len(config.Cert) == 0 || len(config.Key) == 0 {
			panic("missing TLS_CRT or TLS_KEY in process environment")
		}
	}

	return
}

func (config *TLS) String() string {
	return fmt.Sprintf(
		"\n---\nTransport security configuration:\n\tTLS enabled: %t",
		config.IsEnabled,
	)
}

func (config *TLS) GetCredentials() (credentials.TransportCredentials, error) {
	pair, err := tls.X509KeyPair(config.Cert, config.Key)
	if err != nil {
		return nil, errors.New("failed to load transport credentials")
	}

	return credentials.NewServerTLSFromCert(&pair), nil
}

func (config *TLS) LoadFromFiles() error {
	// check is cert files are located in current directory
	path, err := os.Getwd()
	if err != nil {
		return errors.New("unable to determine current working directory")
	}

	slog.Info("searching for tls certificate and key in current directory: " + path)
	entries, err := fs.ReadDir(os.DirFS(path), "tls")
	if err != nil {
		return errors.New("unable to read directory: " + err.Error())
	}

	crtIndex := slices.IndexFunc(entries, func(item fs.DirEntry) bool {
		return !item.IsDir() && strings.HasSuffix(item.Name(), ".crt")
	})

	if crtIndex != -1 {
		slog.Info("found tls certificate file: " + entries[crtIndex].Name())
	}

	keyIndex := slices.IndexFunc(entries, func(item fs.DirEntry) bool {
		return !item.IsDir() && strings.HasSuffix(item.Name(), ".key")
	})

	if keyIndex != -1 {
		slog.Info("found tls certificate file: " + entries[keyIndex].Name())
	}

	if crtIndex == -1 || keyIndex == -1 {
		return errors.New("unable to find tls certificate or key")
	}

	config.CertFilePath = filepath.Join(path, "tls", entries[crtIndex].Name())
	config.KeyFilePath = filepath.Join(path, "tls", entries[keyIndex].Name())

	config.Cert, err = os.ReadFile(config.CertFilePath)
	if err != nil {
		panic("unable to read tls certificate: " + err.Error())
	} else {
		slog.Info("tls certificate loaded")
	}

	config.Key, err = os.ReadFile(config.KeyFilePath)
	if err != nil {
		panic("unable to read tls key: " + err.Error())
	} else {
		slog.Info("tls key loaded")
	}

	return nil
}
