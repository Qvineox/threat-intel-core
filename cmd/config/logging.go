package config

import (
	"fmt"
	"os"
)

type Logging struct {
	URL   string
	Token string
}

func (config Logging) String() string {
	return fmt.Sprintf(
		"\n---\nLogging configuration:\n\tLogging server URL: %s\n",
		config.URL)
}

func NewLoggingConfigFromEnv() (config Logging) {
	config.URL, _ = os.LookupEnv("LOGS_URL")
	config.Token, _ = os.LookupEnv("LOGS_TOKEN")

	return

}
