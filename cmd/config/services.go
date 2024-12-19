package config

import (
	"fmt"
	"os"
)

type Services struct {
	CoordinatorURL   string
	ControlCenterURL string
	CollectorURL     string
}

func NewServicesConfigFromEnv() (config Services) {
	config.ControlCenterURL = os.Getenv("CONTROL_CENTER_URL")
	config.CoordinatorURL = os.Getenv("COORDINATOR_URL")
	config.CollectorURL = os.Getenv("COLLECTOR_URL")

	return
}

func (config Services) String() string {
	return fmt.Sprintf(
		"\n---\nService grid configuration:\n\tControl center URL: %s\n\tCoordinator URL: %s\n\tCollector URL: %s\n",
		config.ControlCenterURL,
		config.CoordinatorURL,
		config.CollectorURL,
	)
}
