package config

import (
	"fmt"
	"os"
)

type Services struct {
	CoordinatorURL      string
	ControlCenterURL    string
	CollectorURL        string
	TelegramAdminBotURL string
}

func NewServicesConfigFromEnv() (config Services) {
	config.ControlCenterURL = os.Getenv("CONTROL_CENTER_URL")
	config.CoordinatorURL = os.Getenv("COORDINATOR_URL")
	config.CollectorURL = os.Getenv("COLLECTOR_URL")
	config.TelegramAdminBotURL = os.Getenv("TG_ADMIN_BOT_URL")

	return
}

func (config Services) String() string {
	return fmt.Sprintf(
		"\n---\nService grid configuration:\n\tControl center URL: %s\n\tCoordinator URL: %s\n\tCollector URL: %s\n\tTelegram admin bot URL: %s",
		config.ControlCenterURL,
		config.CoordinatorURL,
		config.CollectorURL,
		config.TelegramAdminBotURL,
	)
}
