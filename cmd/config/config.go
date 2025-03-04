package config

const defaultHost = "0.0.0.0"

type Config struct {
	DatabaseConnection Database
	REST               REST
	RemoteProcedures   RPC
	Security           TLS
	ServiceDiscovery   Services
	Logging            Logging
	Auth               Auth
}

type LoadOptions struct {
	TryCertFiles bool
}

func (config Config) String() string {
	return config.DatabaseConnection.String() + config.REST.String() + config.RemoteProcedures.String() + config.Security.String() + config.ServiceDiscovery.String() + config.Logging.String() + "\n---"

}

func NewConfigFromEnv(opt LoadOptions) (config Config) {
	return Config{
		DatabaseConnection: NewDatabaseConfigFromEnv(),
		REST:               NewRESTConfigFromEnv(),
		RemoteProcedures:   NewRPCConfigFromEnv(),
		Security:           NewTLSConfigFromEnv(opt.TryCertFiles),
		ServiceDiscovery:   NewServicesConfigFromEnv(),
		Logging:            NewLoggingConfigFromEnv(),
		Auth:               NewAuthConfigFromEnv(),
	}
}
