package test

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.domsnail.ru/domsnail/threat-intel-core/cmd/config"
	"log/slog"
	"os"
	"testing"
)

func TestConfig(t *testing.T) {
	t.Run("empty config creation from env", func(t *testing.T) {
		cfg := config.NewConfigFromEnv()
		slog.Info(cfg.String())
	})

	_ = os.Setenv("DB_HOST", "test_host")
	_ = os.Setenv("DB_PORT", "123")
	_ = os.Setenv("DB_NAME", "test_name")
	_ = os.Setenv("DB_USER", "test_user")
	_ = os.Setenv("DB_SSL", "false")
	_ = os.Setenv("DB_TZ", "Europe/Moscow")

	t.Run("database config creation from env", func(t *testing.T) {
		db := config.NewDatabaseConfigFromEnv()

		require.EqualValues(t, "test_host", db.Host)
		require.EqualValues(t, 123, db.Port)
		require.EqualValues(t, "test_user", db.User)
		require.EqualValues(t, "test_name", db.Name)
		require.EqualValues(t, "Europe/Moscow", db.Timezone)
		require.False(t, db.UseSSL)
	})

	_ = os.Setenv("DB_PORT", "123as")
	_ = os.Setenv("DB_SSL", "fa1lse")

	t.Run("database config creation with panic", func(t *testing.T) {
		assert.Panics(t, func() {
			config.NewDatabaseConfigFromEnv()
		})

		assert.Panics(t, func() {
			config.NewDatabaseConfigFromEnv()
		})
	})

	_ = os.Setenv("TLS_ENABLED", "true")
	_ = os.Setenv("TLS_CRT", "test_crt")
	_ = os.Setenv("TLS_KEY", "test_key")

	t.Run("tls config creation from env", func(t *testing.T) {
		tls := config.NewTLSConfigFromEnv()

		require.True(t, tls.IsEnabled)
		require.EqualValues(t, "test_crt", tls.Cert)
		require.EqualValues(t, "test_key", tls.Key)
	})

	os.Clearenv()
	_ = os.Setenv("TLS_ENABLED", "true")

	t.Run("tls config creation with panic", func(t *testing.T) {
		assert.Panics(t, func() {
			config.NewTLSConfigFromEnv()
		})
	})
}
