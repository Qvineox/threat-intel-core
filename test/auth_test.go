package test

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"gitlab.domsnail.ru/domsnail/threat-intel-core/cmd/entities/auth"
	"strconv"
	"testing"
	"time"
)

const tokenSecret = "test_token_123456"
const tokenDomain = "test.domsnail.ru"

func TestTokens(t *testing.T) {
	issuer := auth.NewIssuer(
		[]byte(tokenSecret),
		jwt.SigningMethodHS256,
		tokenDomain,
		[]string{"test cases"},
	)

	var tokenStr string
	const clusterID = 1

	expiresAt := time.Now().Add(time.Hour)

	t.Run("issue token", func(t *testing.T) {
		var err error

		tokenStr, err = issuer.IssueToken(
			strconv.Itoa(clusterID),
			expiresAt,
			auth.Permissions{
				User: auth.UserPermissions{},
				Bot: auth.BotPermissions{
					Connection: true,
				},
			},
		)

		require.NotEmpty(t, tokenStr)
		require.NoError(t, err)
	})

	validator := auth.NewValidator([]byte(tokenSecret), tokenDomain, jwt.SigningMethodHS256)

	t.Run("token validation", func(t *testing.T) {
		token, err := validator.Validate(tokenStr)
		require.NoError(t, err)

		require.NotNil(t, token.TokenUUID)

		require.EqualValues(t, "test.domsnail.ru", token.Issuer)
		require.EqualValues(t, []string{"test cases"}, token.Audience)
		require.EqualValues(t, "1", token.Subject)
		require.EqualValues(t, expiresAt.Unix(), token.ExpiresAt.Unix())
		require.EqualValues(t, expiresAt.Unix(), token.ExpiresAt.Unix())

		require.True(t, token.Permissions.Bot.Connection)
	})

	t.Run("expired token creation", func(t *testing.T) {
		tokenStr_, err := issuer.IssueToken(
			strconv.Itoa(clusterID),
			time.Now().Add(-time.Hour),
			auth.Permissions{
				User: auth.UserPermissions{},
				Bot: auth.BotPermissions{
					Connection: true,
				},
			},
		)

		_, err = validator.Validate(tokenStr_)
		require.Error(t, err)
	})

	t.Run("other secret token validation", func(t *testing.T) {
		issuer_ := auth.NewIssuer(
			[]byte("test"),
			jwt.SigningMethodHS256,
			"test.other.ru",
			[]string{"error test cases"},
		)

		tokenStr_, err := issuer_.IssueToken(
			strconv.Itoa(clusterID),
			time.Now().Add(time.Hour),
			auth.Permissions{},
		)

		_, err = validator.Validate(tokenStr_)
		require.Error(t, err)
	})

	t.Run("other domain issuer token validation", func(t *testing.T) {
		issuer_ := auth.NewIssuer(
			[]byte(tokenSecret),
			jwt.SigningMethodHS256,
			"test.other.ru",
			[]string{"error test cases"},
		)

		tokenStr_, err := issuer_.IssueToken(
			strconv.Itoa(clusterID),
			time.Now().Add(time.Hour),
			auth.Permissions{},
		)

		_, err = validator.Validate(tokenStr_)
		require.Error(t, err)
	})
}
