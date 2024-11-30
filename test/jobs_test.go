package test

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"gitlab.qvineox.ru/domsnail/threat-intel-core/api/services"
	"gitlab.qvineox.ru/domsnail/threat-intel-core/cmd/entities"
	"testing"
)

func TestJobs(t *testing.T) {
	t.Run("ping job creation", func(t *testing.T) {
		opt := &services.PingOptions{Default: &services.Options{Targets: nil}}

		job, err := entities.NewPingJobFromProto(opt, nil)
		require.Error(t, err)
		require.Nil(t, job)

		opt = &services.PingOptions{Default: &services.Options{Targets: make([]string, 0)}}
		job, err = entities.NewPingJobFromProto(opt, nil)
		require.NoError(t, err)
		require.NotNil(t, job)

		require.False(t, job.IsSent)
		require.EqualValues(t, entities.JOB_TYPE_PING, job.Type)
		require.NotZero(t, job.CreatedAt)
		require.Nil(t, job.CreatedBy)

		var userID uint64 = 1

		opt = &services.PingOptions{Default: &services.Options{Targets: []string{"ya.ru", "192.168.31.0/24"}}}
		job, err = entities.NewPingJobFromProto(opt, &userID)
		require.NoError(t, err)
		require.NotNil(t, job)

		var options_ services.PingOptions

		err = json.Unmarshal(job.Options, &options_)
		require.NotNil(t, job)

		require.EqualValues(t, opt.Default.Targets, options_.Default.Targets)
		require.EqualValues(t, *job.CreatedBy, userID)
	})

	t.Run("job state error", func(t *testing.T) {
		opt := &services.PingOptions{Default: &services.Options{Targets: []string{"ya.ru", "192.168.31.0/24"}}}
		var userID uint64 = 1

		job, err := entities.NewPingJobFromProto(opt, &userID)
		require.NoError(t, err)
		require.NotNil(t, job)
	})
}
