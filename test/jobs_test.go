package test

import (
	"encoding/json"
	"errors"
	"github.com/stretchr/testify/require"
	"gitlab.qvineox.ru/domsnail/threat-intel-core/api/services"
	"gitlab.qvineox.ru/domsnail/threat-intel-core/cmd/entities"
	"testing"
)

func TestJobs(t *testing.T) {
	t.Run("jobs creation", func(t *testing.T) {
		opt := &services.PingOptions{Default: &services.Options{Targets: nil}}

		job, err := entities.NewPingJobFromProto(opt, nil)
		require.Error(t, err)
		require.Nil(t, job)

		opt = &services.PingOptions{Default: &services.Options{Targets: make([]string, 0)}}
		job, err = entities.NewPingJobFromProto(opt, nil)
		require.NoError(t, err)
		require.NotNil(t, job)

		require.EqualValues(t, entities.JOB_STATE_QUEUED, job.State)
		require.EqualValues(t, entities.JOB_TYPE_PING, job.Type)
		require.NotZero(t, job.CreatedAt)
		require.Nil(t, job.CreatedBy)

		var userID uint64 = 1

		opt = &services.PingOptions{Default: &services.Options{Targets: []string{"ya.ru", "192.168.31.0/24"}}}
		job, err = entities.NewPingJobFromProto(opt, &userID)
		require.NoError(t, err)
		require.NotNil(t, job)

		var targets []string

		err = json.Unmarshal(job.Options.Bytes, &targets)
		require.NotNil(t, job)

		require.EqualValues(t, opt.Default.Targets, targets)
		require.EqualValues(t, *job.CreatedBy, userID)
	})

	t.Run("job states change", func(t *testing.T) {
		opt := &services.PingOptions{Default: &services.Options{Targets: []string{"ya.ru", "192.168.31.0/24"}}}
		var userID uint64 = 1

		job, err := entities.NewPingJobFromProto(opt, &userID)
		require.NoError(t, err)
		require.NotNil(t, job)

		completed := job.NextState()
		require.EqualValues(t, entities.JOB_STATE_STARTED, job.State)
		require.False(t, completed)

		completed = job.NextState()
		require.EqualValues(t, entities.JOB_STATE_COMPLETED, job.State)
		require.True(t, completed)

		completed = job.NextState()
		require.EqualValues(t, entities.JOB_STATE_COMPLETED, job.State)
		require.Empty(t, job.ErrorText)
		require.True(t, completed)
	})

	t.Run("job state error", func(t *testing.T) {
		opt := &services.PingOptions{Default: &services.Options{Targets: []string{"ya.ru", "192.168.31.0/24"}}}
		var userID uint64 = 1

		job, err := entities.NewPingJobFromProto(opt, &userID)
		require.NoError(t, err)
		require.NotNil(t, job)

		completed := job.NextState()
		require.EqualValues(t, entities.JOB_STATE_STARTED, job.State)
		require.False(t, completed)

		job.Error(errors.New("test error"))
		require.EqualValues(t, "test error", *job.ErrorText)
		require.EqualValues(t, entities.JOB_STATE_ERROR, job.State)
	})
}
