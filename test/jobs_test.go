package test

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"gitlab.domsnail.ru/domsnail/threat-intel-core/api/services"
	"gitlab.domsnail.ru/domsnail/threat-intel-core/cmd/entities"
	"testing"
)

func TestJobs(t *testing.T) {
	t.Run("ping job creation", func(t *testing.T) {
		opt := &services.PingOptions{Default: &services.Options{Targets: nil}}

		job, err := entities.NewPingJobFromProto(opt, nil, 0, 1)
		require.Error(t, err)
		require.Nil(t, job)

		opt = &services.PingOptions{Default: &services.Options{Targets: make([]string, 0)}}
		job, err = entities.NewPingJobFromProto(opt, nil, 0, 1)
		require.NoError(t, err)
		require.NotNil(t, job)

		require.Nil(t, job.IsAllocated)
		require.Nil(t, job.IsStarted)
		require.EqualValues(t, entities.JOB_TYPE_PING, job.Type)
		require.NotZero(t, job.CreatedAt)
		require.Nil(t, job.CreatedBy)

		var userID uint64 = 1

		opt = &services.PingOptions{Default: &services.Options{Targets: []string{"ya.ru", "192.168.31.0/24"}}}
		job, err = entities.NewPingJobFromProto(opt, &userID, 0, 1)
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

		job, err := entities.NewPingJobFromProto(opt, &userID, 0, 1)
		require.NoError(t, err)
		require.NotNil(t, job)
	})

	t.Run("job priority sort", func(t *testing.T) {
		var jobs = []entities.Job{
			{
				Priority: entities.P_CRITICAL,
			},
			{
				Priority: entities.P_MEDIUM,
			},
			{
				Priority: entities.P_LOW,
			},
			{
				Priority: entities.P_MEDIUM,
			},
			{
				Priority: entities.P_HIGH,
			},
			{
				Priority: entities.P_LOW,
			},
		}

		entities.SortJobsByPriority(jobs)

		require.EqualValues(t, jobs[0].Priority, entities.P_CRITICAL)
		require.EqualValues(t, jobs[1].Priority, entities.P_HIGH)
		require.EqualValues(t, jobs[2].Priority, entities.P_MEDIUM)
		require.EqualValues(t, jobs[3].Priority, entities.P_MEDIUM)
		require.EqualValues(t, jobs[4].Priority, entities.P_LOW)
		require.EqualValues(t, jobs[5].Priority, entities.P_LOW)
	})
}
