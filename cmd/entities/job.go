package entities

import (
	"fmt"
	"github.com/jackc/pgtype"
	"gitlab.qvineox.ru/domsnail/threat-intel-core/api/services"
	"time"
)

type JobType string

const (
	JOB_TYPE_PING JobType = "P"
)

type JobState string

const (
	JOB_STATE_QUEUED    JobState = "queued"
	JOB_STATE_STARTED   JobState = "started"
	JOB_STATE_COMPLETED JobState = "completed"
	JOB_STATE_ERROR     JobState = "error"
)

// Job represents minimal system task provided by user
type Job struct {
	ID    *uint64  `json:"ID" gorm:"primary_key"`
	Type  JobType  `json:"Type" gorm:"column:type;index;not null;type:varchar(1);comment:Job type"`
	State JobState `json:"State" gorm:"column:state;not null;type:varchar(10);comment:Current job state"`

	Options   *pgtype.JSONB `json:"Options" gorm:"column:options;type:jsonb;comment:Full job parameters and targets as requested in job"`
	ErrorText *string       `json:"ErrorText" gorm:"column:error_text;type:text;comment:Job error message"`

	// CreatedBy is the identity of a user
	CreatedBy *uint64 `json:"CreatedBy" gorm:"column:created_by;index;comment:Job author's user ID"`

	CreatedAt time.Time `json:"CreatedAt"`
	UpdatedAt time.Time `json:"UpdatedAt"`
}

func (j *Job) String() string {
	return fmt.Sprintf("JOB-%d (%s)", *j.ID, j.Type)
}

func NewPingJob(desc *services.PingOptions, createdBy *uint64) (*Job, error) {
	if desc == nil || desc.Default == nil || desc.Default.Targets == nil {
		return nil, fmt.Errorf("targets not found")
	}

	var options = &pgtype.JSONB{}
	err := options.Set(desc.Default.Targets)
	if err != nil {
		return nil, err
	}

	return &Job{
		Type:      JOB_TYPE_PING,
		State:     JOB_STATE_QUEUED,
		Options:   options,
		CreatedBy: createdBy,
		CreatedAt: time.Now(),
	}, nil
}

func (j *Job) NextState() (isCompleted bool) {
	switch j.State {
	case JOB_STATE_QUEUED:
		j.State = JOB_STATE_STARTED

		return false
	case JOB_STATE_STARTED:
		j.State = JOB_STATE_COMPLETED

		return true
	}

	return true
}

func (j *Job) Error(err error) {
	j.State = JOB_STATE_ERROR

	e := err.Error()
	j.ErrorText = &e
}
