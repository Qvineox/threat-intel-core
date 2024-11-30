package entities

import (
	"encoding/json"
	"fmt"
	"gitlab.qvineox.ru/domsnail/threat-intel-core/api/services"
	"gorm.io/datatypes"
	"time"
)

type JobType uint64

const (
	JOB_TYPE_PING JobType = 0
)

// Job represents minimal system task provided by user
type Job struct {
	ID   *uint64 `json:"ID" gorm:"primary_key"`
	Type JobType `json:"Type" gorm:"column:type;index;not null;comment:Job type"`
	//State JobState `json:"State" gorm:"column:state;not null;type:varchar(10);comment:Current job state"`
	IsSent bool `json:"IsSent" gorm:"column:is_sent;type:boolean;not null;default:false;comment:Is job sent to processing unit"`

	Options   datatypes.JSON `json:"Options" gorm:"column:options;type:jsonb;comment:Full job parameters and targets as requested in job"`
	ErrorText *string        `json:"ErrorText" gorm:"column:error_text;type:text;comment:Job error message"`

	// CreatedBy is the identity of a user
	CreatedBy *uint64 `json:"CreatedBy" gorm:"column:created_by;index;comment:Job author's user ID"`

	CreatedAt time.Time `json:"CreatedAt"`
	UpdatedAt time.Time `json:"UpdatedAt"`
}

func (j *Job) String() string {
	return fmt.Sprintf("JOB-%d (%d)", *j.ID, j.Type)
}

func NewPingJobFromProto(desc *services.PingOptions, createdBy *uint64) (*Job, error) {
	if desc == nil || desc.Default == nil || desc.Default.Targets == nil {
		return nil, fmt.Errorf("targets not found")
	}

	body, err := json.Marshal(desc)
	if err != nil {
		return nil, err
	}

	return &Job{
		Type:      JOB_TYPE_PING,
		IsSent:    false,
		Options:   body,
		CreatedBy: createdBy,
		CreatedAt: time.Now(),
	}, nil
}

func (j *Job) Error(err error) {
	e := err.Error()
	j.ErrorText = &e
}
