package entities

import (
	"encoding/json"
	"fmt"
	"gitlab.domsnail.ru/domsnail/threat-intel-core/api/services"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/datatypes"
	"sort"
	"time"
)

type (
	JobType        uint64
	Priority       uint64
	AssignmentMode uint64
)

const (
	JOB_TYPE_PING JobType = 0
)

const (
	P_LOW      Priority = 0
	P_MEDIUM   Priority = 1
	P_HIGH     Priority = 2
	P_CRITICAL Priority = 3
)

const (
	BM_LEAST_TASKS AssignmentMode = 0
	BM_EVEN        AssignmentMode = 1
	BM_NON_BUSY    AssignmentMode = 2
)

// Job represents minimal system task provided by user
type Job struct {
	ID   *uint64 `json:"ID" gorm:"primary_key"`
	Type JobType `json:"Type" gorm:"column:type;index;not null;comment:Job type"`

	IsAllocated *bool `json:"IsAllocated" gorm:"column:is_allocated;type:boolean;not null;default:false;comment:Is job sent to coordination unit"`
	IsStarted   *bool `json:"IsStarted" gorm:"column:is_started;type:boolean;not null;default:false;comment:Is job has been successfully started by bots"`
	//State JobState `json:"State" gorm:"column:state;not null;type:varchar(10);comment:Current job state"`

	Priority Priority       `json:"Priority" gorm:"column:priority;comment:Job relative priority.\n0 to 3 (higher is better)"`
	Mode     AssignmentMode `json:"AssignmentMode" gorm:"column:mode;comment:Job balancing mode.\n0 = least tasks\n1 = even\n2 = non busy"`

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

func (j *Job) ToProto() *services.Job {
	return &services.Job{
		ID:          j.ID,
		Type:        services.JobType(j.Type),
		IsAllocated: *j.IsAllocated,
		IsStarted:   *j.IsStarted,
		Mode:        services.AssignmentMode(j.Mode),
		Priority:    services.Priority(j.Priority),
		Options:     j.Options,
		ErrorText:   j.ErrorText,
		CreatedBy:   j.CreatedBy,
		CreatedAt:   timestamppb.New(j.CreatedAt),
		UpdatedAt:   timestamppb.New(j.UpdatedAt),
	}
}

func NewPingJobFromProto(desc *services.PingOptions, createdBy *uint64) (*Job, error) {
	if desc == nil || desc.Default == nil || desc.Default.Targets == nil {
		return nil, fmt.Errorf("targets not found")
	}

	body, err := json.Marshal(desc.Default)
	if err != nil {
		return nil, err
	}

	j := &Job{
		Type:      JOB_TYPE_PING,
		Options:   body,
		ErrorText: nil,
		CreatedBy: createdBy,
		CreatedAt: time.Now(),
	}

	if desc.Labels != nil {
		j.Priority = Priority(desc.Labels.Priority)
		j.Mode = AssignmentMode(desc.Labels.AssignmentMode)
	}

	return j, nil
}

func (j *Job) Error(err error) {
	e := err.Error()
	j.ErrorText = &e
}

// SortJobsByPriority higher priority first
func SortJobsByPriority(jobs []Job) {
	sort.Slice(jobs, func(i, j int) bool {
		return jobs[i].Priority > jobs[j].Priority
	})
}

// JobSummary additional summary data about Job
type JobSummary struct {
	ID         uint64 `json:"ID" gorm:"column:id"`
	ScansTotal uint64 `json:"ScansTotal" gorm:"column:scans_total"`

	StartedAt time.Time `json:"StartedAt" gorm:"column:started_at"`
	EndedAt   time.Time `json:"EndedAt" gorm:"column:ended_at"`
}

func (js *JobSummary) ToProto() *services.JobSummary {
	return &services.JobSummary{
		ID:         js.ID,
		ScansTotal: js.ScansTotal,
		StartedAt:  timestamppb.New(js.StartedAt),
		EndedAt:    timestamppb.New(js.EndedAt),
	}
}
