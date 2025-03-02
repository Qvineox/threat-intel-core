package timekeeping

import (
	"github.com/google/uuid"
	"gitlab.domsnail.ru/domsnail/threat-intel-core/api/services"
	"google.golang.org/protobuf/types/known/timestamppb"
	"time"
)

type ScheduledRoutine struct {
	UUID uuid.UUID `json:"UUID"`

	IsEnabled bool `json:"IsEnabled"`
	IsRunning bool `json:"IsRunning"`

	Name        string `json:"Name"`
	Group       string `json:"Group"`
	Description string `json:"Description"`

	Cron string `json:"Cron"`

	LastSuccessText string `json:"LastSuccessText"`
	LastErrorText   string `json:"LastErrorText"`

	LastRunAt           *time.Time `json:"LastRunAt"`
	LastSuccessfulRunAt *time.Time `json:"LastSuccessfulRunAt"`
	NextRunAt           time.Time  `json:"NextRunAt"`

	Run *func() (text string, err error) `json:"-"`
}

func (r ScheduledRoutine) ToProto() *services.ScheduledRoutine {
	p := &services.ScheduledRoutine{
		UUID:            r.UUID.String(),
		IsEnabled:       r.IsEnabled,
		IsRunning:       r.IsRunning,
		Name:            r.Name,
		Group:           r.Group,
		Description:     r.Description,
		CRON:            r.Cron,
		NextRunAt:       timestamppb.New(r.NextRunAt),
		LastSuccessText: r.LastSuccessText,
		LastErrorText:   r.LastErrorText,
	}

	if r.LastRunAt != nil {
		p.LastRunAt = timestamppb.New(*r.LastRunAt)
	}

	if r.LastSuccessfulRunAt != nil {
		p.LastSuccessfulRunAt = timestamppb.New(*r.LastSuccessfulRunAt)
	}

	return p
}
