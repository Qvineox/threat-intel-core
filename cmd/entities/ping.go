package entities

import (
	"fmt"
	"github.com/google/uuid"
	"gitlab.qvineox.ru/domsnail/threat-intel-core/api/services"
	"time"
)

type PingResult struct {
	// UUID should use version 7
	UUID *uuid.UUID `json:"UUID" gorm:"primary_key;type:uuid"`

	Target       string                `json:"Target" gorm:"column:target;not_null;type:inet;index"`
	ResponseType services.ResponseType `json:"ResponseType" gorm:"column:response_type;not_null"`
	Latency      *uint64               `json:"Latency" gorm:"column:latency"`
	ResolvedName *string               `json:"ResolvedName" gorm:"column:resolved_name;index"`

	// CreatedAt date of data collection
	CreatedAt time.Time `json:"CreatedAt" gorm:"column:created_at;index:,sort:desc"`
}

func NewPingResultFromProto(r *services.PingResult) (*PingResult, error) {
	uuidV7, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}

	return &PingResult{
		UUID:         &uuidV7,
		Target:       r.GetTarget(),
		ResponseType: r.Response,
		Latency:      r.Latency,
		ResolvedName: r.ResolvedName,
		CreatedAt:    time.Now(),
	}, nil
}

func (p PingResult) String() string {
	return fmt.Sprintf("PING-{%s, %s, %d}", p.UUID.String(), p.Target, p.ResponseType)
}
