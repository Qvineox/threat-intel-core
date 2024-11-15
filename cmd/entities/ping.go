package entities

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgtype"
	"gitlab.qvineox.ru/domsnail/threat-intel-core/api/services"
	"time"
)

type PingResult struct {
	// UUID should use version 7
	UUID *uuid.UUID `json:"UUID" gorm:"primary_key;type:uuid"`

	IP           pgtype.Inet `json:"IP" gorm:"column:ip;not_null;type:inet;index;comment:Targeted IP address, can have multiple IP for a single host"`
	ResolvedName *string     `json:"ResolvedName" gorm:"column:resolved_name;index;comment:Host assigned to resolved IP address"`

	ResponseType uint64 `json:"ResponseType" gorm:"column:response_type;not_null;type:smallint;index"`

	PacketsSent uint32  `json:"PacketsSent" gorm:"column:packets_sent;type:smallint;comment:Amount of packets sent in a single ping query"`
	PacketsLoss float32 `json:"PacketsLoss" gorm:"column:packets_loss;type:numeric(5,2)"`

	MinRttMs *uint64 `json:"MinRttMs" gorm:"column:min_rtt_ms;type:numeric(6);comment:Min round trip in milliseconds"`
	MaxRttMs *uint64 `json:"MaxRttMs" gorm:"column:max_rtt_ms;type:numeric(6);comment:Max round trip in milliseconds"`
	AvgRttMs *uint64 `json:"AvgRttMs" gorm:"column:avg_rtt_ms;type:numeric(6);comment:Average round trip in milliseconds"`

	// CreatedAt date of data collection
	CreatedAt time.Time `json:"CreatedAt" gorm:"column:created_at;index:,sort:desc"`

	// CreatedBy is the identity of a bot
	CreatedBy *string `json:"CreatedBy" gorm:"column:created_by;index;comment:Ping bot identity recovered from response metadata"`
}

func NewPingResultFromProto(r *services.PingResult, createdBy *string) (*PingResult, error) {
	uuidV7, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}

	ip_ := pgtype.Inet{}
	err = ip_.Set(r.GetIP())
	if err != nil {
		return nil, errors.New("received invalid ip address")
	}

	return &PingResult{
		UUID:         &uuidV7,
		IP:           ip_,
		ResponseType: uint64(r.GetResponse()),
		ResolvedName: r.ResolvedName,
		PacketsSent:  r.PacketsSent,
		PacketsLoss:  r.PacketsLoss,
		MinRttMs:     r.MinRttMs,
		MaxRttMs:     r.MaxRttMs,
		AvgRttMs:     r.AvgRttMs,
		CreatedAt:    time.Now(),
		CreatedBy:    createdBy,
	}, nil
}

func (p PingResult) String() string {
	return fmt.Sprintf("PING-{%s, %s, %d}", p.UUID.String(), p.IP.IPNet.String(), p.ResponseType)
}
