package entities

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgtype"
	"gitlab.qvineox.ru/domsnail/threat-intel-core/api/services"
	"net"
	"time"
)

type PingResult struct {
	// UUID should use version 7
	UUID *uuid.UUID `json:"UUID" gorm:"primary_key;type:uuid"`

	IP           pgtype.Inet `json:"IP" gorm:"column:ip;not_null;type:inet;index"`
	ResolvedName *string     `json:"ResolvedName" gorm:"column:resolved_name;index"`

	ResponseType services.ResponseType `json:"ResponseType" gorm:"column:response_type;not_null;index'"`

	PacketsSent uint32  `json:"PacketsSent" gorm:"column:packets_sent"`
	PacketsLoss float32 `json:"PacketsLoss" gorm:"column:packets_loss"`

	MinRtt float32 `json:"MinRtt" gorm:"column:min_rtt"`
	MaxRtt float32 `json:"MaxRtt" gorm:"column:max_rtt"`
	AvgRtt float32 `json:"AvgRtt" gorm:"column:avg_rtt"`

	// CreatedAt date of data collection
	CreatedAt time.Time `json:"CreatedAt" gorm:"column:created_at;index:,sort:desc"`
}

func NewPingResultFromProto(r *services.PingResult) (*PingResult, error) {
	uuidV7, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}

	ip_ := net.ParseIP(r.GetIP())
	if ip_ == nil {
		return nil, errors.New("received invalid ip address")
	}

	return &PingResult{
		UUID:         &uuidV7,
		IP:           pgtype.Inet{IPNet: &net.IPNet{IP: ip_, Mask: net.IPv4Mask(255, 255, 255, 255)}},
		ResponseType: r.GetResponse(),
		ResolvedName: r.ResolvedName,
		PacketsSent:  r.PacketsSent,
		PacketsLoss:  r.PacketsLoss,
		MinRtt:       r.MinRtt,
		MaxRtt:       r.MaxRtt,
		AvgRtt:       r.AvgRtt,
		CreatedAt:    time.Now(),
	}, nil
}

func (p PingResult) String() string {
	return fmt.Sprintf("PING-{%s, %s, %d}", p.UUID.String(), p.IP.IPNet.String(), p.ResponseType)
}
