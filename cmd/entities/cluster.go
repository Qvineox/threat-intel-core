package entities

import (
	"gitlab.domsnail.ru/domsnail/threat-intel-core/api/services"
	"google.golang.org/protobuf/types/known/timestamppb"
	"time"
)

type Cluster struct {
	ID *uint64 `json:"UUID" gorm:"primary_key"`

	Name        string `json:"Name" gorm:"column:name;not null;unique;comment:Cluster identity"`
	Description string `json:"Description" gorm:"column:description;comment:Cluster info (i.e. host, geo etc)"`

	IsActive bool   `json:"IsActive" gorm:"column:is_active;index"`
	BotToken string `json:"BotToken" gorm:"column:bot_token;index;comment:Bot auth token"`

	CreatedAt time.Time `json:"CreatedAt"`
	UpdatedAt time.Time `json:"UpdatedAt"`
}

func NewClusterFromProto(p *services.Cluster) (*Cluster, error) {
	c := &Cluster{
		ID:          p.ID,
		Name:        p.GetName(),
		Description: p.GetDescription(),
		IsActive:    p.GetIsActive(),
	}

	token := p.GetToken()
	if token != nil {
		c.BotToken = token.GetJWT()
	}

	return c, nil
}

func (c *Cluster) ToProto() *services.Cluster {
	return &services.Cluster{
		ID:          c.ID,
		Name:        c.Name,
		Description: c.Description,
		IsActive:    c.IsActive,
		//Token:       nil,
		CreatedAt: timestamppb.New(c.CreatedAt),
		UpdatedAt: timestamppb.New(c.UpdatedAt),
	}
}
