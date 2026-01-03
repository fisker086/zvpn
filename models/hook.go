package models

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	"gorm.io/gorm"
)

type HookPoint int

const (
	PreRouting  HookPoint = 0
	PostRouting HookPoint = 1
	Forward     HookPoint = 2
	Input       HookPoint = 3
	Output      HookPoint = 4
)

func (h HookPoint) String() string {
	switch h {
	case PreRouting:
		return "PRE_ROUTING"
	case PostRouting:
		return "POST_ROUTING"
	case Forward:
		return "FORWARD"
	case Input:
		return "INPUT"
	case Output:
		return "OUTPUT"
	default:
		return "UNKNOWN"
	}
}

type HookType string

const (
	ACLHook             HookType = "acl"
	PortFilterHook      HookType = "port_filter"
	UserPolicyHook      HookType = "user_policy"
	TimeRestrictionHook HookType = "time_restriction"
	CustomHook          HookType = "custom"
)

type PolicyAction int

const (
	Allow    PolicyAction = 0
	Deny     PolicyAction = 1
	Redirect PolicyAction = 2
	Log      PolicyAction = 3
)

type Hook struct {
	ID        string         `gorm:"primarykey;size:255" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Name        string    `gorm:"not null;size:255" json:"name"`
	HookPoint   HookPoint `gorm:"not null" json:"hook_point"`
	Priority    int       `gorm:"not null" json:"priority"`
	Type        HookType  `gorm:"not null;size:50" json:"type"`
	Enabled     bool      `gorm:"default:true" json:"enabled"`
	Description string    `gorm:"type:text" json:"description,omitempty"`
	Rules       HookRules `gorm:"type:json" json:"rules"`
	Stats       *HookStats `gorm:"-" json:"stats,omitempty"` // 运行时统计，不存储在数据库
}

type HookRules []HookRule

func (r *HookRules) Scan(value interface{}) error {
	if value == nil {
		*r = []HookRule{}
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}

	return json.Unmarshal(bytes, r)
}

func (r HookRules) Value() (driver.Value, error) {
	if len(r) == 0 {
		return "[]", nil
	}
	return json.Marshal(r)
}

type HookRule struct {
	SourceIPs           []string `json:"source_ips,omitempty"`
	DestinationIPs      []string `json:"destination_ips,omitempty"`
	SourceNetworks      []string `json:"source_networks,omitempty"`
	DestinationNetworks []string `json:"destination_networks,omitempty"`

	SourcePorts      []int       `json:"source_ports,omitempty"`
	DestinationPorts []int       `json:"destination_ports,omitempty"`
	PortRanges       []PortRange `json:"port_ranges,omitempty"`

	Protocols []string `json:"protocols,omitempty"`

	UserIDs []uint `json:"user_ids,omitempty"`

	TimeRanges []TimeRange `json:"time_ranges,omitempty"`

	Action PolicyAction `json:"action"`
}

type PortRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

type TimeRange struct {
	StartTime string `json:"start_time"`         // HH:MM
	EndTime   string `json:"end_time"`           // HH:MM
	Weekdays  []int  `json:"weekdays,omitempty"` // 0-6
}

type HookStats struct {
	TotalMatches  uint64     `json:"total_matches"`
	TotalAllows   uint64     `json:"total_allows"`
	TotalDenies   uint64     `json:"total_denies"`
	LastMatchTime *time.Time `json:"last_match_time,omitempty"`
}
