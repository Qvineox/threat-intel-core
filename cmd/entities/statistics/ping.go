package statistics

import "gitlab.domsnail.ru/domsnail/threat-intel-core/api/services"

type PingScansStatistics struct {
	TotalScans      uint64 `json:"total_scans" gorm:"total_scans"`
	SuccessfulScans uint64 `json:"successful_scans" gorm:"column:successful_scans"`
	FailedScans     uint64 `json:"failed_scans" gorm:"failed_scans"`

	DistinctIPs uint64 `json:"distinct_ips" gorm:"column:distinct_ips"`
}

func (stats PingScansStatistics) ToProto() *services.PingScanStatistics {
	return &services.PingScanStatistics{
		Common: &services.CommonStatistics{
			TotalScans:      stats.TotalScans,
			SuccessfulScans: stats.SuccessfulScans,
			FailedScans:     stats.FailedScans,
			DistinctIPs:     stats.DistinctIPs,
		},
	}
}
