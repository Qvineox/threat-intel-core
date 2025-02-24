package statistics

import "gitlab.domsnail.ru/domsnail/threat-intel-core/api/services"

type CoverageStatistics struct {
	TotalScans  uint64 `json:"total_scans" gorm:"total_scans"`
	DistinctIPs uint64 `json:"distinct_ips" gorm:"column:distinct_ips"`

	PercentOfTotalIPs float32 `json:"percent_of_total_ips" gorm:"column:percent_of_total_ips"`
	PercentOfSavedIPs float32 `json:"percent_of_saved_ips" gorm:"column:percent_of_saved_ips"`
}

func (stats CoverageStatistics) ToProto() *services.CoverageStatistics {
	return &services.CoverageStatistics{
		TotalScans:        stats.TotalScans,
		DistinctIPs:       stats.DistinctIPs,
		PercentOfSavedIPs: stats.PercentOfSavedIPs,
		PercentOfTotalIPs: stats.PercentOfTotalIPs,
	}
}
