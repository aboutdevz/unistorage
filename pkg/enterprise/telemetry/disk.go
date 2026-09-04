package telemetry

// DiskUsage represents storage filesystem space statistics.
type DiskUsage struct {
	Path        string  `json:"path"`
	TotalBytes  uint64  `json:"total_bytes"`
	FreeBytes   uint64  `json:"free_bytes"`
	AvailBytes  uint64  `json:"avail_bytes"`
	UsedBytes   uint64  `json:"used_bytes"`
	UsedPercent float64 `json:"used_percent"`
}
