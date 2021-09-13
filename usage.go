package ulyssestrojan

import (
	"encoding/json"
	"fmt"
)

// server.AccountUsage struct
type AccountUsage struct {
	TrafficQuota    int64  // BIGINT
	TrafficDownload uint64 // BIGINT_UNSIGNED
	TrafficUpload   uint64 // BIGINT_UNSIGNED
}

// ForClient() returns the JSON string representing traffic info including Quota, Download, Upload
func (u AccountUsage) ForClient() (usage string) {
	b, err := json.Marshal(u)
	if err != nil {
		return fmt.Sprintf(`{"Error":"%s"}`, err.Error())
	}
	usage = string(b)
	return usage
}

// ForAdmin() No diff from ForClient() for trojan protocol
func (u AccountUsage) ForAdmin() (usage string) {
	return u.ForClient()
}
