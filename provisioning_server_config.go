package utrojan

import (
	"encoding/json"

	"github.com/TunnelWork/Ulysses.Lib/server"
)

type ServerInfo struct {
	ServerAddress          string  `json:"server_address"`
	ServerPort             uint16  `json:"server_port"`
	ServerMonthlyBandwidth float64 `json:"server_monthly_bandwidth"` // in bytes
}

type ProvisioningServerConfig struct {
	Mysql MysqlConfig `json:"mysql"`
	Info  ServerInfo  `json:"server_info"`
}

func ParseProvisioningServerConfig(v interface{}) (ProvisioningServerConfig, error) {
	switch value := v.(type) {
	case ProvisioningServerConfig:
		return value, nil
	case map[string]interface{}:
		jsonString, _ := json.Marshal(value)
		var result ProvisioningServerConfig
		err := json.Unmarshal(jsonString, &result)
		return result, err
	case string:
		var result ProvisioningServerConfig
		err := json.Unmarshal([]byte(value), &result)
		return result, err
	default:
		return ProvisioningServerConfig{}, server.ErrServerConfigurables
	}
}

func (psc ProvisioningServerConfig) ToJson() string {
	jsonString, _ := json.Marshal(psc)
	return string(jsonString)
}
