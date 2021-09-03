package trojan

import (
	"encoding/json"
	"fmt"

	UlyssesServer "github.com/TunnelWork/Ulysses/src/server"
	_ "github.com/go-sql-driver/mysql"
)

// server.AccountUsage struct
type Usage struct {
	TrafficQuota    int64  // BIGINT
	TrafficDownload uint64 // BIGINT_UNSIGNED
	TrafficUpload   uint64 // BIGINT_UNSIGNED
}

// ForClient() returns the JSON string representing traffic info including Quota, Download, Upload
func (u Usage) ForClient() (usage string) {
	b, err := json.Marshal(u)
	if err != nil {
		return fmt.Sprintf(`{"Error":"%s"}`, err.Error())
	}
	usage = string(b)
	return usage
}

// ForAdmin() No diff from ForClient() for trojan protocol
func (u Usage) ForAdmin() (usage string) {
	return u.ForClient()
}

// server.Credential struct
type Credential struct {
	Id           uint   // Not needed for connection
	Username     string // Not needed for connection
	PasswdSHA224 string // Don't think it could be insightful
}

// ForClient() is not useful for trojan protocol, given that password stored on DB server is hashed.
func (c Credential) ForClient() (credential string) {
	return ""
}

func (c Credential) ForAdmin() (credential string) {
	b, err := json.Marshal(c)
	if err != nil {
		return fmt.Sprintf(`{"Error":"%s"}`, err.Error())
	}
	credential = string(b)
	return credential
}

// internal struct supporting MySQL/MariaDB-based management
type serverconf struct {
	// Mandatory
	mysqlHost     string // For IPv6, use the format of [::]
	mysqlPort     uint16
	mysqlDatabase string
	mysqlUser     string
	mysqlPasswd   string

	// Optional
	mysqlCAPath   string
	mysqlKeyPath  string
	mysqlCertPath string
}

// server.Server struct
type Server struct {
}

func (s Server) AddAccount(sconf UlyssesServer.ServerConfigurables, aconf []UlyssesServer.AccountConfigurables) (accid []int, err error) {
	accid = make([]int, 0)
	servconf, err := loadServerConf(sconf)
	if err != nil {
		return accid, err
	}

	db, err := conn(servconf)
	if err != nil {
		return accid, err
	}
	defer db.Close()

	// TODO: Parse aconf, then INSERT one-by-one (in order to maximize the insertable amount before fail)

	return accid, err
}
