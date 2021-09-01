package trojan

import (
	"encoding/json"
	"fmt"

	UlyssesServer "github.com/TunnelWork/Ulysses/src/server"
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
	mysqlHost     string
	mysqlPort     string
	mysqlDatabase string
	mysqlUser     string
	mysqlPasswd   string
	mysqlKeyPath  string
	mysqlCertPath string
	mysqlCAPath   string
}

func loadServerConf(sconf *UlyssesServer.ServerConfigurables) (serverconf, error) {
	lsconf := serverconf{}

	mysqlHost, ok := (*sconf)["mysqlHost"]
	if !ok {
		return lsconf, UlyssesServer.ErrServerConfigurables
	}
	lsconf.mysqlHost = mysqlHost

	mysqlPort, ok := (*sconf)["mysqlPort"]
	if !ok {
		return lsconf, UlyssesServer.ErrServerConfigurables
	}
	lsconf.mysqlPort = mysqlPort

	mysqlDatabase, ok := (*sconf)["mysqlDatabase"]
	if !ok {
		return lsconf, UlyssesServer.ErrServerConfigurables
	}
	lsconf.mysqlDatabase = mysqlDatabase

	mysqlUser, ok := (*sconf)["mysqlUser"]
	if !ok {
		return lsconf, UlyssesServer.ErrServerConfigurables
	}
	lsconf.mysqlUser = mysqlUser

	mysqlPasswd, ok := (*sconf)["mysqlPasswd"]
	if !ok {
		return lsconf, UlyssesServer.ErrServerConfigurables
	}
	lsconf.mysqlPasswd = mysqlPasswd

	mysqlKeyPath, ok := (*sconf)["mysqlKeyPath"]
	if !ok {
		return lsconf, UlyssesServer.ErrServerConfigurables
	}
	lsconf.mysqlKeyPath = mysqlKeyPath

	mysqlCertPath, ok := (*sconf)["mysqlCertPath"]
	if !ok {
		return lsconf, UlyssesServer.ErrServerConfigurables
	}
	lsconf.mysqlCertPath = mysqlCertPath

	mysqlCAPath, ok := (*sconf)["mysqlCAPath"]
	if !ok {
		return lsconf, UlyssesServer.ErrServerConfigurables
	}
	lsconf.mysqlCAPath = mysqlCAPath

	return lsconf, nil
}

// server.Server struct
type Server struct {
}

func (s Server) AddAccount(sconf *UlyssesServer.ServerConfigurables, aconf *UlyssesServer.AccountConfigurables) (accid int, err error) {
	lsconf, err := loadServerConf(sconf)
	if err != nil {
		return 0, err
	}

	// TODO: Connect to MySQL

	return 0, nil
}
