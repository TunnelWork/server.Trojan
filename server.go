package trojan

import (
	"encoding/json"
	"fmt"
	"sync"

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

// server.Server struct
type Server struct {
	lock      *sync.RWMutex
	mysqlConf mysqlConf
}

// NewServer creates a new Server struct by saving ServerConfigurables into Server struct
// then initialize a new RWMutex.
func NewServer(sconf UlyssesServer.ServerConfigurables) (Server, error) {
	newServer := Server{}

	mysqlConf, err := parseServerConf(sconf)
	if err != nil {
		return newServer, err
	}
	newServer.mysqlConf = mysqlConf
	newServer.lock = &sync.RWMutex{}

	return newServer, nil
}

// UpdateServer update the saved ServerConfigurables for a Server
// this implemenetation will be useful for memory-persistent implementation
func (s Server) UpdateServer(sconf UlyssesServer.ServerConfigurables) (err error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	mysqlConf, err := parseServerConf(sconf)
	if err != nil {
		return err
	}
	s.mysqlConf = mysqlConf

	return nil
}

// AddAccount add a set of new Trojan users into the database specified by s.mysqlConf
// and return the added user IDs
func (s Server) AddAccount(aconf []UlyssesServer.AccountConfigurables) (accid []int, err error) {
	db, err := connectDB(s.mysqlConf)
	if err != nil {
		return accid, err
	}
	defer db.Close()

	if isValidTrojanConf(aconf, ADD) {
		accid, err = newTrojanAccounts(db, aconf)
	}

	return accid, err
}

func (s Server) UpdateAccount(accID []int, aconf []UlyssesServer.AccountConfigurables) (successAccID []int, err error) {
	db, err := connectDB(s.mysqlConf)
	if err != nil {
		return successAccID, err
	}
	defer db.Close()

	if isValidTrojanConf(aconf, UPDATE) {
		// TODO: update mysql.go
		successAccID, err = updateTrojanAccounts(db, accID, aconf)
	}

	return successAccID, err
}

func (s Server) DeleteAccount(accID []int) (successAccID []int, err error) {
	db, err := connectDB(s.mysqlConf)
	if err != nil {
		return successAccID, err
	}
	defer db.Close()

	// TODO: update mysql.go
	successAccID, err = deleteTrojanAccounts(db, accID)

	return successAccID, err
}

func (s Server) GetCredentials(accID []int) (credentials []Credential, err error) {
	db, err := connectDB(s.mysqlConf)
	if err != nil {
		return credentials, err
	}
	defer db.Close()

	credentials, err = getCredentialTrojanAccounts(db, accID)

	return credentials, err
}

func (s Server) GetUsage(accID []int) (usages []Usage, err error) {
	db, err := connectDB(s.mysqlConf)
	if err != nil {
		return usages, err
	}
	defer db.Close()

	usages, err = getUsageTrojanAccounts(db, accID)

	return usages, err
}

// InitDB is a wrapper for initDB() which initializes a database(scheme) for
// Trojan by creating a table under the name `user`.
// When hard == true, it will overwrite the existing table with name `user`
func InitDB(sconf mysqlConf, hard bool) error {
	return initDB(sconf, hard)
}
