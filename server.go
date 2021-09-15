package ulyssestrojan

import (
	"sync"

	UlyssesServer "github.com/TunnelWork/Ulysses/src/server"
	_ "github.com/go-sql-driver/mysql"
)

// Server does not implement UlyssesServer.Server interface for
// memory safety restrictions (i.e. UlyssesServer.Server should be copyable).
// Instead, *Server does.
type Server struct {
	lock      sync.RWMutex
	mysqlConf mysqlConf
}

// UpdateServer update the saved ServerConfigurables for a Server
// this implemenetation will be useful for memory-persistent implementation
func (s *Server) UpdateServer(sconf UlyssesServer.Configurables) (err error) {
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
func (s *Server) AddAccount(aconf []UlyssesServer.Configurables) (accid []int, err error) {
	accid = []int{}
	db, err := connectDB(s.mysqlConf)
	if err != nil {
		return accid, err
	}
	defer db.Close()

	if arrTrojanAccountConfigurables, err := parseTrojanAccountConfigurables(aconf, ADD); err != nil {
		return accid, err
	} else {
		accid, err = newTrojanAccounts(db, arrTrojanAccountConfigurables)
		if err != nil {
			return nil, err
		}
	}

	return accid, err
}

func (s *Server) UpdateAccount(accID []int, aconf []UlyssesServer.Configurables) (successAccID []int, err error) {
	successAccID = []int{}
	db, err := connectDB(s.mysqlConf)
	if err != nil {
		return successAccID, err
	}
	defer db.Close()

	if arrTrojanAccountConfigurables, err := parseTrojanAccountConfigurables(aconf, UPDATE); err != nil {
		return successAccID, err
	} else {
		successAccID, err = updateTrojanAccounts(db, accID, arrTrojanAccountConfigurables)
		if err != nil {
			return nil, err
		}
	}

	return successAccID, err
}

func (s *Server) DeleteAccount(accID []int) (successAccID []int, err error) {
	db, err := connectDB(s.mysqlConf)
	if err != nil {
		return successAccID, err
	}
	defer db.Close()

	// TODO: update mysql.go
	successAccID, err = deleteTrojanAccounts(db, accID)

	return successAccID, err
}

func (s *Server) GetCredentials(accID []int) (credentials []UlyssesServer.Credential, err error) {
	db, err := connectDB(s.mysqlConf)
	if err != nil {
		return credentials, err
	}
	defer db.Close()

	credentials, err = getCredentialTrojanAccounts(db, accID)

	return credentials, err
}

func (s *Server) GetUsage(accID []int) (usages []UlyssesServer.AccountUsage, err error) {
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
func InitDB(sconf mysqlConf) error {
	return initDB(sconf)
}

// HardInitDB is a wrapper for initDB() which initializes a database(scheme) for
// Trojan by creating a table under the name `user`.
// It will overwrite the `user` table if it exist.
func HardInitDB(sconf mysqlConf) error {
	err := clearDB(sconf)
	if err != nil {
		return err
	}
	return initDB(sconf)
}
