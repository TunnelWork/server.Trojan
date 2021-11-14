package utrojan

import (
	"database/sql"
	"sync"

	"github.com/TunnelWork/Ulysses.Lib/security"
	"github.com/TunnelWork/Ulysses.Lib/server"
	_ "github.com/go-sql-driver/mysql"
)

func NewProvisioningServer( /*_ *sql.DB, */ instanceID string, serverConfiguration interface{}) (server.ProvisioningServer, error) {
	var psc ProvisioningServerConfig
	var err error
	psc, err = ParseProvisioningServerConfig(serverConfiguration)
	if err != nil {
		return nil, err
	}

	db, err := mysqlConnect(psc.Mysql)
	if err != nil {
		return nil, err
	}

	err = mysqlCreateTableIfNotExists(db)
	if err != nil {
		return nil, err
	}

	var p ProvisioningServer = ProvisioningServer{
		lock:   sync.RWMutex{},
		config: psc,
		db:     db,
	}

	return &p, nil
}

type ProvisioningServer struct {
	lock   sync.RWMutex
	config ProvisioningServerConfig
	db     *sql.DB
}

// TODO: implement after upstream (Ulysses.Lib/Server) is confirmed
// func (p *ProvisioningServer) ResourceGroup() server.ServerResourceGroup {
// 	return NewServerResourceGroup()
// }

func (p *ProvisioningServer) CreateAccount(productSN uint64, accountConfiguration interface{}) error {
	conf, err := ParseAccountConfiguration(accountConfiguration)
	if err != nil {
		return err
	}

	return createAccount(p.db, productSN, conf)
}

func (p *ProvisioningServer) GetAccount(productSN uint64) (server.Account, error) {
	account, err := getAccount(p.db, productSN)
	if err != nil {
		return nil, err
	}

	// Complete filling resource details
	account.resources[0].ResourceID = server.RESOURCE_DATA_TRANSFER
	account.resources[0].Free = -1
	if account.resources[0].Allocated > 0 {
		account.resources[0].Free = account.resources[0].Allocated - account.resources[0].Used
	}

	// Complete password decryption
	account.credentials.passwordDecrypted = security.DecryptPassword(account.credentials.passwordDecrypted)

	return account, nil
}

func (p *ProvisioningServer) UpdateAccount(productSN uint64, accountConfiguration interface{}) error {
	conf, err := ParseAccountConfiguration(accountConfiguration)
	if err != nil {
		return err
	}

	return updateAccount(p.db, productSN, conf)
}

func (p *ProvisioningServer) DeleteAccount(productSN uint64) error {
	return deleteAccount(p.db, productSN)
}

// Update password_sha224 to some random stuff
func (p *ProvisioningServer) SuspendAccount(productSN uint64) error {
	return maskPasswdAccount(p.db, productSN)
}

// Recover password_sha224 from password_encrypted
func (p *ProvisioningServer) UnsuspendAccount(productSN uint64) error {
	return unmaskPasswdAccount(p.db, productSN)
}

// Currently only clears data usage
func (p *ProvisioningServer) RefreshAccount(productSN uint64) error {
	return refreshDownloadUploadAccount(p.db, productSN)
}
