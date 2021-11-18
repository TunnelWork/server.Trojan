package utrojan

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io/ioutil"

	harpocrates "github.com/TunnelWork/Harpocrates"
	"github.com/TunnelWork/Ulysses.Lib/security"
	"github.com/TunnelWork/Ulysses.Lib/server"
	"github.com/go-sql-driver/mysql"
)

func mysqlConnect(conf MysqlConfig) (*sql.DB, error) {
	driverName := "mysql"
	// dsn = fmt.Sprintf("user:password@tcp(localhost:5555)/dbname?tls=skip-verify&autocommit=true")
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?loc=Local&autocommit=true", conf.User, conf.Password, conf.Host, conf.Port, conf.Database)
	if conf.CACertPath != "" {
		dsn += "&tls=custom"
		rootCertPool := x509.NewCertPool()
		pem, err := ioutil.ReadFile(conf.CACertPath)
		if err != nil {
			return nil, err
		}
		ok := rootCertPool.AppendCertsFromPEM(pem)
		if !ok {
			return nil, server.ErrServerConfigurables
		}
		if conf.ClientCertPath != "" && conf.ClientKeyPath != "" {
			// Both Key and Cert are set. Go with customer cert.
			clientCert := make([]tls.Certificate, 0, 1)
			certs, err := tls.LoadX509KeyPair(conf.ClientCertPath, conf.ClientKeyPath)
			if err != nil {
				return nil, err
			}
			clientCert = append(clientCert, certs)
			mysql.RegisterTLSConfig("custom", &tls.Config{
				// ServerName: "example.com",
				RootCAs:      rootCertPool,
				Certificates: clientCert,
				MinVersion:   tls.VersionTLS12,
				MaxVersion:   0,
			})
		} else if conf.ClientCertPath == "" && conf.ClientKeyPath == "" {
			// Neither Key or Cert is set. Proceed without customer cert.
			mysql.RegisterTLSConfig("custom", &tls.Config{
				// ServerName: "example.com",
				RootCAs:    rootCertPool,
				MinVersion: tls.VersionTLS12,
				MaxVersion: 0,
			})
		} else {
			// one of Key or Cert is set but not both, which is ILLEGAL.
			return nil, server.ErrServerConfigurables
		}
	}

	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, err
	}

	if connected, err := mysqlIsConnected(db); !connected {
		return nil, err
	}
	return db, nil
}

func mysqlIsConnected(db *sql.DB) (bool, error) {
	err := db.Ping()
	if err != nil {
		return false, err
	}
	return true, nil
}

func mysqlCreateTableIfNotExists(db *sql.DB) error {
	stmtCreateTableIfNotExists, err := db.Prepare(`CREATE TABLE users (
        id INT UNSIGNED NOT NULL AUTO_INCREMENT,
        password CHAR(56) NOT NULL,
        quota BIGINT NOT NULL DEFAULT 0,
        download BIGINT UNSIGNED NOT NULL DEFAULT 0,
        upload BIGINT UNSIGNED NOT NULL DEFAULT 0,
        product_serial_number BIGINT UNSIGNED NOT NULL,
        password_encrypted VARCHAR() NOT NULL,
		last_refresh DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY (password),
        INDEX (product_serial_number)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;`)
	if err != nil {
		return err
	}
	defer stmtCreateTableIfNotExists.Close()

	_, err = stmtCreateTableIfNotExists.Exec()
	return err
}

/**** User Table Operations ****/
func createAccount(db *sql.DB, productSN uint64, conf AccountConfiguration) error {
	stmtCreateAccount, err := db.Prepare(`INSERT INTO users (
        password, 
        quota,
        product_serial_number, 
        password_encrypted,
		last_refresh
    ) VALUES (?, ?, ?, ?, NOW())`)
	if err != nil {
		return err
	}
	defer stmtCreateAccount.Close()

	_, err = stmtCreateAccount.Exec(
		conf.PasswordSHA224(),
		conf.QuotaBytes(),
		productSN,
		conf.PasswordEncrypted(),
	)

	return err
}

func getAccount(db *sql.DB, productSN uint64) (*Account, error) {
	stmtGetAccount, err := db.Prepare(`SELECT password, quota, download + upload, product_serial_number, password_encrypted, last_refresh FROM users WHERE product_serial_number = ?`)
	if err != nil {
		return nil, err
	}
	defer stmtGetAccount.Close()

	var account Account = Account{
		credentials: &Credentials{},
		resources: []*server.Resource{
			{
				ResourceID: server.RESOURCE_DATA_TRANSFER,
			},
			{
				ResourceID: server.RESOURCE_SERVICE_HOUR,
			},
		},
	}
	var trafficBytesAllocated int64
	var trafficBytesUsed uint64

	err = stmtGetAccount.QueryRow(productSN).Scan(
		&account.credentials.passwordSHA224,
		// resourceID needs to be set
		&trafficBytesAllocated,
		&trafficBytesUsed,
		// Don't forget compute Free
		&account.credentials.productSN,
		&account.credentials.passwordDecrypted, // Still needs to be decrypted
		&account.credentials.timeLastRefresh,
	)

	if err != nil {
		return nil, err
	}

	// Convert bytes to GB
	if trafficBytesAllocated > 0 {
		account.resources[0].Allocated = float64(trafficBytesAllocated/1024/1024) / 1024
	} else {
		account.resources[0].Allocated = -1
	}
	account.resources[0].Used = float64(trafficBytesUsed/1024/1024) / 1024

	return &account, err
}

func updateAccount(db *sql.DB, productSN uint64, conf AccountConfiguration) error {
	stmtUpdateAccount, err := db.Prepare(`UPDATE users SET
        password = ?,
        quota = ?,
        product_serial_number = ?,
        password_encrypted = ?
    WHERE product_serial_number = ?`)
	if err != nil {
		return err
	}
	defer stmtUpdateAccount.Close()

	_, err = stmtUpdateAccount.Exec(
		conf.PasswordSHA224(),
		conf.QuotaBytes(),
		productSN,
		conf.PasswordEncrypted(),
		productSN,
	)

	return err
}

func deleteAccount(db *sql.DB, productSN uint64) error {
	stmtDeleteAccount, err := db.Prepare(`DELETE FROM users WHERE product_serial_number = ?`)
	if err != nil {
		return err
	}
	defer stmtDeleteAccount.Close()

	_, err = stmtDeleteAccount.Exec(productSN)

	return err
}

func maskPasswdAccount(db *sql.DB, productSN uint64) error {
	rndPasswd, err := harpocrates.GetRandomHex(28)
	if err != nil {
		return err
	}

	stmtPasswdAccount, err := db.Prepare(`UPDATE users SET
        password = ?
    WHERE product_serial_number = ?`)
	if err != nil {
		return err
	}
	defer stmtPasswdAccount.Close()

	_, err = stmtPasswdAccount.Exec(
		rndPasswd,
		productSN,
	)

	return err
}

func unmaskPasswdAccount(db *sql.DB, productSN uint64) error {
	// Fetch encrypted password first
	stmtPasswdAccount, err := db.Prepare(`SELECT password_encrypted FROM users WHERE product_serial_number = ?`)
	if err != nil {
		return err
	}
	defer stmtPasswdAccount.Close()

	var passwordEncrypted string
	err = stmtPasswdAccount.QueryRow(productSN).Scan(
		&passwordEncrypted,
	)

	if err != nil {
		return err
	}

	// Decrypt password
	passwordDecrypted := security.EncryptPassword(passwordEncrypted)

	// Set password
	stmtPasswdAccount, err = db.Prepare(`UPDATE users SET
        password = ?
    WHERE product_serial_number = ?`)
	if err != nil {
		return err
	}
	defer stmtPasswdAccount.Close()

	_, err = stmtPasswdAccount.Exec(
		passwordDecrypted,
		productSN,
	)

	return err
}

func refreshDownloadUploadAccount(db *sql.DB, productSN uint64) error {
	stmtRefreshAccount, err := db.Prepare(`UPDATE users SET
        download = 0,
        upload = 0,
		last_refresh = NOW()
    WHERE product_serial_number = ?`)
	if err != nil {
		return err
	}
	defer stmtRefreshAccount.Close()

	_, err = stmtRefreshAccount.Exec(productSN)

	return err
}
