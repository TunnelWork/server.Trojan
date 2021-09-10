package trojan

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io/ioutil"
	"strconv"

	UlyssesServer "github.com/TunnelWork/Ulysses/src/server"
	"github.com/go-sql-driver/mysql"
	// _ "github.com/go-sql-driver/mysql"
)

const (
	dbEngineInsertResultUnknown     = 0
	dbEngineInsertResultSupported   = 1
	dbEngineInsertResultUnsupported = 2
)

const (
	mysqlAutoCommit        = true
	trojanTableName        = "users"
	trojanDropTableQuery   = `DROP TABLE IF EXISTS ` + trojanTableName
	trojanCreateTableQuery = `
		CREATE TABLE ` + trojanTableName + ` (
			id INT UNSIGNED NOT NULL AUTO_INCREMENT,
			username VARCHAR(64) NOT NULL,
			password CHAR(56) NOT NULL,
			quota BIGINT NOT NULL DEFAULT 0,
			download BIGINT UNSIGNED NOT NULL DEFAULT 0,
			upload BIGINT UNSIGNED NOT NULL DEFAULT 0,
			PRIMARY KEY (id),
			INDEX (password)
		)`
)

func dbIsConnected(db *sql.DB) (bool, error) {
	err := db.Ping()
	if err != nil {
		db.Close()
		return false, err
	}
	return true, nil
}

func connectDB(sconf mysqlConf) (*sql.DB, error) {
	driverName := "mysql"
	// dsn = fmt.Sprintf("user:password@tcp(localhost:5555)/dbname?tls=skip-verify&autocommit=true")
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?loc=Local", sconf.mysqlUser, sconf.mysqlPasswd, sconf.mysqlHost, sconf.mysqlPort, sconf.mysqlDatabase)
	if mysqlAutoCommit {
		dsn += "&autocommit=true"
	}
	if sconf.mysqlCAPath != "" {
		dsn += "&tls=custom"
		rootCertPool := x509.NewCertPool()
		pem, err := ioutil.ReadFile(sconf.mysqlCAPath)
		if err != nil {
			return nil, err
		}
		if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
			return nil, UlyssesServer.ErrServerConfigurables
		}
		if sconf.mysqlKeyPath != "" && sconf.mysqlCertPath != "" {
			// Both Key and Cert are set. Go with customer cert.
			clientCert := make([]tls.Certificate, 0, 1)
			certs, err := tls.LoadX509KeyPair(sconf.mysqlCertPath, sconf.mysqlKeyPath)
			if err != nil {
				return nil, err
			}
			clientCert = append(clientCert, certs)
			mysql.RegisterTLSConfig("custom", &tls.Config{
				// ServerName: "example.com",
				RootCAs:      rootCertPool,
				Certificates: clientCert,
			})
		} else if sconf.mysqlKeyPath == "" && sconf.mysqlCertPath == "" {
			// Neither Key or Cert is set. Proceed without customer cert.
			mysql.RegisterTLSConfig("custom", &tls.Config{
				// ServerName: "example.com",
				RootCAs: rootCertPool,
			})
		} else {
			// one of Key or Cert is set but not both, which is ILLEGAL.
			return nil, UlyssesServer.ErrServerConfigurables
		}
	}

	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, err
	}

	if connected, err := dbIsConnected(db); !connected {
		return nil, err
	}

	return db, nil
}

func initDB(sconf mysqlConf, hard bool) error {
	db, err := connectDB(sconf)
	if err != nil {
		return err
	}
	defer db.Close()

	if hard {
		stmtCreateDrop, err := db.Prepare(trojanDropTableQuery)
		if err != nil {
			return err
		}
		defer stmtCreateDrop.Close()

		_, err = stmtCreateDrop.Exec()
		if err != nil {
			return err
		}
	}

	stmtCreateTbl, err := db.Prepare(trojanCreateTableQuery)
	if err != nil {
		return err
	}
	defer stmtCreateTbl.Close()

	_, err = stmtCreateTbl.Exec()

	return err
}

// newTrojanAccounts creates accounts according to aconfs passed in.
// Callee must check for aconfs' validity.
// Passing in bad aconfs will result in crashing/paniking.
// func newTrojanAccounts(db *sql.DB, aconfs []UlyssesServer.AccountConfigurables, bypassLivenessCheck bool) (accid []int, err error) {
func newTrojanAccounts(db *sql.DB, aconfs []UlyssesServer.AccountConfigurables) (accid []int, err error) {
	var dbEngineInsertResultSupport int8 = dbEngineInsertResultUnknown
	accid = make([]int, 0)

	// // Caller must be checking liveness or handling potential errors if bypassing liveness check.
	// // Otherwise, check for liveness.
	// if !bypassLivenessCheck {
	// 	if connected, err := dbIsConnected(db); !connected {
	// 		return accid, err
	// 	}
	// }

	stmtCheckUser, err := db.Prepare(`SELECT id FROM ` + trojanTableName + ` WHERE username = ? AND password = ?`)
	if err != nil {
		return accid, err
	}
	defer stmtCheckUser.Close()

	stmtInsertUser, err := db.Prepare(`INSERT INTO ` + trojanTableName + ` (username, password, quota) VALUES( ?, ?, ? )`)
	if err != nil {
		return accid, err
	}
	defer stmtInsertUser.Close()

	for _, aconf := range aconfs {
		quota, err := strconv.ParseInt(aconf["quota"], 10, 64)
		if err != nil {
			return accid, err
		}
		result, err := stmtInsertUser.Exec(aconf["username"], aconf["password"], int(quota))
		if err != nil {
			return accid, err
		} else {
			var insertedId int
			switch dbEngineInsertResultSupport {
			case dbEngineInsertResultSupported:
				// When this is the case, use LastInsertId() will suffice which saves time.
				lastId, err := result.LastInsertId()
				if err != nil {
					return accid, err
				}
				accid = append(accid, int(lastId))
			case dbEngineInsertResultUnsupported:
				// Otherwise we need to execute the stmtCheckUser to get the ID
				err = stmtCheckUser.QueryRow(aconf["username"], aconf["password"]).Scan(&insertedId)

				if err != nil {
					// Too bad, we can't query even the first one.
					return accid, err
				}

				accid = append(accid, insertedId)
			default:
				// Check if it is supported?
				lastId, err := result.LastInsertId()
				if err != nil || lastId == 0 {
					// Apparently, not supported
					dbEngineInsertResultSupport = dbEngineInsertResultUnsupported

					err = stmtCheckUser.QueryRow(aconf["username"], aconf["password"]).Scan(&insertedId)

					if err != nil {
						// Too bad, we can't query even the first one.
						return accid, err
					}

					accid = append(accid, insertedId)
				} else {
					dbEngineInsertResultSupport = dbEngineInsertResultSupported
					accid = append(accid, int(lastId))
				}
			}
		}
	}

	return accid, nil
}

func updateTrojanAccounts(db *sql.DB, accID []int, aconfs []UlyssesServer.AccountConfigurables) (successAccID []int, err error) {
	// TODO: Finish this function
	return successAccID, err
}

func deleteTrojanAccounts(db *sql.DB, accID []int) (successAccID []int, err error) {
	// TODO: Finish this function
	return successAccID, err
}

func getCredentialTrojanAccounts(db *sql.DB, accID []int) (credentials []Credential, err error) {
	// TODO: Finish this function
	return credentials, err
}

func getUsageTrojanAccounts(db *sql.DB, accID []int) (usage []Usage, err error) {
	// TODO: Finish this function
	return usage, err
}
