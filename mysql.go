package trojan

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io/ioutil"
	"strings"

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
func newTrojanAccounts(db *sql.DB, aconfs []*trojanAccountConfigurables) (accid []int, err error) {
	var dbEngineInsertResultSupport int8 = dbEngineInsertResultUnknown
	accid = []int{}

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
		result, err := stmtInsertUser.Exec(aconf.username, aconf.password, aconf.quota)
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
				err = stmtCheckUser.QueryRow(aconf.username, aconf.password).Scan(&insertedId)

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

					err = stmtCheckUser.QueryRow(aconf.username, aconf.password).Scan(&insertedId)

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

// TODO: Finish this func
func updateTrojanAccounts(db *sql.DB, accID []int, aconfs []*trojanAccountConfigurables) (successAccID []int, err error) {
	// Check the first aconf to see what keys are needed.
	successAccID = []int{}
	keysSlices := []string{}
	questionMarkSlices := []string{}

	if aconfs[0].username != nil {
		keysSlices = append(keysSlices, "username")
		questionMarkSlices = append(questionMarkSlices, "?")
	}
	if aconfs[0].password != nil {
		keysSlices = append(keysSlices, "password")
		questionMarkSlices = append(questionMarkSlices, "?")
	}
	if aconfs[0].quota != nil {
		keysSlices = append(keysSlices, "quota")
		questionMarkSlices = append(questionMarkSlices, "?")
	}
	if aconfs[0].download != nil {
		keysSlices = append(keysSlices, "download")
		questionMarkSlices = append(questionMarkSlices, "?")
	}
	if aconfs[0].upload != nil {
		keysSlices = append(keysSlices, "upload")
		questionMarkSlices = append(questionMarkSlices, "?")
	}
	keysListString := strings.Join(keysSlices[:], ", ")                 // "username, password, quota, download, upload"
	questionMarkListString := strings.Join(questionMarkSlices[:], ", ") // "?, ?, ?, ?, ?"

	stmtUpdateUser, err := db.Prepare(`UPDATE ` + trojanTableName + ` ( ` + keysListString + ` )` + `VALUES( ` + questionMarkListString + ` )`)
	if err != nil {
		return successAccID, err
	}
	defer stmtUpdateUser.Close()

	for _, aconf := range aconfs {
		// Construct interface{} list
		var args []interface{}
		if aconf.username != nil {
			args = append(args, aconf.username)
		}
		if aconf.password != nil {
			args = append(args, aconf.password)
		}
		if aconf.quota != nil {
			args = append(args, aconf.quota)
		}
		if aconf.download != nil {
			args = append(args, aconf.download)
		}
		if aconf.upload != nil {
			args = append(args, aconf.upload)
		}

		_, err := stmtUpdateUser.Exec(args...)
		if err != nil {
			return successAccID, err
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
				err = stmtCheckUser.QueryRow(aconf.username, aconf.password).Scan(&insertedId)

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

					err = stmtCheckUser.QueryRow(aconf.username, aconf.password).Scan(&insertedId)

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
