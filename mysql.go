package trojan

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io/ioutil"

	UlyssesServer "github.com/TunnelWork/Ulysses/src/server"
	"github.com/go-sql-driver/mysql"
	// _ "github.com/go-sql-driver/mysql"
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
		);
	`
)

func conn(sconf mysqlConf) (*sql.DB, error) {
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

	err = db.Ping()
	if err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
}

func initDB(sconf mysqlConf, hard bool) error {
	db, err := conn(sconf)
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

func insert(tbl string) {

}
