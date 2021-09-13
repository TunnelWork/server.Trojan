// +build mysqlstaging

package ulyssestrojan

import "testing"

// mysqlstaging credentials

func TestConnWithNoCert(t *testing.T) {
	var mysqlConf = serverconf{
		mysqlHost:     "127.0.0.1",
		mysqlPort:     3306,
		mysqlDatabase: "tmp_staging",
		mysqlUser:     "staging",
		mysqlPasswd:   "staging",
	}

	if _, err := conn(mysqlConf); err != nil {
		t.Errorf("%s", err)
	}
}

func TestConnWithCert(t *testing.T) {
	var mysqlConf = serverconf{
		mysqlHost:     "mysql-cert-staging.local",
		mysqlPort:     3443,
		mysqlDatabase: "tmp_staging",
		mysqlUser:     "staging",
		mysqlPasswd:   "staging",
		mysqlCAPath:   "/home/staging/ca.pem",
		mysqlKeyPath:  "/home/staging/key.pem",
		mysqlCertPath: "/home/staging/cert.pem",
	}

	if _, err := conn(mysqlConf); err != nil {
		t.Errorf("%s", err)
	}
}
