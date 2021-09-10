package trojan

import (
	"strconv"

	UlyssesServer "github.com/TunnelWork/Ulysses/src/server"
)

// internal struct supporting MySQL/MariaDB-based management
type mysqlConf struct {
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

func parseServerConf(sconf UlyssesServer.ServerConfigurables) (mysqlConf, error) {
	servconf := mysqlConf{}

	mysqlHost, ok := sconf["mysqlHost"]
	if !ok {
		return servconf, UlyssesServer.ErrServerConfigurables
	}
	servconf.mysqlHost = mysqlHost

	mysqlPort, ok := sconf["mysqlPort"]
	if !ok {
		return servconf, UlyssesServer.ErrServerConfigurables
	}
	mysqlPortu64, err := strconv.ParseUint(mysqlPort, 10, 16)
	if err != nil {
		return servconf, UlyssesServer.ErrServerConfigurables
	}
	servconf.mysqlPort = uint16(mysqlPortu64)

	mysqlDatabase, ok := sconf["mysqlDatabase"]
	if !ok {
		return servconf, UlyssesServer.ErrServerConfigurables
	}
	servconf.mysqlDatabase = mysqlDatabase

	mysqlUser, ok := sconf["mysqlUser"]
	if !ok {
		return servconf, UlyssesServer.ErrServerConfigurables
	}
	servconf.mysqlUser = mysqlUser

	mysqlPasswd, ok := sconf["mysqlPasswd"]
	if !ok {
		return servconf, UlyssesServer.ErrServerConfigurables
	}
	servconf.mysqlPasswd = mysqlPasswd

	mysqlKeyPath, ok := sconf["mysqlKeyPath"]
	// if !ok {
	// 	return &servconf, UlyssesServer.ErrServerConfigurables
	// }
	if ok {
		servconf.mysqlKeyPath = mysqlKeyPath
	}

	mysqlCertPath, ok := sconf["mysqlCertPath"]
	// if !ok {
	// 	return &servconf, UlyssesServer.ErrServerConfigurables
	// }
	if ok {
		servconf.mysqlCertPath = mysqlCertPath
	}

	mysqlCAPath, ok := sconf["mysqlCAPath"]
	// if !ok {
	// 	return &servconf, UlyssesServer.ErrServerConfigurables
	// }
	if ok {
		servconf.mysqlCAPath = mysqlCAPath
	}

	return servconf, nil
}

type serverOperator uint8

const (
	ADD serverOperator = iota
	UPDATE
)

func isValidTrojanConf(aconfs []UlyssesServer.AccountConfigurables, op serverOperator) bool {
	if op == ADD {
		// To add new accounts, each AccountConfigurables must set username, password, quota.
		//
		for _, aconf := range aconfs {
			if _, ok := aconf["username"]; !ok {
				return false
			}
			if _, ok := aconf["password"]; !ok {
				return false
			}
			if _, ok := aconf["quota"]; !ok {
				return false
			}
		}
	}
	if op == UPDATE {
		// To run a batch update, make sure:
		// - every AccountConfigurables include all keys in the first AccountConfigurables.
		// - no unrecognized keys (i'm lazy)
		keysFromFirst := make([]string, 0)

		for key, _ := range aconfs[0] {
			switch key {
			case "username", "password", "quota", "download", "upload": // All recognized keys
				keysFromFirst = append(keysFromFirst, key)
			default:
				return false // unrecognized key
			}
		}

		for _, aconf := range aconfs[1:] {
			// Now loop through to check all keys
			for _, key := range keysFromFirst {
				if _, ok := aconf[key]; !ok {
					return false
				}
			}
		}
	}
	return true
}
