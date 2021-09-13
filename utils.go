package ulyssestrojan

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

type trojanAccountConfigurables struct {
	username interface{}
	password interface{}
	quota    interface{}
	download interface{}
	upload   interface{}
}

func parseTrojanAccountConfigurables(aconfs []UlyssesServer.AccountConfigurables, op serverOperator) ([]*trojanAccountConfigurables, error) {
	var newArrTrojanAccountConfigurables = []*trojanAccountConfigurables{}
	if op == ADD {
		// To add new accounts, each AccountConfigurables must set username, password, quota.
		//
		for _, aconf := range aconfs {
			var newTrojanAccountConfigurables = trojanAccountConfigurables{}

			if username, ok := aconf["username"]; !ok {
				return nil, UlyssesServer.ErrAccountConfigurables
			} else {
				newTrojanAccountConfigurables.username = username
			}
			if password, ok := aconf["password"]; !ok {
				return nil, UlyssesServer.ErrAccountConfigurables
			} else {
				newTrojanAccountConfigurables.password = password
			}
			if quota, ok := aconf["quota"]; !ok {
				return nil, UlyssesServer.ErrAccountConfigurables
			} else {
				// quota needs to be converted from string to int
				quota64, err := strconv.ParseInt(quota, 10, 64)
				if err != nil {
					return nil, UlyssesServer.ErrAccountConfigurables
				}
				parsedQuota := int(quota64)
				newTrojanAccountConfigurables.quota = parsedQuota
			}

			newArrTrojanAccountConfigurables = append(newArrTrojanAccountConfigurables, &newTrojanAccountConfigurables)
		}
	}
	if op == UPDATE {
		// To run a batch update, make sure:
		// - every AccountConfigurables include all keys in the first AccountConfigurables.
		// - [IGNORE THIS] no unrecognized keys (i'm lazy)
		keysFromFirst := make([]string, 0)

		keycnt := 0
		for key := range aconfs[0] {
			switch key {
			case "username", "password", "quota", "download", "upload": // All recognized keys
				keysFromFirst = append(keysFromFirst, key)
				keycnt += 1
				// default: // Ignore any key that can't be recognized
				// 	return nil, ErrInvalidTrojanConfigurables
			}
		}

		if keycnt == 0 {
			return nil, UlyssesServer.ErrAccountConfigurables // Reject empty updates
		}

		for _, aconf := range aconfs {
			var newTrojanAccountConfigurables = trojanAccountConfigurables{}

			// Now loop through to check all keys
			for _, key := range keysFromFirst {
				if val, ok := aconf[key]; !ok {
					// If an AccountConfigurables doesn't contain all VALID keys from the first one, fail.
					return nil, UlyssesServer.ErrAccountConfigurables
				} else {
					switch key {
					case "username":
						newTrojanAccountConfigurables.username = val
					case "password":
						newTrojanAccountConfigurables.password = val
					case "quota":
						// quota needs to be converted from string to int
						quota64, err := strconv.ParseInt(val, 10, 64)
						if err != nil {
							return nil, UlyssesServer.ErrAccountConfigurables
						}
						parsedQuota := int(quota64)
						newTrojanAccountConfigurables.quota = parsedQuota
					case "download":
						// download needs to be converted from string to uint
						download64, err := strconv.ParseUint(val, 10, 64)
						if err != nil {
							return nil, UlyssesServer.ErrAccountConfigurables
						}
						parsedDownload := uint(download64)
						newTrojanAccountConfigurables.download = parsedDownload
					case "upload":
						// upload needs to be converted from string to uint
						upload64, err := strconv.ParseUint(val, 10, 64)
						if err != nil {
							return nil, UlyssesServer.ErrAccountConfigurables
						}
						parsedUpload := uint(upload64)
						newTrojanAccountConfigurables.upload = parsedUpload
					}
					newArrTrojanAccountConfigurables = append(newArrTrojanAccountConfigurables, &newTrojanAccountConfigurables)
				}
			}
		}
	}
	return newArrTrojanAccountConfigurables, nil
}
