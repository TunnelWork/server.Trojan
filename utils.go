package trojan

import (
	"strconv"

	UlyssesServer "github.com/TunnelWork/Ulysses/src/server"
)

func loadServerConf(sconf UlyssesServer.ServerConfigurables) (serverconf, error) {
	servconf := serverconf{}

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
