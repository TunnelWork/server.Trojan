package ulyssestrojan

import (
	"sync"

	UlyssesServer "github.com/TunnelWork/Ulysses/src/server"
)

type ServerRegistrar struct {
}

// NewServer creates a new Server struct by saving ServerConfigurables into Server struct
// then initialize a new RWMutex.
func (sr *ServerRegistrar) NewServer(sconf UlyssesServer.ServerConfigurables) (UlyssesServer.Server, error) {
	mysqlConf, err := parseServerConf(sconf)
	if err != nil {
		return &Server{}, err
	}

	return &Server{
		mysqlConf: mysqlConf,
		lock:      sync.RWMutex{},
	}, nil
}

func registrarInit() {
	UlyssesServer.AddServerRegistrar("trojan", &ServerRegistrar{})
}
