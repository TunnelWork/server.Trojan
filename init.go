package utrojan

import "github.com/TunnelWork/Ulysses.Lib/server"

func init() {
	server.RegisterServer("utrojan", NewProvisioningServer)
}
