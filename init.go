package utrojan

import "github.com/TunnelWork/Ulysses.Lib/server"

func init() {
	server.RegisterServer("trojan", func( /*db *sql.DB, */ instanceID string, serverConfiguration interface{}) (server.ProvisioningServer, error) {
		return NewProvisioningServer(instanceID, serverConfiguration)
	})
}