package ulyssestrojan

import (
	"encoding/json"
	"fmt"
)

// server.Credential struct
type Credential struct {
	Id           uint   // Not needed for connection
	Username     string // Not needed for connection
	PasswdSHA224 string // Don't think it could be insightful
}

// ForClient() is not useful for trojan protocol, given that password stored on DB server is hashed.
func (c Credential) ForClient() (credential string) {
	return ""
}

func (c Credential) ForAdmin() (credential string) {
	b, err := json.Marshal(c)
	if err != nil {
		return fmt.Sprintf(`{"Error":"%s"}`, err.Error())
	}
	credential = string(b)
	return credential
}
