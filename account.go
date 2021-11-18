package utrojan

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/TunnelWork/Ulysses.Lib/security"
	"github.com/TunnelWork/Ulysses.Lib/server"
)

type Account struct {
	credentials *Credentials
	resources   []*server.Resource
}

func (a *Account) Credentials() (server.Credentials, error) {
	return a.credentials, nil
}

func (a *Account) Resources() ([]*server.Resource, error) {
	return []*server.Resource{}, nil
}

type Credentials struct {
	productSN         uint64
	passwordSHA224    string
	passwordDecrypted string
	timeLastRefresh   time.Time
	remoteAddr        string // inherited from ServerInfo.ServerAddress
	remotePort        uint16 // inherited from ServerInfo.ServerPort (default 443?)
}

func (c *Credentials) Customer() (credentials []*server.Credential) {
	return []*server.Credential{
		{
			CredentialName:  "account_type",
			CredentialValue: "trojan",
		},
		{
			CredentialName:  "product_serial_number",
			CredentialValue: c.productSN,
		},
		{
			CredentialName:  "password_decrypted",
			CredentialValue: c.passwordDecrypted,
		},
		{
			CredentialName:  "time_last_refresh",
			CredentialValue: c.timeLastRefresh.Format("2006-01-02"),
		},
		{
			CredentialName:  "remote_addr",
			CredentialValue: c.remoteAddr,
		},
		{
			CredentialName:  "remote_port",
			CredentialValue: c.remotePort,
		},
		{
			CredentialName:  "trojan_url",
			CredentialValue: fmt.Sprintf("trojan://%s@%s:%d", c.passwordDecrypted, c.remoteAddr, c.remotePort),
		},
	}
}

func (c *Credentials) Admin() (credentials []*server.Credential) {
	return []*server.Credential{
		{
			CredentialName:  "account_type",
			CredentialValue: "trojan",
		},
		{
			CredentialName:  "product_serial_number",
			CredentialValue: c.productSN,
		},
		{
			CredentialName:  "password_SHA224",
			CredentialValue: c.passwordSHA224,
		},
		{
			CredentialName:  "time_last_refresh",
			CredentialValue: c.timeLastRefresh.Format("2006-01-02"),
		},
		{
			CredentialName:  "remote_addr",
			CredentialValue: c.remoteAddr,
		},
		{
			CredentialName:  "remote_port",
			CredentialValue: c.remotePort,
		},
	}
}

type AccountConfiguration struct {
	Password string  `json:"password"`
	Quota    float64 `json:"quota"` // in GB
}

func ParseAccountConfiguration(config interface{}) (ac AccountConfiguration, err error) {
	switch value := config.(type) {
	case map[string]interface{}:
		jsonString, _ := json.Marshal(value)
		err = json.Unmarshal(jsonString, &ac)
	case string:
		err = json.Unmarshal([]byte(value), &ac)
	case AccountConfiguration:
		ac = value
	default:
		err = server.ErrAccountConfigurables
	}
	if err == nil {
		// Validate password length. Longer password is less vulnerable to brute force attacks.
		if len(ac.Password) < 8 { // too weak
			err = errors.New("utrojan: bad account password")
		}
	}
	return ac, err
}

// PasswordEncrypted() returns the password encrypted by the managed security module.
func (ac AccountConfiguration) PasswordEncrypted() string {
	return security.EncryptPassword(ac.Password)
}

// PasswordSHA224() calculates the SHA224 hash of the password, which is used by trojan
func (ac AccountConfiguration) PasswordSHA224() string {
	sum224 := sha256.Sum224([]byte(ac.Password))
	return base64.StdEncoding.EncodeToString(sum224[:])
}

// Quota() converts the quota from GB to bytes.
func (ac AccountConfiguration) QuotaBytes() int64 {
	if ac.Quota > 0 {
		return int64(ac.Quota * 1024 * 1024 * 1024) // in bytes
	} else if ac.Quota == 0 {
		return 0
	} else {
		return -1
	}
}
