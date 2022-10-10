package basic

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/watcher"
	"golang.org/x/crypto/argon2"
)

type userPassword struct {
	hash []byte
	salt []byte
}

type params struct {
	saltLength uint32
	time       uint32
	memory     uint32
	threads    uint8
	keyLength  uint32
}

type userCfg struct {
	pwd   userPassword
	group string
}

type groupCfg struct {
	perms []string
}

type jsonCfgMap struct {
	users  map[string]userCfg
	groups map[string]groupCfg
	rwm    sync.RWMutex
}

var argonParams = &params{
	saltLength: 16,
	time:       3,
	memory:     64 * 1024,
	threads:    4,
	keyLength:  32,
}

// NewHTPasswdValidator constructs an httpasswd based validator from the file
// at the path given.
func NewJsonCfgValidator(path string) (Validator, error) {
	res := &jsonCfgMap{
		users:  make(map[string]userCfg),
		groups: make(map[string]groupCfg),
	}
	if err := res.loadJsonCfgFile(path); err != nil {
		return nil, fmt.Errorf("could not load jsonCfg file: %v", err)
	}

	if err := watcher.WatchFileForUpdates(path, nil, func() {
		err := res.loadJsonCfgFile(path)
		if err != nil {
			logger.Errorf("%v: no changes were made to the current jsonCfg map", err)
		}
	}); err != nil {
		return nil, fmt.Errorf("could not watch jsonCfg file: %v", err)
	}
	return res, nil
}

func getDummyUser() userCfg {
	// TODO: remove this
	dummyHash, _ := hex.DecodeString("1a642bb57085acfce19c46b85d6d51a62b6f31a13e31916dc2cc002b54341407")
	return userCfg{
		pwd: userPassword{
			hash: dummyHash,
			salt: []byte("0123456789abcdef"),
		},
	}
}
func (h *jsonCfgMap) loadJsonCfgFile(path string) error {
	// TODO: implement this. Currently dummy code for testing
	newJsonCfgMap := &jsonCfgMap{
		users:  make(map[string]userCfg),
		groups: make(map[string]groupCfg),
	}
	newJsonCfgMap.users["h2g2"] = getDummyUser()
	return nil
}

// Validate checks a users password against the htpasswd entries
func (h *jsonCfgMap) Validate(user string, password string, req *http.Request) bool {
	userData, exists := h.users[user]
	if !exists {
		return false
	}
	passwordHash := argon2.IDKey(
		[]byte(password),
		userData.pwd.salt,
		argonParams.time,
		argonParams.memory,
		argonParams.threads,
		argonParams.keyLength,
	)

	passAtZero := 2 // Authn + Authz
	passAtZero -= subtle.ConstantTimeCompare(passwordHash, userData.pwd.hash)
	// TODO: Authz
	return passAtZero == 0
}
