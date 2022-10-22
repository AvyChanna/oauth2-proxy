package basic

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/watcher"
	"golang.org/x/crypto/argon2"
)

type userPassword struct {
	hash    []byte
	salt    []byte
	HashB64 string `json:"hash"`
	SaltB64 string `json:"salt"`
}

type params struct {
	saltLength uint32
	time       uint32
	memory     uint32
	threads    uint8
	keyLength  uint32
}

type userCfg struct {
	Pwd   userPassword
	Group string
}

type permsObj string

type groupCfg struct {
	Perms []permsObj
}

type jsonCfgMap struct {
	Users  map[string]userCfg
	Groups map[string]groupCfg
	rwm    sync.RWMutex
}

var argonParams = &params{
	saltLength: 16,
	time:       3,
	memory:     64 * 1024,
	threads:    4,
	keyLength:  32,
}

func NewJSONCfgValidator(path string) (Validator, error) {
	res := &jsonCfgMap{}
	if err := res.loadJSONCfgFile(path); err != nil {
		return nil, fmt.Errorf("could not load jsonCfg file: %v", err)
	}

	if err := watcher.WatchFileForUpdates(path, nil, func() {
		err := res.loadJSONCfgFile(path)
		if err != nil {
			logger.Errorf("%v: no changes were applied to the current jsonCfg map", err)
		}
	}); err != nil {
		return nil, fmt.Errorf("could not watch jsonCfg file: %v", err)
	}
	return res, nil
}

func (h *jsonCfgMap) loadJSONCfgFile(filename string) error {
	content, err := os.ReadFile(filename) // #nosec G304
	if err != nil {
		return fmt.Errorf("could not open jsonCfg file: %v", err)
	}
	rr := &jsonCfgMap{}
	if err := json.Unmarshal(content, &rr); err != nil {
		return fmt.Errorf("error while JSON Unmarshal: %v", err)
	}

	if err := processJSONCfgData(rr); err != nil {
		return err
	}

	h.rwm.Lock()
	h.Users = rr.Users
	h.Groups = rr.Groups
	h.rwm.Unlock()

	return nil
}

func processJSONCfgData(rr *jsonCfgMap) error {
	if len(rr.Users) == 0 {
		return errors.New("no user defined in JsonCfg")
	}

	if len(rr.Groups) == 0 {
		return errors.New("no group defined in JsonCfg")
	}

	for _, usr := range rr.Users {
		grp := usr.Group
		if _, exists := rr.Groups[grp]; !exists {
			return fmt.Errorf("group %s for user %s is not defined in JsonCfg", grp, usr)
		}

		decodedHash, err := base64.StdEncoding.DecodeString(usr.Pwd.HashB64)
		if err != nil {
			return fmt.Errorf("hash decode error for user %s in JsonCfg", usr)
		}
		usr.Pwd.hash = decodedHash
		// usr.Pwd.HashB64 = ""

		decodedSalt, err := base64.StdEncoding.DecodeString(usr.Pwd.SaltB64)
		if err != nil {
			return fmt.Errorf("salt decode error for user %s in JsonCfg", usr)
		}
		usr.Pwd.salt = decodedSalt
		// usr.Pwd.SaltB64 = ""
	}

	return nil
}

func (h *jsonCfgMap) Validate(user string, password string, req *http.Request) bool {
	userData, exists := h.Users[user]
	if !exists {
		return false
	}
	passwordHash := argon2.IDKey(
		[]byte(password),
		userData.Pwd.salt,
		argonParams.time,
		argonParams.memory,
		argonParams.threads,
		argonParams.keyLength,
	)

	passAtZero := 2 // Authn + Authz
	passAtZero -= subtle.ConstantTimeCompare(passwordHash, userData.Pwd.hash)

	group := userData.Group
	groupData, exists := h.Groups[group]
	if !exists {
		logger.Errorf("group %s not found for user %s", group, user)
		return false
	}

	for _, perm := range groupData.Perms {
		fmt.Printf("%s\n", perm)
		// TODO: match perms
	}
	return passAtZero == 0
}
