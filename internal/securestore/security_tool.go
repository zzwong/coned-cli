package securestore

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// securityToolKeys keeps sealedDriver keys in the Keychain through Apple's
// security tool. Items it creates carry the apple-tool partition and trust
// only that tool, so any coned build can use them through it and other
// applications still cannot read them directly.
type securityToolKeys struct {
	tool string
}

const (
	keyAccount = "v1"
	keyLength  = 32

	// security exits with the low byte of the OSStatus.
	securityExitNotFound       = 44 // errSecItemNotFound
	securityExitNotInteractive = 36 // errSecInteractionNotAllowed: locked, or needs approval
)

var errKeyTool = errors.New("keychain key tool failed")

func keyService(service string) string { return service + ".storage-key" }

func (k securityToolKeys) Key(service string, create bool) ([]byte, error) {
	key, err := k.read(service)
	if !create || !errors.Is(err, ErrNotFound) {
		return key, err
	}
	fresh := make([]byte, keyLength)
	if _, err := rand.Read(fresh); err != nil {
		return nil, err
	}
	if err := k.add(service, fresh); err != nil {
		return nil, err
	}
	// Another process may have added a key first. Reading back makes the
	// stored key the one every writer uses.
	return k.read(service)
}

func (k securityToolKeys) read(service string) ([]byte, error) {
	out, err := exec.Command(k.tool, "find-generic-password", "-s", keyService(service), "-a", keyAccount, "-w").Output()
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit) && exit.ExitCode() == securityExitNotFound:
		return nil, ErrNotFound
	case errors.As(err, &exit) && exit.ExitCode() == securityExitNotInteractive:
		return nil, ErrAccessDenied
	case err != nil:
		return nil, errKeyTool
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil || len(key) != keyLength {
		return nil, errInvalidKeyringValue
	}
	return key, nil
}

// add passes the key on standard input in interactive mode, so it never
// appears in a process listing.
func (k securityToolKeys) add(service string, key []byte) error {
	cmd := exec.Command(k.tool, "-i")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("add-generic-password -s %s -a %s -w %s\n",
		keyService(service), keyAccount, base64.StdEncoding.EncodeToString(key)))
	// Interactive mode exits 0 even when a command fails; the caller reads
	// the key back to learn whether it was stored.
	if err := cmd.Run(); err != nil {
		return errKeyTool
	}
	return nil
}
