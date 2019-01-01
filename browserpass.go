package browserpass

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/browserpass/browserpass/pass"
	"github.com/browserpass/browserpass/protector"
	"github.com/gokyle/twofactor"
)

// Login represents a single pass login.
type Login struct {
	Username   string `json:"u"`
	Password   string `json:"p"`
	OTP        string `json:"digits"`
	OTPLabel   string `json:"label"`
	URL        string `json:"url"`
	AutoSubmit *bool  `json:"autoSubmit,omitempty"`
}

var endianness = binary.LittleEndian

//Use gpg or keepass
var useGpg = false

// Settings info for the browserpass program.
//
// The browser extension will look up settings in its localstorage and find
// which options have been selected by the user, and put them in a JSON object
// which is then passed along with the command over the native messaging api.

// Config defines the root config structure sent from the browser extension
type Config struct {
	// Manual searches use FuzzySearch if true, GlobSearch otherwise
	UseFuzzy     bool                   `json:"use_fuzzy_search"`
	CustomStores []pass.StoreDefinition `json:"customStores"`
}

// msg defines a message sent from a browser extension.
type msg struct {
	Settings Config `json:"settings"`
	Action   string `json:"action"`
	Domain   string `json:"domain"`
	Entry    string `json:"entry"`
}

func SendError(err error, stdout io.Writer) error {
	var buf bytes.Buffer
	if writeError := json.NewEncoder(&buf).Encode(err.Error()); writeError != nil {
		return err
	}
	if writeError := binary.Write(stdout, endianness, uint32(buf.Len())); writeError != nil {
		return err
	}
	buf.WriteTo(stdout)
	return err
}

// Run starts browserpass.
func Run(stdin io.Reader, stdout io.Writer) error {

	protector.Protect("stdio rpath proc exec getpw")
	for {
		// Get message length, 4 bytes
		var n uint32
		if err := binary.Read(stdin, endianness, &n); err == io.EOF {
			return nil
		} else if err != nil {
			return SendError(err, stdout)
		}

		// Get message body
		var data msg
		lr := &io.LimitedReader{R: stdin, N: int64(n)}
		if err := json.NewDecoder(lr).Decode(&data); err != nil {
			return SendError(err, stdout)
		}

		var s pass.Store
		var err error
		if useGpg {
			s, err = pass.NewDefaultStore(data.Settings.CustomStores, data.Settings.UseFuzzy)
		} else {
			s, err = pass.NewKeepassStore(data.Settings.CustomStores, data.Settings.UseFuzzy)
		}

		if err != nil {
			return SendError(err, stdout)
		}

		var resp interface{}
		switch data.Action {
		case "search":
			list, err := s.Search(data.Domain)
			if err != nil {
				return SendError(err, stdout)
			}
			resp = list
		case "match_domain":
			list, err := s.GlobSearch(data.Domain)
			if err != nil {
				return SendError(err, stdout)
			}
			resp = list
		case "get":
			rc, err := s.Open(data.Entry)
			if err != nil {
				return SendError(err, stdout)
			}
			defer rc.Close()
			login, err := readLoginGPG(rc)
			if err != nil {
				return SendError(err, stdout)
			}
			resp = login
		default:
			return SendError(errors.New("Invalid action"), stdout)
		}

		var b bytes.Buffer
		if err := json.NewEncoder(&b).Encode(resp); err != nil {
			return SendError(err, stdout)
		}

		if err := binary.Write(stdout, endianness, uint32(b.Len())); err != nil {
			return err
		}
		if _, err := b.WriteTo(stdout); err != nil {
			return err
		}
	}
}

func detectGPGBin() (string, error) {
	binPriorityList := []string{
		"gpg2", "/bin/gpg2", "/usr/bin/gpg2", "/usr/local/bin/gpg2",
		"gpg", "/bin/gpg", "/usr/bin/gpg", "/usr/local/bin/gpg",
	}

	binToUse := ""
	for _, bin := range binPriorityList {
		binCheck := exec.Command(bin, "--version")
		if err := binCheck.Run(); err == nil {
			binToUse = bin
			break
		}
	}

	if binToUse == "" {
		return "", errors.New("Unable to detect the location of gpg binary")
	}

	return binToUse, nil
}

// readLoginGPG reads a encrypted login from r using the system's GPG binary.
func readLoginGPG(r io.Reader) (*Login, error) {
	login, err := parseLogin(r)
	if err != nil {
		return nil, err
	}
	return login, err
}

func parseTotp(str string, l *Login) error {
	urlPattern := regexp.MustCompile("^otpauth.*$")
	ourl := urlPattern.FindString(str)

	if ourl == "" {
		tokenPattern := regexp.MustCompile("(?i)^totp(-secret)?:")
		token := tokenPattern.ReplaceAllString(str, "")
		if len(token) != len(str) {
			ourl = "otpauth://totp/?secret=" + strings.TrimSpace(token)
		}
	}
	if ourl != "" {
		o, label, err := twofactor.FromURL(ourl)
		if err != nil {
			return err
		}
		l.OTP = o.OTP()
		l.OTPLabel = label
	}

	return nil
}

// parseLogin parses a login and a password from a decrypted password file.
func parseLogin(r io.Reader) (*Login, error) {
	login := new(Login)

	scanner := bufio.NewScanner(r)
	lines := make([]string, 0)
	for scanner.Scan() {
		l := scanner.Text()
		if l != "" {
			lines = append(lines, l)
		}
	}

	if len(lines) >= 1 {
		login.Username = lines[0]

	}
	if len(lines) >= 2 {
		login.Password = lines[1]

	}
	return login, nil
}

// guessLogin tries to guess a username from an entry's name.
func guessUsername(name string) string {
	if strings.Count(filepath.ToSlash(name), "/") >= 1 {
		return filepath.Base(name)
	}
	return ""
}
