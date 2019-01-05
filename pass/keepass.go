package pass

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tobischo/gokeepasslib"
)

type keepassStore struct {
	Database *gokeepasslib.Database
}

type keepassStoreConfig struct {
	DatabasePath string `json:"db"`
	KeyPath      string `json:"key"`
}

var defaultConfigDir = filepath.Join(".browserkeepass", "config")

// NewKeepassStore creates a new keePass store from with the provided defaults
func NewKeepassStore(stores []StoreDefinition, useFuzzy bool) (Store, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}

	configPath := filepath.Join(usr.HomeDir, defaultConfigDir)
	if len(stores) == 1 {
		configPath = stores[0].Path
	}

	configContent, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	config := keepassStoreConfig{}
	json.Unmarshal(configContent, &config)

	db := gokeepasslib.NewDatabase()
	db.Credentials, err = gokeepasslib.NewKeyCredentials(config.KeyPath)
	if err != nil {
		return nil, err
	}

	passContent, err := os.Open(config.DatabasePath)
	if err != nil {
		return nil, err
	}

	err = gokeepasslib.NewDecoder(passContent).Decode(db)
	if err != nil {
		return nil, err
	}

	db.UnlockProtectedEntries()
	return &keepassStore{Database: db}, nil
}

func (store *keepassStore) Search(query string) ([]string, error) {
	return store.GlobSearch(query)
}

func (store *keepassStore) Open(item string) (io.ReadCloser, error) {
	parts := strings.SplitN(item, ":", 2)
	name := parts[0]
	if len(parts) > 1 {
		name = parts[1]
	}

	for _, e := range allKeepassEntries(*store.Database) {
		if name == e.GetTitle() {
			s := fmt.Sprintf("%s\n%s", e.GetContent("UserName"), e.GetPassword())
			return ioutil.NopCloser(bytes.NewBufferString(s)), nil
		}
	}
	return nil, fmt.Errorf("unable to open: %s in keepass store", name)
}

func (store *keepassStore) GlobSearch(query string) ([]string, error) {
	result := make([]string, 0)
	for _, e := range allKeepassEntries(*store.Database) {
		titleLower := strings.ToLower(e.GetTitle())
		queryLower := strings.ToLower(query)
		if strings.Contains(titleLower, queryLower) ||
			strings.Contains(e.GetContent("URL"), queryLower) {
			result = append(result, e.GetTitle())
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("unable to find: %s in keepass store", query)
	}

	sort.Strings(result)
	return result, nil
}

func allKeepassEntries(db gokeepasslib.Database) []gokeepasslib.Entry {
	return allEntries(db.Content.Root.Groups)
}

func allEntries(gs []gokeepasslib.Group) []gokeepasslib.Entry {
	entries := make([]gokeepasslib.Entry, 0)
	for _, g1 := range gs {
		entries = append(entries, g1.Entries...)
		entries = append(entries, allEntries(g1.Groups)...)
	}
	return entries
}
