package pass

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/tobischo/gokeepasslib"
)

func TestOpenKeepass(t *testing.T) {
	passFile, _ := os.Open("keepass.kdbx")

	db := gokeepasslib.NewDatabase()
	var err error
	db.Credentials, err = gokeepasslib.NewKeyCredentials("keepass.key")
	if err != nil {
		t.Fatal(err)
	}

	err = gokeepasslib.NewDecoder(passFile).Decode(db)
	if err != nil {
		t.Fatal(err)
	}

	db.UnlockProtectedEntries()
	entries := allKeepassEntries(*db)

	for _, et := range entries {
		assert.True(t, et.GetTitle() != "")
		/*
			assert.True(t, et.GetContent("UserName") != "")
			assert.True(t, et.GetContent("URL") != "")
		*/
	}
}

func TestOpenConfig(t *testing.T) {
	st := []StoreDefinition{
		StoreDefinition{
			Path: "keepass.config",
		},
	}
	store, err := NewKeepassStore(st, true)
	if err != nil {
		t.Fatalf(err.Error())
	}

	if store == nil {
		t.Error("could not open")
	}

}
func TestGetLogin(t *testing.T) {
	st := []StoreDefinition{
		StoreDefinition{
			Path: "keepass.config",
		},
	}
	store, err := NewKeepassStore(st, true)
	if err != nil {
		t.Fatalf(err.Error())
	}

	ss, err := store.Open("one:sample")
	assert.NoError(t, err)
	b, _ := ioutil.ReadAll(ss)
	assert.Equal(t, "uuser\nesteban", string(b))

	ss, err = store.Open("sample")
	assert.NoError(t, err)
	b, _ = ioutil.ReadAll(ss)
	assert.Equal(t, "uuser\nesteban", string(b))
}
