package pass

import (
	"fmt"
	"os"
	"testing"

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
	//entry := db.Content.Root.Groups[0].Groups[0].Entries[0]
	db.UnlockProtectedEntries()
	entries := allKeepassEntries(*db)

	for _, et := range entries {
		fmt.Println(et.GetTitle())
		fmt.Println(et.GetContent("URL"))
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
