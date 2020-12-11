package lite

import (
	"github.com/dgraph-io/badger/v2"
	"github.com/dgraph-io/badger/v2/options"
	"os"
	"path/filepath"
)

func Create(path string) (*Datastore, error) {
	p := "badgers"
	if !filepath.IsAbs(p) {
		p = filepath.Join(path, p)
	}

	err := os.MkdirAll(p, 0755)
	if err != nil {
		return nil, err
	}

	defopts := badger.LSMOnlyOptions("")

	// This is to optimize the database on close so it can be opened
	// read-only and efficiently queried. We don't do that and hanging on
	// stop isn't nice.
	defopts.CompactL0OnClose = false

	defopts.SyncWrites = true

	// Uses less memory, is no slower when writing, and is faster when
	// reading (in some tests).
	defopts.ValueLogLoadingMode = options.FileIO

	defopts.TableLoadingMode = options.FileIO

	return NewDatastore(p, defopts)
}
