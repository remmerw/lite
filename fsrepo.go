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

	defaultOptions := badger.DefaultOptions("")

	// This is to optimize the database on close so it can be opened
	// read-only and efficiently queried. We don't do that and hanging on
	// stop isn't nice.
	defaultOptions.CompactL0OnClose = false

	defaultOptions.SyncWrites = true
	defaultOptions.ValueThreshold = 1024

	// Uses less memory, is no slower when writing, and is faster when
	// reading (in some tests).
	defaultOptions.ValueLogLoadingMode = options.FileIO

	defaultOptions.TableLoadingMode = options.FileIO

	return NewDatastore(p, defaultOptions)
}
