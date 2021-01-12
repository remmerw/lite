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

	opts := badger.DefaultOptions("")

	// This is to optimize the database on close so it can be opened
	// read-only and efficiently queried. We don't do that and hanging on
	// stop isn't nice.
	opts = opts.WithCompactL0OnClose(false)

	opts = opts.WithValueLogLoadingMode(options.FileIO)
	opts = opts.WithTableLoadingMode(options.FileIO)
	opts = opts.WithSyncWrites(true)
	opts = opts.WithValueThreshold(1024)
	opts = opts.WithValueLogFileSize(128 << 20) // 128 MB value log file
	opts = opts.WithMaxCacheSize(8 << 20)
	opts = opts.WithMaxTableSize(8 << 20)
	opts = opts.WithKeepL0InMemory(false)

	return NewDatastore(p, opts)
}
