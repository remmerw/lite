package lite

import (
	blocks "github.com/ipfs/go-block-format"
	cid "github.com/ipfs/go-cid"
	bstore "github.com/ipfs/go-ipfs-blockstore"
	"github.com/ipfs/go-verifcid"
)

type VerifBS struct {
	bstore.Blockstore
	Listener Listener
}

func (bs *VerifBS) Put(b blocks.Block) error {
	if err := verifcid.ValidateCid(b.Cid()); err != nil {
		return err
	}
	bs.Listener.Leeching(len(b.RawData()))
	return bs.Blockstore.Put(b)
}

func (bs *VerifBS) PutMany(blks []blocks.Block) error {
	for _, b := range blks {
		if err := verifcid.ValidateCid(b.Cid()); err != nil {
			return err
		}
		bs.Listener.Leeching(len(b.RawData()))
	}
	return bs.Blockstore.PutMany(blks)
}

func (bs *VerifBS) Get(c cid.Cid) (blocks.Block, error) {
	if err := verifcid.ValidateCid(c); err != nil {
		return nil, err
	}

	data, err := bs.Blockstore.Get(c)
	if err == nil {
		bs.Listener.Seeding(len(data.RawData()))
	}
	return data, err
}
