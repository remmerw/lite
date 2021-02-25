package lite

import (
	"context"
	blocks "github.com/ipfs/go-block-format"
	cid "github.com/ipfs/go-cid"
	bstore "github.com/ipfs/go-ipfs-blockstore"
	dshelp "github.com/ipfs/go-ipfs-ds-help"
)

var _ bstore.Blockstore = (*blockstore)(nil)

func NewBlockstore(listener Listener) bstore.Blockstore {
	return &blockstore{
		Listener: listener,
	}
}

type blockstore struct {
	Listener Listener
	rehash   bool
}

func (bs *blockstore) HashOnRead(enabled bool) {
	bs.rehash = enabled
}

func (bs *blockstore) Get(k cid.Cid) (blocks.Block, error) {
	if !k.Defined() {
		bs.Listener.Error("undefined cid in blockstore")
		return nil, bstore.ErrNotFound
	}

	bdata := bs.Listener.BlockGet(dshelp.CidToDsKey(k).String())
	if bdata == nil {
		return nil, bstore.ErrNotFound
	}
	if bs.rehash {
		rbcid, err := k.Prefix().Sum(bdata)
		if err != nil {
			return nil, err
		}

		if !rbcid.Equals(k) {
			return nil, bstore.ErrHashMismatch
		}

		return blocks.NewBlockWithCid(bdata, rbcid)
	}
	return blocks.NewBlockWithCid(bdata, k)
}

func (bs *blockstore) Put(block blocks.Block) error {
	k := dshelp.CidToDsKey(block.Cid())

	// Has is cheaper than Put, so see if we already have it
	exists := bs.Listener.BlockHas(k.String())
	if exists {
		return nil // already stored.
	}
	bs.Listener.BlockPut(k.String(), block.RawData())
	return nil
}

func (bs *blockstore) PutMany(blocks []blocks.Block) error {

	for _, b := range blocks {
		err := bs.Put(b)
		if err != nil {
			return err
		}
	}
	return nil
}

func (bs *blockstore) Has(k cid.Cid) (bool, error) {
	return bs.Listener.BlockHas(dshelp.CidToDsKey(k).String()), nil
}

func (bs *blockstore) GetSize(k cid.Cid) (int, error) {
	size := bs.Listener.BlockSize(dshelp.CidToDsKey(k).String())
	if size < 0 {
		return -1, bstore.ErrNotFound
	}
	return size, nil
}

func (bs *blockstore) DeleteBlock(k cid.Cid) error {
	bs.Listener.BlockDelete(dshelp.CidToDsKey(k).String())
	return nil
}

// AllKeysChan runs a query for keys from the blockstore.
// this is very simplistic, in the future, take dsq.Query as a param?
//
// AllKeysChan respects context.
func (bs *blockstore) AllKeysChan(ctx context.Context) (<-chan cid.Cid, error) {
	return nil, nil
}
