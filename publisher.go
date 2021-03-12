package lite

import (
	"context"

	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/ipfs/go-ipns"
	"github.com/ipfs/go-path"
	"github.com/libp2p/go-libp2p-core/peer"
)

const DefaultRecordEOL = 24 * time.Hour

func (n *Node) PublishName(p string, close Closeable, sequence int) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func(stream Closeable) {
		for {
			if ctx.Err() != nil {
				break
			}
			if stream.Close() {
				cancel()
				break
			}
			time.Sleep(time.Duration(n.Responsive) * time.Millisecond)
		}
	}(close)

	value, err := path.ParsePath(p)
	if err != nil {
		return err
	}

	pkey, err := DecodePrivateKey(n.PrivateKey)
	if err != nil {
		return err
	}

	eol := time.Now().Add(DefaultRecordEOL)

	record, err := ipns.Create(pkey, []byte(value), uint64(sequence), eol)
	if err != nil {
		return err
	}

	pk := pkey.GetPublic()

	if err := ipns.EmbedPublicKey(pk, record); err != nil {
		return err
	}

	id, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return err
	}

	data, err := proto.Marshal(record)
	if err != nil {
		return err
	}

	// Store ipns entry at "/ipns/"+h(pubkey)
	rk := "/ipns/" + string(id)
	return n.Routing.PutValue(ctx, rk, data)

}
