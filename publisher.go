package lite

import (
	"context"

	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/ipfs/go-ipns"
	pb "github.com/ipfs/go-ipns/pb"
	"github.com/ipfs/go-path"
	ci "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/routing"
)

type PublisherClose interface {
	Close() bool
}

func (n *Node) PublishName(p string, close PublisherClose, sequence int) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func(stream PublisherClose) {
		for {
			if ctx.Err() != nil {
				break
			}
			if stream.Close() {
				cancel()
				break
			}
			time.Sleep(time.Millisecond * 500)
		}
	}(close)

	parsePath, err := path.ParsePath(p)
	if err != nil {
		return err
	}

	pkey, err := DecodePrivateKey(n.PrivateKey)
	if err != nil {
		return err
	}

	return PublishWithEOL(ctx, n.Routing,
		pkey, parsePath, time.Now().Add(DefaultRecordEOL), sequence)

}

const DefaultRecordEOL = 24 * time.Hour

func CreateRecord(k ci.PrivKey, value path.Path, eol time.Time, seq int) (*pb.IpnsEntry, error) {

	// Create record
	entry, err := ipns.Create(k, []byte(value), uint64(seq), eol)
	if err != nil {
		return nil, err
	}

	return entry, nil
}

// PublishWithEOL is a temporary stand in for the ipns records implementation
// see here for more details: https://github.com/ipfs/specs/tree/master/records
func PublishWithEOL(ctx context.Context, routing routing.ValueStore,
	k ci.PrivKey, value path.Path, eol time.Time, sequence int) error {
	record, err := CreateRecord(k, value, eol, sequence)
	if err != nil {
		return err
	}

	return PutRecordToRouting(ctx, routing, k.GetPublic(), record)
}

func PutRecordToRouting(ctx context.Context, r routing.ValueStore, k ci.PubKey, entry *pb.IpnsEntry) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errs := make(chan error, 1)

	if err := ipns.EmbedPublicKey(k, entry); err != nil {
		return err
	}

	id, err := peer.IDFromPublicKey(k)
	if err != nil {
		return err
	}

	go func() {
		errs <- PublishEntry(ctx, r, ipns.RecordKey(id), entry)
	}()

	return waitOnErrChan(ctx, errs)
}

func waitOnErrChan(ctx context.Context, errs chan error) error {
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func PublishEntry(ctx context.Context, r routing.ValueStore, ipnskey string, rec *pb.IpnsEntry) error {
	data, err := proto.Marshal(rec)
	if err != nil {
		return err
	}

	// Store ipns entry at "/ipns/"+h(pubkey)
	return r.PutValue(ctx, ipnskey, data)
}
