package lite

import (
	"context"

	"time"

	"github.com/gogo/protobuf/proto"
	ds "github.com/ipfs/go-datastore"
	"github.com/ipfs/go-ipns"
	pb "github.com/ipfs/go-ipns/pb"
	"github.com/ipfs/go-path"
	ci "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/routing"
	"github.com/whyrusleeping/base32"
)

type Sequence interface {
	Value(int64)
}
type PublisherClose interface {
	Close() bool
}

func (n *Node) PublishName(p string, close PublisherClose, sequence Sequence) error {
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

	return PublishWithEOL(ctx, n.Routing, n.DataStore,
		pkey, parsePath, time.Now().Add(DefaultRecordEOL), sequence)

}

const DefaultRecordEOL = 24 * time.Hour

func IpnsDsKey(id peer.ID) ds.Key {
	return ds.NewKey("/ipns/" + base32.RawStdEncoding.EncodeToString([]byte(id)))
}

// GetPublished returns the record this node has published corresponding to the
// given peer ID.
//
// If `checkRouting` is true and we have no existing record, this method will
// check the routing system for any existing records.
func GetPublished(ctx context.Context, routing routing.ValueStore, datastore ds.Datastore, id peer.ID, checkRouting bool) (*pb.IpnsEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()

	value, err := datastore.Get(IpnsDsKey(id))
	switch err {
	case nil:
	case ds.ErrNotFound:
		if !checkRouting {
			return nil, nil
		}
		ipnskey := ipns.RecordKey(id)
		value, err = routing.GetValue(ctx, ipnskey)
		if err != nil {
			// Not found or other network issue. Can't really do
			// anything about this case.

			return nil, nil
		}
	default:
		return nil, err
	}
	e := new(pb.IpnsEntry)
	if err := proto.Unmarshal(value, e); err != nil {
		return nil, err
	}
	return e, nil
}

func UpdateRecord(ctx context.Context, routing routing.ValueStore, ds ds.Datastore,
	k ci.PrivKey, value path.Path, eol time.Time, sequence Sequence) (*pb.IpnsEntry, error) {
	id, err := peer.IDFromPrivateKey(k)
	if err != nil {
		return nil, err
	}

	// get previous records sequence number
	rec, err := GetPublished(ctx, routing, ds, id, false)
	if err != nil {
		return nil, err
	}

	seqno := rec.GetSequence() // returns 0 if rec is nil
	if rec != nil && value != path.Path(rec.GetValue()) {
		// Don't bother incrementing the sequence number unless the
		// value changes.
		seqno++

		sequence.Value(int64(seqno));
	}

	// Create record
	entry, err := ipns.Create(k, []byte(value), seqno, eol)
	if err != nil {
		return nil, err
	}

	// Set the TTL
	// TODO: Make this less hacky.
	ttl, ok := checkCtxTTL(ctx)
	if ok {
		entry.Ttl = proto.Uint64(uint64(ttl.Nanoseconds()))
	}

	data, err := proto.Marshal(entry)
	if err != nil {
		return nil, err
	}

	// Put the new record.
	key := IpnsDsKey(id)
	if err := ds.Put(key, data); err != nil {
		return nil, err
	}
	if err := ds.Sync(key); err != nil {
		return nil, err
	}
	return entry, nil
}

// PublishWithEOL is a temporary stand in for the ipns records implementation
// see here for more details: https://github.com/ipfs/specs/tree/master/records
func PublishWithEOL(ctx context.Context, routing routing.ValueStore, ds ds.Datastore,
	k ci.PrivKey, value path.Path, eol time.Time, sequence Sequence) error {
	record, err := UpdateRecord(ctx, routing, ds, k, value, eol, sequence)
	if err != nil {
		return err
	}

	return PutRecordToRouting(ctx, routing, k.GetPublic(), record)
}

// setting the TTL on published records is an experimental feature.
// as such, i'm using the context to wire it through to avoid changing too
// much code along the way.
func checkCtxTTL(ctx context.Context) (time.Duration, bool) {
	v := ctx.Value("ipns-publish-ttl")
	if v == nil {
		return 0, false
	}

	d, ok := v.(time.Duration)
	return d, ok
}

func PutRecordToRouting(ctx context.Context, r routing.ValueStore, k ci.PubKey, entry *pb.IpnsEntry) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errs := make(chan error, 2) // At most two errors (IPNS, and public key)

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

	// Publish the public key if a public key cannot be extracted from the ID
	// TODO: once v0.4.16 is widespread enough, we can stop doing this
	// and at that point we can even deprecate the /pk/ namespace in the dht
	//
	// NOTE: This check actually checks if the public key has been embedded
	// in the IPNS entry. This check is sufficient because we embed the
	// public key in the IPNS entry if it can't be extracted from the ID.
	if entry.PubKey != nil {
		go func() {
			errs <- PublishPublicKey(ctx, r, PkKeyForID(id), k)
		}()

		if err := waitOnErrChan(ctx, errs); err != nil {
			return err
		}
	}

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

func PublishPublicKey(ctx context.Context, r routing.ValueStore, k string, pubk ci.PubKey) error {

	pkbytes, err := pubk.Bytes()
	if err != nil {
		return err
	}

	// Store associated public key
	return r.PutValue(ctx, k, pkbytes)
}

func PublishEntry(ctx context.Context, r routing.ValueStore, ipnskey string, rec *pb.IpnsEntry) error {
	data, err := proto.Marshal(rec)
	if err != nil {
		return err
	}

	// Store ipns entry at "/ipns/"+h(pubkey)
	return r.PutValue(ctx, ipnskey, data)
}

// PkKeyForID returns the public key routing key for the given peer ID.
func PkKeyForID(id peer.ID) string {
	return "/pk/" + string(id)
}
