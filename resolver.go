package lite

import (
	"fmt"
	"github.com/ipfs/go-ipns"
	_ "github.com/ipfs/go-ipns/pb"

	"context"
	"time"

	"github.com/gogo/protobuf/proto"
	pb "github.com/ipfs/go-ipns/pb"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/routing"
	dht "github.com/libp2p/go-libp2p-kad-dht"
)

type Result struct {
	Path string
	Seq  uint64
	Err  error
}

type ResolveInfo interface {
	Resolved(NAME string, Seq int64)
	Close() bool
}

func (n *Node) DecodeName(name string) string {

	pid, err := peer.Decode(name)
	if err != nil {
		n.Listener.Error("Error decoding name")
		return ""
	}
	return pid.Pretty()
}

func (n *Node) ResolveName(info ResolveInfo, name string, offline bool, dhtRecords int) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func(stream ResolveInfo) {
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
	}(info)

	results := resolveIpnsOnceAsync(ctx, n.Listener, n.Routing, name, dhtRecords, offline)

	for res := range results {
		info.Resolved(res.Path, int64(res.Seq))
	}

	return nil
}

func emitOnceResult(ctx context.Context, outCh chan<- Result, r Result) {
	select {
	case outCh <- r:
	case <-ctx.Done():
	}
}

// resolveOnce implements resolver. Uses the IPFS routing system to
// resolve SFS-like names.
func resolveIpnsOnceAsync(ctx context.Context, listener Listener, r routing.ValueStore, name string, dhtRecords int, offline bool) <-chan Result {
	out := make(chan Result, 1)
	listener.Verbose(fmt.Sprintf("RoutingResolver resolving %s", name))
	cancel := func() {}

	pid, err := peer.Decode(name)
	if err != nil {
		listener.Error(fmt.Sprintf("RoutingResolver: could not convert public key hash %s to peer ID: %s\n", name, err))
		out <- Result{Err: err}
		close(out)
		cancel()
		return out
	}

	// Use the routing system to get the name.
	// Note that the DHT will call the ipns validator when retrieving
	// the value, which in turn verifies the ipns record signature
	ipnsKey := ipns.RecordKey(pid)

	var opts []routing.Option
	opts = append(opts, dht.Quorum(dhtRecords))
	if offline {
		opts = append(opts, routing.Offline)
	}

	vals, err := r.SearchValue(ctx, ipnsKey, opts...)

	if err != nil {
		listener.Error(fmt.Sprintf("RoutingResolver: dht get for name %s failed: %s", name, err))
		out <- Result{Err: err}
		close(out)
		cancel()
		return out
	}

	go func() {
		defer cancel()
		defer close(out)
		for {
			select {
			case val, ok := <-vals:
				if !ok {
					return
				}

				entry := new(pb.IpnsEntry)
				err = proto.Unmarshal(val, entry)
				if err != nil {
					listener.Error(fmt.Sprintf("RoutingResolver: could not unmarshal value for name %s: %s", name, err))
					emitOnceResult(ctx, out, Result{Err: err})
					return
				}

				p := string(entry.GetValue())
				seq := entry.GetSequence()

				emitOnceResult(ctx, out, Result{Path: p, Seq: seq})
			case <-ctx.Done():
				return
			}
		}
	}()

	return out
}
