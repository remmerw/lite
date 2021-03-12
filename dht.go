package lite

import (
	"context"
	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p-core/peer"
	"time"
)

type Providers interface {
	Closeable
	Peer(PeerID string)
}

func (n *Node) DhtFindProviders(hash string, numProviders int, provider Providers) error {
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
	}(provider)

	c, err := cid.Decode(hash)
	if err != nil {
		return err
	}

	pchan := n.Routing.FindProvidersAsync(ctx, c, numProviders)

	for p := range pchan {
		np := p
		provider.Peer(np.ID.Pretty())
	}

	return nil
}

func (n *Node) DhtProvide(hash string, close Closeable) error {
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

	c, err := cid.Decode(hash)
	if err != nil {
		return err
	}

	return n.Routing.Provide(ctx, c, true)
}

func (n *Node) FindPeer(ctx context.Context, p peer.ID) (peer.AddrInfo, error) {

	pi, err := n.Routing.FindPeer(ctx, peer.ID(p))
	if err != nil {
		return peer.AddrInfo{}, err
	}

	return pi, nil
}
