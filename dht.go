package lite

import (
	"context"
	"fmt"
	"github.com/ipfs/go-cid"
	"github.com/ipfs/interface-go-ipfs-core/path"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/routing"
	"time"
)

type Provider interface {
	Pid(Message string)
}

func (n *Node) DhtFindProvsTimeout(mcid string, provider Provider, numProviders int, timeout int32) error {
	dnsTimeout := time.Duration(timeout) * time.Second

	cctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()

	if numProviders < 1 {
		return fmt.Errorf("number of providers must be greater than 0")
	}

	var err error

	cido := path.New(mcid)

	pchan, err := n.FindProviders(cctx, cido, numProviders)
	if err != nil {
		return err
	}

	for p := range pchan {
		np := p
		provider.Pid(np.ID.Pretty())
	}

	return nil
}

func (n *Node) DhtFindProvs(mcid string, provider Provider, numProviders int, close Closeable) error {
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

	if numProviders < 1 {
		return fmt.Errorf("number of providers must be greater than 0")
	}

	var err error

	cido := path.New(mcid)

	pchan, err := n.FindProviders(ctx, cido, numProviders)
	if err != nil {
		return err
	}

	for p := range pchan {
		np := p
		provider.Pid(np.ID.Pretty())
	}

	return nil
}

func (n *Node) DhtProvide(mcid string, close Closeable) error {
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

	return n.Provide(ctx, path.New(mcid))
}

func (n *Node) DhtProvideTimeout(mcid string, timeout int32) error {
	dnsTimeout := time.Duration(timeout) * time.Second

	cctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()

	cido := path.New(mcid)
	return n.Provide(cctx, cido)
}

func (n *Node) FindPeer(ctx context.Context, p peer.ID) (peer.AddrInfo, error) {

	pi, err := n.Routing.FindPeer(ctx, peer.ID(p))
	if err != nil {
		return peer.AddrInfo{}, err
	}

	return pi, nil
}

func (n *Node) FindProviders(ctx context.Context, p path.Path, numProviders int) (<-chan peer.AddrInfo, error) {

	rp, err := ResolvePath(ctx, n.DagService, p)
	if err != nil {
		return nil, err
	}

	if numProviders < 1 {
		return nil, fmt.Errorf("number of providers must be greater than 0")
	}

	pchan := n.Routing.FindProvidersAsync(ctx, rp.Cid(), numProviders)
	return pchan, nil
}

func (n *Node) Provide(ctx context.Context, path path.Path) error {

	rp, err := ResolvePath(ctx, n.DagService, path)
	if err != nil {
		return err
	}

	c := rp.Cid()

	has, err := n.BlockStore.Has(c)
	if err != nil {
		return err
	}

	if !has {
		return fmt.Errorf("block %s not found locally, cannot provide", c)
	}

	return provideKeys(ctx, n.Routing, c)

}

func provideKeys(ctx context.Context, r routing.Routing, cid cid.Cid) error {
	return r.Provide(ctx, cid, true)
}
