package lite

import (
	"context"

	"github.com/libp2p/go-libp2p-core/network"
	inet "github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"time"
)

type PeerStream interface {
	Peer(ID string)
}

type Peer struct {
	Address string
	ID      string
}

func (n *Node) NumSwarmPeers() int {
	return len(n.Host.Network().Conns())
}

func (n *Node) SwarmPeer(pid string) (*Peer, error) {

	conn := n.Host.Network().Conns()

	for _, c := range conn {

		if c.RemotePeer().Pretty() == pid {
			ci := Peer{
				Address: c.RemoteMultiaddr().String(),
				ID:      c.RemotePeer().Pretty(),
			}
			return &ci, nil
		}

	}

	return nil, nil
}

func (n *Node) IsConnected(pid string) (bool, error) {

	id, err := peer.Decode(pid)
	if err != nil {
		return false, err
	}

	net := n.Host.Network()
	connected := net.Connectedness(id) == network.Connected
	return connected, nil

}

func (n *Node) SwarmConnect(addr string, protect bool, close Closeable) (bool, error) {
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
	var err error

	pis, err := parseAddresses(addr)
	if err != nil {
		return false, err
	}

	for _, pi := range pis {
		err = n.Connect(ctx, pi, protect)
		if err != nil {
			return false, err
		}
		return true, nil
	}

	return false, nil
}

func (n *Node) SwarmConnectTimeout(addr string, timeout int32, protect bool) (bool, error) {
	dnsTimeout := time.Duration(timeout) * time.Second

	cctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	var err error

	pis, err := parseAddresses(addr)
	if err != nil {
		return false, err
	}

	for _, pi := range pis {
		err = n.Connect(cctx, pi, protect)
		if err != nil {
			return false, err
		}
		return true, nil
	}

	return false, nil
}

func parseAddresses(addrs string) ([]peer.AddrInfo, error) {

	maddrs, err := resolveAddr(addrs)

	if err != nil {
		return nil, err
	}

	return peer.AddrInfosFromP2pAddrs(maddrs)
}

func resolveAddr(addrs string) (ma.Multiaddr, error) {
	maddr, err := ma.NewMultiaddr(addrs)
	if err != nil {
		return nil, err
	}

	return maddr, nil
}

// tag used in the connection manager when explicitly connecting to a peer.
const connectionManagerTag = "user-connect"
const connectionManagerWeight = 100

func (n *Node) Connect(ctx context.Context, pi peer.AddrInfo, protect bool) error {

	if err := n.Host.Connect(ctx, pi); err != nil {
		return err
	}

	if protect {
		n.Host.ConnManager().TagPeer(pi.ID, connectionManagerTag, connectionManagerWeight)
		n.Host.ConnManager().Protect(pi.ID, connectionManagerTag)
	}
	return nil
}

func (n *Node) SwarmDisconnect(addr string) (bool, error) {
	var err error

	addrs, err := parseAddresses(addr)
	if err != nil {
		return false, err
	}
	output := make([]string, 0, len(addrs))
	for _, ainfo := range addrs {
		maddrs, err := peer.AddrInfoToP2pAddrs(&ainfo)
		if err != nil {
			return false, err
		}
		// FIXME: This will print:
		//
		//   disconnect QmFoo success
		//   disconnect QmFoo success
		//   ...
		//
		// Once per address specified. However, I'm not sure of
		// a good backwards compat solution. Right now, I'm just
		// preserving the current behavior.
		for _, addr := range maddrs {
			msg := "disconnect " + ainfo.ID.Pretty()
			if err := n.Disconnect(addr); err != nil {
				msg += " failure: " + err.Error()
			} else {
				msg += " success"
			}
			output = append(output, msg)
		}
	}
	return false, nil
}

func (n *Node) Disconnect(addr ma.Multiaddr) error {

	taddr, id := peer.SplitAddr(addr)
	if id == "" {
		return peer.ErrInvalidAddr
	}

	net := n.Host.Network()
	if taddr == nil {
		if net.Connectedness(id) != inet.Connected {
			return nil
		}
		if err := net.ClosePeer(id); err != nil {
			return err
		}
		return nil
	}
	for _, conn := range net.ConnsToPeer(id) {
		if !conn.RemoteMultiaddr().Equal(taddr) {
			continue
		}

		return conn.Close()
	}
	return nil
}

func (n *Node) SwarmPeers(stream PeerStream) error {

	conn := n.Host.Network().Conns()

	for _, c := range conn {
		stream.Peer(c.RemotePeer().Pretty())
	}
	return nil
}
