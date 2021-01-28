package lite

import (
	"bytes"
	"context"
	_ "expvar"
	"fmt"
	"github.com/ipfs/go-bitswap"
	bsnet "github.com/ipfs/go-bitswap/network"
	"github.com/ipfs/go-blockservice"
	"github.com/ipfs/go-cid"
	blockstore "github.com/ipfs/go-ipfs-blockstore"
	"github.com/ipfs/go-ipns"
	"github.com/ipfs/go-merkledag"
	"github.com/libp2p/go-libp2p"
	connmgr "github.com/libp2p/go-libp2p-connmgr"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/event"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/peerstore"
	"github.com/libp2p/go-libp2p-core/pnet"
	"github.com/libp2p/go-libp2p-core/protocol"
	"github.com/libp2p/go-libp2p-core/routing"
	"github.com/libp2p/go-libp2p-gostream"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	noise "github.com/libp2p/go-libp2p-noise"
	"github.com/libp2p/go-libp2p-peerstore/pstoremem"
	libp2pquic "github.com/libp2p/go-libp2p-quic-transport"
	record "github.com/libp2p/go-libp2p-record"
	tls "github.com/libp2p/go-libp2p-tls"
	ma "github.com/multiformats/go-multiaddr"
	"io"
	_ "net/http/pprof"
	"sort"
	"time"
)

var (
	ProtocolPush protocol.ID = "/ipfs/push/1.0.0"
)

func (n *Node) Push(pid string, msg []byte) (int, error) {
	var id peer.ID

	var Timeout = time.Second * 3
	var num int
	var err error

	id, err = peer.Decode(pid)
	if err != nil {
		return 0, err
	}
	clientConn, err := gostream.Dial(context.Background(),
		n.Host, id, ProtocolPush)

	if err != nil {
		return 0, err
	}

	defer clientConn.Close()
	err = clientConn.SetDeadline(time.Now().Add(Timeout))
	if err != nil {
		return 0, err
	}

	num, err = clientConn.Write(msg)
	if err != nil && err != io.EOF {
		return 0, err
	}

	buf := make([]byte, 2)
	cum, err := clientConn.Read(buf)

	if err != nil && err != io.EOF {
		n.Listener.Error(err.Error())
		return 0, err
	}

	if string(buf[:cum]) != "ok" {
		return 0, err
	}

	return num, nil
}

const (
	MaxSize = 1024
)

func (n *Node) Daemon(EnablePrivateSharing bool) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// let the user know we're going.
	n.Listener.Info("Initializing daemon...")

	var Swarm []string

	Swarm = append(Swarm, fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", n.Port))
	Swarm = append(Swarm, fmt.Sprintf("/ip6/::/tcp/%d", n.Port))

	// TODO activate again when quic support private network
	if !n.EnablePrivateNetwork {
		Swarm = append(Swarm, fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic", n.Port))
		Swarm = append(Swarm, fmt.Sprintf("/ip6/::/udp/%d/quic", n.Port))
	}
	var err error
	mAddresses, err := listenAddresses(Swarm)
	if err != nil {
		return err
	}

	id, err := peer.Decode(n.PeerID)
	if err != nil {
		return fmt.Errorf("invalid peer id")
	}

	sk, err := DecodePrivateKey(n.PrivateKey)
	if err != nil {
		return err
	}

	n.PeerStore = pstoremem.NewPeerstore()
	n.RecordValidator = record.NamespacedValidator{
		"pk":   record.PublicKeyValidator{},
		"ipns": ipns.Validator{KeyBook: n.PeerStore},
	}

	err = pstoreAddSelfKeys(id, sk, n.PeerStore)
	if err != nil {
		return err
	}

	// hash security
	bs := blockstore.NewBlockstore(n.DataStore)

	bs = blockstore.NewIdStore(bs)
	gcLocker := blockstore.NewGCLocker()
	n.BlockStore = blockstore.NewGCBlockstore(bs, gcLocker)

	grace, err := time.ParseDuration(n.GracePeriod)
	if err != nil {
		return fmt.Errorf("parsing Swarm.ConnMgr.GracePeriod: %s", err)
	}
	n.ConnectionManager = connmgr.NewConnManager(n.LowWater, n.HighWater, grace)

	// HOST and Routing
	var opts []libp2p.Option
	opts = append(opts, libp2p.ListenAddrs(mAddresses...))
	opts = append(opts, libp2p.UserAgent(n.Agent))
	opts = append(opts, libp2p.ChainOptions(libp2p.Security(tls.ID, tls.New), libp2p.Security(noise.ID, noise.New)))
	opts = append(opts, libp2p.ConnectionManager(n.ConnectionManager))
	// TODO activate again when quic support private network
	if !n.EnablePrivateNetwork {
		opts = append(opts, libp2p.Transport(libp2pquic.NewTransport))
	}
	opts = append(opts, libp2p.DefaultTransports)
	opts = append(opts, libp2p.Ping(false))

	opts = append(opts, libp2p.ChainOptions(libp2p.EnableAutoRelay(), libp2p.DefaultStaticRelays()))

	opts = append(opts, libp2p.EnableNATService())

	interval := time.Minute

	opts = append(opts,
		libp2p.AutoNATServiceRateLimit(30, 3, interval),
	)

	if n.EnablePrivateNetwork {
		psk, err := pnet.DecodeV1PSK(bytes.NewReader(n.SwarmKey))
		if err != nil {
			return err
		}
		n.PrivateNetwork = true
		opts = append(opts, libp2p.PrivateNetwork(psk))
	} else {
		n.PrivateNetwork = false
	}

	// Let this host use the DHT to find other hosts
	opts = append(opts, libp2p.Routing(func(host host.Host) (routing.PeerRouting, error) {

		n.Routing, err = dht.New(
			ctx, host,
			dht.Concurrency(10),
			dht.Mode(dht.ModeClient),
			dht.Datastore(n.DataStore),
			dht.Validator(n.RecordValidator))

		bitSwapNetwork := bsnet.NewFromIpfsHost(host, n.Routing)
		if EnablePrivateSharing {
			bitSwapNetwork = NewLiteHost(host, n.Listener)
		}

		bs = &VerifBS{Blockstore: bs, Listener: n.Listener}
		exchange := bitswap.New(ctx, bitSwapNetwork, bs,
			bitswap.ProvideEnabled(false))

		n.BlockService = blockservice.New(n.BlockStore, exchange)
		n.DagService = merkledag.NewDAGService(n.BlockService)
		return n.Routing, err
	}))

	n.Host, err = constructPeerHost(ctx, id, n.PeerStore, opts)
	if err != nil {
		return fmt.Errorf("constructPeerHost: %s", err)
	}

	n.Listener.Info("New Node...")

	printSwarmAddrs(n)

	n.Listener.Info("Daemon is ready")

	n.Running = true
	n.Shutdown = false

	go receiver(n)
	go reachable(n, ctx)

	for {
		if n.Shutdown {
			n.Running = false
			n.Listener.Info("Daemon is shutdown")
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}

	return nil
}

func receiver(n *Node) {

	listener, _ := gostream.Listen(n.Host, ProtocolPush)
	defer listener.Close()
	var Timeout = time.Second * 3

	for {
		conn, err := listener.Accept()

		if err != nil {
			n.Listener.Error(err.Error())
			return
		}

		pid := conn.RemoteAddr().String()
		if !n.Shutdown {

			buf := make([]byte, 59)
			err = conn.SetDeadline(time.Now().Add(Timeout))
			if err != nil {
				n.Listener.Error(err.Error())
			}
			num, err := conn.Read(buf)
			if err != nil && err != io.EOF {
				n.Listener.Error(err.Error())
			} else {
				if n.Pushing {
					id, err := cid.Decode(string(buf[:num]))
					if err == nil {
						n.Listener.Push(id.String(), pid)
						_, err = conn.Write([]byte("ok"))
						if err != nil {
							n.Listener.Error(err.Error())
						}
					} else {
						_, err = conn.Write([]byte("ko"))
						if err != nil {
							n.Listener.Error(err.Error())
						}
					}
				} else {
					_, err = conn.Write([]byte("ko"))
					if err != nil {
						n.Listener.Error(err.Error())
					}
				}
			}

			err = conn.Close()
			if err != nil {
				n.Listener.Error(err.Error())
			}
		} else {
			return
		}
	}
}

func reachable(n *Node, ctx context.Context) {
	subReachability, _ := n.Host.EventBus().Subscribe(new(event.EvtLocalReachabilityChanged))
	defer subReachability.Close()

	for {
		select {
		case ev, ok := <-subReachability.Out():
			if !ok {
				return
			}
			evt, ok := ev.(event.EvtLocalReachabilityChanged)
			if !ok {
				return
			}
			if evt.Reachability == network.ReachabilityPrivate {
				n.Listener.ReachablePrivate()
			} else if evt.Reachability == network.ReachabilityPublic {
				n.Listener.ReachablePublic()
			} else {
				n.Listener.ReachableUnknown()
			}

		case <-ctx.Done():
			return
		}
	}
}

func listenAddresses(addresses []string) ([]ma.Multiaddr, error) {
	var listen []ma.Multiaddr
	for _, addr := range addresses {
		maddr, err := ma.NewMultiaddr(addr)
		if err != nil {
			return nil, fmt.Errorf("failure to parse config.Addresses.Swarm: %s", addresses)
		}
		listen = append(listen, maddr)
	}

	return listen, nil
}

func pstoreAddSelfKeys(id peer.ID, sk crypto.PrivKey, ps peerstore.Peerstore) error {
	if err := ps.AddPubKey(id, sk.GetPublic()); err != nil {
		return err
	}

	return ps.AddPrivKey(id, sk)
}

func constructPeerHost(ctx context.Context, id peer.ID, ps peerstore.Peerstore, options []libp2p.Option) (host.Host, error) {
	pkey := ps.PrivKey(id)
	if pkey == nil {
		return nil, fmt.Errorf("missing private key for node ID: %s", id.Pretty())
	}
	options = append([]libp2p.Option{libp2p.Identity(pkey), libp2p.Peerstore(ps)}, options...)

	return libp2p.New(ctx, options...)
}

func printSwarmAddrs(n *Node) {

	var lisAddrs []string
	ifaceAddrs, err := n.Host.Network().InterfaceListenAddresses()
	if err != nil {
		n.Listener.Error(fmt.Sprintf("failed to read listening addresses: %s", err))
	}
	for _, addr := range ifaceAddrs {
		lisAddrs = append(lisAddrs, addr.String())
	}
	sort.Strings(lisAddrs)
	for _, addr := range lisAddrs {
		n.Listener.Info(fmt.Sprintf("Swarm listening on %s", addr))
	}

	var addrs []string
	for _, addr := range n.Host.Addrs() {
		addrs = append(addrs, addr.String())
	}
	sort.Strings(addrs)
	for _, addr := range addrs {
		n.Listener.Info(fmt.Sprintf("Swarm announcing %s", addr))
	}

}
