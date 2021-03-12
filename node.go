package lite

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	_ "expvar"
	"github.com/ipfs/go-blockservice"
	"github.com/ipfs/go-cid"
	bs "github.com/ipfs/go-ipfs-blockstore"
	exchange "github.com/ipfs/go-ipfs-exchange-interface"
	format "github.com/ipfs/go-ipld-format"
	"github.com/libp2p/go-libp2p-core/connmgr"
	ci "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/peerstore"
	"github.com/libp2p/go-libp2p-core/pnet"
	"github.com/libp2p/go-libp2p-core/routing"
	record "github.com/libp2p/go-libp2p-record"
	_ "net/http/pprof"
	"time"
)

type Node struct {
	GracePeriod string
	LowWater    int
	HighWater   int
	Port        int
	Concurrency int
	Responsive  int

	PeerID     string
	PrivateKey string
	PublicKey  string
	Agent      string

	EnablePrivateNetwork bool
	SwarmKey             []byte

	Running        bool
	Shutdown       bool
	PrivateNetwork bool
	Pushing        bool
	Listener       Listener

	Exchange          exchange.Interface
	PeerStore         peerstore.Peerstore
	RecordValidator   record.Validator
	BlockStore        bs.Blockstore
	BlockService      blockservice.BlockService
	DagService        format.DAGService
	Host              host.Host
	ConnectionManager connmgr.ConnManager
	Routing           routing.Routing
}

type Listener interface {
	Error(Message string)
	Info(Message string)
	Verbose(Message string)
	ReachableUnknown()
	ReachablePublic()
	ReachablePrivate()
	Seeding(int)
	Leeching(int)
	ShouldConnect(string) bool
	ShouldGate(string) bool
	Push(string, string)
	BlockPut(string, []byte)
	BlockGet(string) []byte
	BlockHas(string) bool
	BlockSize(string) int
	BlockDelete(string)
}

type Closeable interface {
	Close() bool
}

func NewNode(listener Listener) *Node {
	return &Node{Listener: listener, BlockStore: NewBlockstore(listener), Running: false}
}

func (n *Node) CheckSwarmKey(key string) error {
	_, err := pnet.DecodeV1PSK(bytes.NewReader([]byte(key)))
	if err != nil {
		return err
	}
	return nil
}

func (n *Node) GetBlock(closeable Closeable, hash string) (string, error) {
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
	}(closeable)

	c, err := cid.Decode(hash)
	if err != nil {
		return "", err
	}

	block, err := n.Exchange.GetBlock(ctx, c)
	if err != nil {
		return "", err
	}

	return block.Cid().String(), nil

}

func (n *Node) Identity() error {

	sk, pk, err := ci.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return err
	}

	skbytes, err := sk.Bytes()
	if err != nil {
		return err
	}
	n.PrivateKey = base64.StdEncoding.EncodeToString(skbytes)

	id, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return err
	}
	n.PeerID = id.Pretty()

	pkbytes, err := pk.Raw()
	if err != nil {
		return err
	}
	n.PublicKey = base64.StdEncoding.EncodeToString(pkbytes)

	return nil
}

func (n *Node) GetRawPrivateKey() (string, error) {
	sk, err := DecodePrivateKey(n.PrivateKey)
	if err != nil {
		return "", err
	}

	// BEGIN TO GET RAW Private Key
	skbytes, err := sk.Raw()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(skbytes), nil

}

func DecodePrivateKey(privKey string) (ci.PrivKey, error) {
	pkb, err := base64.StdEncoding.DecodeString(privKey)
	if err != nil {
		return nil, err
	}

	// currently storing key unencrypted. in the future we need to encrypt it.
	// TODO(security)
	return ci.UnmarshalPrivateKey(pkb)
}
