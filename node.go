package lite

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	_ "expvar"
	"github.com/dgraph-io/badger/v2"
	"github.com/ipfs/go-blockservice"
	ds "github.com/ipfs/go-datastore"
	blockstore "github.com/ipfs/go-ipfs-blockstore"
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
)

type Node struct {
	GracePeriod string
	LowWater    int
	HighWater   int
	Port        int

	PeerID     string
	PrivateKey string
	PublicKey  string
	RepoPath   string
	Agent      string

	EnablePrivateNetwork bool
	SwarmKey             []byte

	Running           bool
	Shutdown          bool
	PrivateNetwork    bool
	Pushing           bool
	Listener          Listener
	Badger            *badger.DB
	DataStore         ds.Batching
	PeerStore         peerstore.Peerstore
	RecordValidator   record.Validator
	BlockStore        blockstore.Blockstore
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
}

func NewNode(listener Listener, repoPath string) *Node {
	return &Node{Listener: listener, RepoPath: repoPath, Running: false}
}

func (n *Node) OpenDatabase() error {

	repodb, err := Create(n.RepoPath)
	if err != nil {
		return err
	}
	n.Listener.Info("Repo open...")
	n.DataStore = repodb
	n.Badger = repodb.DB
	return nil
}

func (n *Node) CheckSwarmKey(key string) error {
	_, err := pnet.DecodeV1PSK(bytes.NewReader([]byte(key)))
	if err != nil {
		return err
	}
	return nil
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
