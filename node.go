package lite

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	_ "expvar"
	"github.com/libp2p/go-libp2p-core/connmgr"
	ci "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/peerstore"
	"github.com/libp2p/go-libp2p-core/pnet"
	"github.com/libp2p/go-libp2p-core/protocol"
	"github.com/libp2p/go-libp2p-core/routing"
	record "github.com/libp2p/go-libp2p-record"
	"github.com/libp2p/go-msgio"
	"io"
	_ "net/http/pprof"
	"strings"
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

	EnablePushService    bool
	EnableConnService    bool
	EnableReachService   bool
	EnablePrivateNetwork bool
	SwarmKey             []byte

	Running        bool
	Shutdown       bool
	PrivateNetwork bool
	Pushing        bool
	Listener       Listener

	PeerStore         peerstore.Peerstore
	RecordValidator   record.Validator
	Host              host.Host
	ConnectionManager connmgr.ConnManager
	Routing           routing.Routing
}

type Listener interface {
	Error(Message string)
	Info(Message string)
	Verbose(Message string)
	AllowConnect(string) bool
	ReachableUnknown()
	ReachablePublic()
	ReachablePrivate()
	Push(string, string)
	BitSwapData(string, string, []byte)
	BitSwapError(string, string, string)
	Connected(pretty string)
}

type Closeable interface {
	Close() bool
}

func NewNode(listener Listener) *Node {
	return &Node{Listener: listener, Running: false}
}

func (n *Node) CheckSwarmKey(key string) error {
	_, err := pnet.DecodeV1PSK(bytes.NewReader([]byte(key)))
	if err != nil {
		return err
	}
	return nil
}

func (n *Node) WriteMessage(close Closeable, pid string, protocols string, data []byte, timeout int32) (int, error) {
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

	id, err := peer.Decode(pid)
	if err != nil {
		return 0, err
	}

	stream, err := n.Host.NewStream(ctx, id,
		protocol.ConvertFromStrings(strings.Split(protocols, ";"))...)
	if err != nil {
		return 0, err
	}
	defer stream.Close()
	dnsTimeout := time.Duration(timeout) * time.Second
	err = stream.SetWriteDeadline(time.Now().Add(dnsTimeout))
	if err != nil && err != io.EOF {
		return 0, err
	}
	return stream.Write(data)
}

func (n *Node) SetStreamHandler(proto string) {
	n.Host.SetStreamHandler(protocol.ID(proto), n.handleNewStream)
}
func (n *Node) handleNewStream(s network.Stream) {
	defer s.Close()

	reader := msgio.NewVarintReaderSize(s, network.MessageSizeMax)
	for {
		p := s.Conn().RemotePeer()

		received, err := reader.ReadMsg()
		if err != nil {
			reader.ReleaseMsg(received)
			if err != io.EOF {
				_ = s.Reset()
				n.Listener.BitSwapError(p.String(), string(s.Protocol()), err.Error())
			}
			return
		}
		n.Listener.BitSwapData(p.String(), string(s.Protocol()), received)
		reader.ReleaseMsg(received)
	}
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
