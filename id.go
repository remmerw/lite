package lite

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/libp2p/go-libp2p-core/peer"
	pstore "github.com/libp2p/go-libp2p-core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/protocol/identify"
)


type PeerInfo struct {
	ID              string
	PublicKey       string
	AgentVersion    string
	ProtocolVersion string
}

func (n *Node) Id() (*PeerInfo, error) {
	return n.printSelf()
}

func (n *Node) PidCheck(pid string) error {

	var err error
	_, err = peer.Decode(pid)
	if err != nil {
		return fmt.Errorf("invalid peer id")
	}
	return nil
}

func (n *Node) PidInfo(pid string) (*PeerInfo, error) {

	var id peer.ID

	var err error
	id, err = peer.Decode(pid)
	if err != nil {
		return nil, fmt.Errorf("invalid peer id")
	}

	if pid == n.PeerID {
		return n.printSelf()
	}

	return printPeer(n.PeerStore, id)
}


func printPeer(ps pstore.Peerstore, p peer.ID) (*PeerInfo, error) {
	if p == "" {
		return nil, errors.New("attempted to print nil peer")
	}

	info := new(PeerInfo)
	info.ID = p.Pretty()

	if pk := ps.PubKey(p); pk != nil {
		pkbytes, err := pk.Raw()
		if err != nil {
			return nil, err
		}
		info.PublicKey = base64.StdEncoding.EncodeToString(pkbytes)
	}

	if v, err := ps.Get(p, "ProtocolVersion"); err == nil {
		if vs, ok := v.(string); ok {
			info.ProtocolVersion = vs
		}
	}
	if v, err := ps.Get(p, "AgentVersion"); err == nil {
		if vs, ok := v.(string); ok {
			info.AgentVersion = vs
		}
	}

	return info, nil
}

func (n *Node) printSelf() (*PeerInfo, error) {
	info := new(PeerInfo)
	info.ID = n.PeerID

	info.PublicKey = n.PublicKey

	info.ProtocolVersion = identify.LibP2PVersion
	info.AgentVersion = "n.a."
	return info, nil
}

func (n *Node) Base58(pid string) (string, error) {

	id, err := peer.Decode(pid)
	if err != nil {
		return "", fmt.Errorf("invalid peer id")
	}
	return id.Pretty(), nil
}

func (n *Node) Base32(pid string) (string, error) {

	id, err := peer.Decode(pid)
	if err != nil {
		return "", fmt.Errorf("invalid peer id")
	}
	return peer.ToCid(id).String(), nil
}

