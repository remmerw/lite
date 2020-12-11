package lite

import (
	"context"
	"errors"
	"github.com/ipfs/go-cid"
	bstore "github.com/ipfs/go-ipfs-blockstore"
	chunker "github.com/ipfs/go-ipfs-chunker"
	files "github.com/ipfs/go-ipfs-files"
	ipld "github.com/ipfs/go-ipld-format"
	dag "github.com/ipfs/go-merkledag"
	"github.com/ipfs/go-unixfs"
	"github.com/ipfs/go-unixfs/importer/balanced"
	ihelper "github.com/ipfs/go-unixfs/importer/helpers"
	"github.com/ipfs/go-unixfs/importer/trickle"
	fio "github.com/ipfs/go-unixfs/io"
	"io"
	gopath "path"
)

type Link struct {
	Name, Hash string
	Size       uint64
}

// NewAdder Returns a new Adder used for a file add operation.
func NewAdder(ctx context.Context, ds ipld.DAGService) (*Adder, error) {
	return &Adder{
		ctx:        ctx,
		dagService: ds,
		Trickle:    false,
		Chunker:    "",
	}, nil
}

// Adder holds the switches passed to the `add` command.
type Adder struct {
	ctx        context.Context
	gcLocker   bstore.GCLocker
	dagService ipld.DAGService
	Trickle    bool
	RawLeaves  bool
	NoCopy     bool
	Chunker    string
	tempRoot   cid.Cid
	CidBuilder cid.Builder
}

// Constructs a node from reader's data, and adds it. Doesn't pin.
func (adder *Adder) Add(reader io.Reader) (ipld.Node, error) {
	chnk, err := chunker.FromString(reader, adder.Chunker)
	if err != nil {
		return nil, err
	}

	params := ihelper.DagBuilderParams{
		Dagserv:    adder.dagService,
		RawLeaves:  adder.RawLeaves,
		Maxlinks:   ihelper.DefaultLinksPerBlock,
		NoCopy:     adder.NoCopy,
		CidBuilder: adder.CidBuilder,
	}

	db, err := params.New(chnk)
	if err != nil {
		return nil, err
	}
	var nd ipld.Node
	if adder.Trickle {
		nd, err = trickle.Layout(db)
	} else {
		nd, err = balanced.Layout(db)
	}
	if err != nil {
		return nil, err
	}

	return nd, nil
}

type syncer interface {
	Sync() error
}

// AddAllAndPin adds the given request's files and pin them.
func (adder *Adder) AddFileNode(file files.Node) (ipld.Node, error) {

	nd, err := adder.addFileNode("", file, true)
	if err != nil {
		return nil, err
	}

	if asyncDagService, ok := adder.dagService.(syncer); ok {
		err := asyncDagService.Sync()
		if err != nil {
			return nil, err
		}
	}

	return nd, nil

}

// Constructs a node from reader's data, and adds it. Doesn't pin.
func (adder *Adder) add(reader io.Reader) (ipld.Node, error) {
	chnk, err := chunker.FromString(reader, adder.Chunker)
	if err != nil {
		return nil, err
	}

	params := ihelper.DagBuilderParams{
		Dagserv:    adder.dagService,
		RawLeaves:  adder.RawLeaves,
		Maxlinks:   ihelper.DefaultLinksPerBlock,
		NoCopy:     adder.NoCopy,
		CidBuilder: adder.CidBuilder,
	}

	db, err := params.New(chnk)
	if err != nil {
		return nil, err
	}
	var nd ipld.Node
	if adder.Trickle {
		nd, err = trickle.Layout(db)
	} else {
		nd, err = balanced.Layout(db)
	}
	if err != nil {
		return nil, err
	}

	return nd, nil
}

func (adder *Adder) addFileNode(path string, file files.Node, toplevel bool) (ipld.Node, error) {
	defer file.Close()

	switch f := file.(type) {
	case files.Directory:
		return adder.addDir(path, f, toplevel)
	case *files.Symlink:
		return adder.addSymlink(path, f)
	case files.File:
		return adder.addFile(path, f)
	default:
		return nil, errors.New("unknown file type")
	}
}

func (adder *Adder) addSymlink(path string, l *files.Symlink) (ipld.Node, error) {
	sdata, err := unixfs.SymlinkData(l.Target)
	if err != nil {
		return nil, err
	}

	dagnode := dag.NodeWithData(sdata)
	dagnode.SetCidBuilder(adder.CidBuilder)
	err = adder.dagService.Add(adder.ctx, dagnode)
	if err != nil {
		return nil, err
	}

	return dagnode, nil
}

func (adder *Adder) addFile(path string, file files.File) (ipld.Node, error) {

	var reader io.Reader = file

	nd, err := adder.add(reader)
	if err != nil {
		return nil, err
	}

	// patch it into the root
	return nd, nil
}

func (adder *Adder) addDir(path string, dir files.Directory, toplevel bool) (ipld.Node, error) {

	fiod := fio.NewDirectory(adder.dagService)
	fiod.SetCidBuilder(adder.CidBuilder)

	it := dir.Entries()
	for it.Next() {
		fpath := gopath.Join(path, it.Name())
		nd, err := adder.addFileNode(fpath, it.Node(), false)
		if err != nil {
			return nil, err
		}
		err = fiod.AddChild(adder.ctx, it.Name(), nd)
		if err != nil {
			return nil, err
		}
	}
	fnd, err := fiod.GetNode()
	if err != nil {
		return nil, err
	}

	err = adder.dagService.Add(adder.ctx, fnd)
	if err != nil {
		return nil, err
	}
	return fnd, nil
}
func (adder *Adder) CreateEmptyDir() (ipld.Node, error) {

	fiod := fio.NewDirectory(adder.dagService)
	fiod.SetCidBuilder(adder.CidBuilder)

	fnd, err := fiod.GetNode()
	if err != nil {
		return nil, err
	}

	err = adder.dagService.Add(adder.ctx, fnd)
	if err != nil {
		return nil, err
	}
	return fnd, nil
}

func (adder *Adder) CreateDir(node ipld.Node) (ipld.Node, error) {

	fiod, err := fio.NewDirectoryFromNode(adder.dagService, node)
	if err != nil {
		return nil, err
	}
	fiod.SetCidBuilder(adder.CidBuilder)

	fnd, err := fiod.GetNode()
	if err != nil {
		return nil, err
	}

	err = adder.dagService.Add(adder.ctx, fnd)
	if err != nil {
		return nil, err
	}
	return fnd, nil
}

func (adder *Adder) RemoveLinkFromDir(node ipld.Node, name string) (ipld.Node, error) {

	fiod, err := fio.NewDirectoryFromNode(adder.dagService, node)
	if err != nil {
		return nil, err
	}
	fiod.SetCidBuilder(adder.CidBuilder)

	err = fiod.RemoveChild(adder.ctx, name)
	if err != nil {
		return nil, err
	}

	fnd, err := fiod.GetNode()
	if err != nil {
		return nil, err
	}

	err = adder.dagService.Add(adder.ctx, fnd)
	if err != nil {
		return nil, err
	}
	return fnd, nil
}

func (adder *Adder) AddLinkToDir(node ipld.Node, name string, link ipld.Node) (ipld.Node, error) {

	fiod, err := fio.NewDirectoryFromNode(adder.dagService, node)
	if err != nil {
		return nil, err
	}
	fiod.SetCidBuilder(adder.CidBuilder)

	err = fiod.AddChild(adder.ctx, name, link)
	if err != nil {
		return nil, err
	}

	fnd, err := fiod.GetNode()
	if err != nil {
		return nil, err
	}

	err = adder.dagService.Add(adder.ctx, fnd)
	if err != nil {
		return nil, err
	}
	return fnd, nil
}
