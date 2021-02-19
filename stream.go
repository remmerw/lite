package lite

import (
	"context"
	"fmt"
	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-blockservice"
	"github.com/ipfs/go-cid"
	"github.com/ipfs/go-cidutil"
	blockstore "github.com/ipfs/go-ipfs-blockstore"
	offlinexch "github.com/ipfs/go-ipfs-exchange-offline"
	files "github.com/ipfs/go-ipfs-files"
	ipld "github.com/ipfs/go-ipld-format"
	dag "github.com/ipfs/go-merkledag"
	ipfspath "github.com/ipfs/go-path"
	"github.com/ipfs/go-path/resolver"
	uio "github.com/ipfs/go-unixfs/io"
	"github.com/ipfs/interface-go-ipfs-core/options"
	"github.com/ipfs/interface-go-ipfs-core/path"
	"io"
	"os"
	gopath "path"
	"time"
)

type Writer struct {
	Writer WriterStream
}

type Reader struct {
	DagReader uio.DagReader
	Size      int64
	Data      []byte
	Read      int
}

type Loader struct {
	DagReader  uio.DagReader
	Size       int64
	Data       []byte
	Read       int
	Responsive int
}

type LoaderClose interface {
	Close() bool
}

type WriterStream interface {
	Read() (n int, err error)
	Data() []byte
	Close() bool
}

func (fd *Writer) Read(p []byte) (n int, err error) {

	load, err := fd.Writer.Read()

	if err != nil {
		return 0, err
	}

	copy(p, fd.Writer.Data())

	if load < 0 {
		return 0, io.EOF
	}

	return load, nil

}

func (n *Node) GetLoader(paths string, close LoaderClose) (*Loader, error) {
	ctx, cancel := context.WithCancel(context.Background())

	var err error
	var done bool = false

	go func(stream LoaderClose) {
		for {
			if ctx.Err() != nil {
				break
			}
			if done {
				break
			}
			if stream.Close() {
				cancel()
				break
			}
			time.Sleep(time.Duration(n.Responsive) * time.Millisecond)
		}
	}(close)

	p := path.New(paths)

	dagService := dag.NewReadOnlyDagService(
		dag.NewSession(ctx, n.DagService))

	nd, err := n.ResolveNode(ctx, dagService, p)
	if err != nil {
		return nil, err
	}

	dr, err := uio.NewDagReader(ctx, nd, dagService)
	if err != nil {
		return nil, err
	}

	size := dr.Size()
	done = true
	return &Loader{DagReader: dr, Size: int64(size), Responsive: n.Responsive}, nil

}

func (n *Node) AddFile(fpath string) (string, error) {

	ctx := context.Background()

	var err error
	stat, err := os.Stat(fpath)
	if err != nil {
		return "", err
	}
	fn, err := files.NewSerialFile(fpath, false, stat)
	if err != nil {
		return "", err
	}

	fileAdder, err := n.getFileAdder(ctx)
	if err != nil {
		return "", err
	}

	nd, err := fileAdder.AddFileNode(fn)
	if err != nil {
		return "", err
	}

	return path.IpfsPath(nd.Cid()).Cid().String(), nil

}

func (n *Node) getFileAdder(ctx context.Context) (*Adder, error) {
	var err error

	settings, prefix, err := options.UnixfsAddOptions(options.Unixfs.CidVersion(1))
	if err != nil {
		return nil, err
	}

	gcbs := blockstore.NewBlockstore(n.DataStore)
	gcbs = &BS{Blockstore: gcbs}

	exchange := offlinexch.Exchange(gcbs)

	bserv := blockservice.New(gcbs, exchange) // hash security 001
	dagService := dag.NewDAGService(bserv)

	fileAdder, err := NewAdder(ctx, dagService)
	if err != nil {
		return nil, err
	}

	fileAdder.Chunker = settings.Chunker
	fileAdder.RawLeaves = settings.RawLeaves
	fileAdder.NoCopy = settings.NoCopy
	fileAdder.CidBuilder = prefix

	switch settings.Layout {
	case options.BalancedLayout:
		// Default
	case options.TrickleLayout:
		fileAdder.Trickle = true
	default:
		return nil, fmt.Errorf("unknown layout: %d", settings.Layout)
	}

	if settings.Inline {
		fileAdder.CidBuilder = cidutil.InlineBuilder{
			Builder: fileAdder.CidBuilder,
			Limit:   settings.InlineLimit,
		}
	}
	return fileAdder, nil
}
func (n *Node) CreateEmptyDir() (string, error) {
	ctx := context.Background()

	fileAdder, err := n.getFileAdder(ctx)
	if err != nil {
		return "", err
	}

	nd, err := fileAdder.CreateEmptyDir()
	if err != nil {
		return "", err
	}

	return path.IpfsPath(nd.Cid()).Cid().String(), nil
}

func (n *Node) AddLinkToDir(dir string, name string, link string) (string, error) {

	ctx := context.Background()

	fileAdder, err := n.getFileAdder(ctx)
	if err != nil {
		return "", err
	}

	dirNode, err := n.ResolveNode(ctx, fileAdder.dagService, path.New(dir))
	if err != nil {
		return "", err
	}

	linkNode, err := n.ResolveNode(ctx, fileAdder.dagService, path.New(link))
	if err != nil {
		return "", err
	}

	nd, err := fileAdder.AddLinkToDir(dirNode, name, linkNode)
	if err != nil {
		return "", err
	}

	return path.IpfsPath(nd.Cid()).Cid().String(), nil

}
func (n *Node) RemoveLinkFromDir(dir string, linkName string) (string, error) {

	ctx := context.Background()

	fileAdder, err := n.getFileAdder(ctx)
	if err != nil {
		return "", err
	}

	dirNode, err := n.ResolveNode(ctx, fileAdder.dagService, path.New(dir))
	if err != nil {
		return "", err
	}

	nd, err := fileAdder.RemoveLinkFromDir(dirNode, linkName)
	if err != nil {
		return "", err
	}

	return path.IpfsPath(nd.Cid()).Cid().String(), nil

}

type BS struct {
	blockstore.Blockstore
}

func (bs *BS) Put(b blocks.Block) error {
	return bs.Blockstore.Put(b)
}

func (bs *BS) PutMany(blks []blocks.Block) error {
	for _, b := range blks {
		if err := bs.Put(b); err != nil {
			return err
		}
	}
	return nil
}

func (bs *BS) Get(c cid.Cid) (blocks.Block, error) {
	return bs.Blockstore.Get(c)
}

func (n *Node) Stream(stream WriterStream) (string, error) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func(stream WriterStream) {
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
	}(stream)

	fileAdder, err := n.getFileAdder(ctx)
	if err != nil {
		return "", err
	}

	fd := &Writer{Writer: stream}

	var reader io.Reader = fd
	nd, err := fileAdder.Add(reader)

	if err != nil {
		return "", err
	}
	return path.IpfsPath(nd.Cid()).Cid().String(), nil
}

func (n *Node) GetReader(paths string) (*Reader, error) {

	ctx := context.Background()

	var err error

	p := path.New(paths)

	gcbs := blockstore.NewBlockstore(n.DataStore)

	exchange := offlinexch.Exchange(gcbs)
	bs := blockservice.New(gcbs, exchange)
	dags := dag.NewDAGService(bs)

	dagReadOnlyService := dag.NewReadOnlyDagService(dags)

	rp, err := ResolvePath(ctx, dagReadOnlyService, p)
	if err != nil {
		return nil, err
	}

	nd, err := dagReadOnlyService.Get(ctx, rp.Cid())
	if err != nil {
		return nil, err
	}

	dr, err := uio.NewDagReader(ctx, nd, dagReadOnlyService)
	if err != nil {
		return nil, err
	}

	size := dr.Size()

	return &Reader{DagReader: dr, Size: int64(size)}, nil

}

func (fd *Reader) Close() error {
	return fd.DagReader.Close()
}

func (fd *Reader) Seek(position int64) error {

	_, err := fd.DagReader.Seek(position, 0)
	if err != nil {
		return err
	}

	return nil
}

func (fd *Loader) Close() error {
	return fd.DagReader.Close()
}

func (fd *Loader) Seek(position int64, close LoaderClose) error {
	var done = false
	go func(stream LoaderClose) {
		for {
			if done {
				break
			}
			if stream.Close() {
				fd.Close()
				break
			}
			time.Sleep(time.Duration(fd.Responsive) * time.Millisecond)
		}
	}(close)
	_, err := fd.DagReader.Seek(position, 0)
	done = true
	if err != nil {
		return err
	}

	return nil
}

func (fd *Loader) Load(size int64, close LoaderClose) error {

	var done = false
	go func(stream LoaderClose) {
		for {
			if done {
				break
			}
			if stream.Close() {
				fd.Close()
				break
			}
			time.Sleep(time.Duration(fd.Responsive) * time.Millisecond)
		}
	}(close)

	buf := make([]byte, size)
	fd.Read = 0

	n, err := fd.DagReader.Read(buf)
	done = true
	if n != 0 {
		fd.Read = n
		fd.Data = buf[:n]
	}
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}
	return nil
}

func (fd *Reader) Load(size int64) error {

	buf := make([]byte, size)
	fd.Read = 0

	n, err := fd.DagReader.Read(buf)
	if n != 0 {
		fd.Read = n
		fd.Data = buf[:n]
	}
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}
	return nil
}

func (fd *Reader) ReadAt(position int64, size int64) error {

	err := fd.Seek(position)
	if err != nil {
		return err
	}

	return fd.Load(size)
}

func ResolvePath(ctx context.Context, dag ipld.NodeGetter, p path.Path) (path.Resolved, error) {
	if _, ok := p.(path.Resolved); ok {
		return p.(path.Resolved), nil
	}
	if err := p.IsValid(); err != nil {
		return nil, err
	}

	ipath := ipfspath.Path(p.String())

	var resolveOnce resolver.ResolveOnce

	switch ipath.Segments()[0] {
	case "ipfs":
		resolveOnce = uio.ResolveUnixfsOnce
	case "ipld":
		resolveOnce = resolver.ResolveSingle
	default:
		return nil, fmt.Errorf("unsupported path namespace: %s", p.Namespace())
	}

	r := &resolver.Resolver{
		DAG:         dag,
		ResolveOnce: resolveOnce,
	}

	node, rest, err := r.ResolveToLastNode(ctx, ipath)
	if err != nil {
		return nil, err
	}

	root, err := cid.Parse(ipath.Segments()[1])
	if err != nil {
		return nil, err
	}

	return path.NewResolvedPath(ipath, node, root, gopath.Join(rest...)), nil
}
