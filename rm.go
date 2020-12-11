package lite

import (
	"context"
	"github.com/ipfs/go-blockservice"
	"github.com/ipfs/go-cid"
	"github.com/ipfs/go-cidutil/cidenc"
	blockstore "github.com/ipfs/go-ipfs-blockstore"
	offlinexch "github.com/ipfs/go-ipfs-exchange-offline"
	ipld "github.com/ipfs/go-ipld-format"
	dag "github.com/ipfs/go-merkledag"
	"github.com/ipfs/interface-go-ipfs-core/path"
	//"github.com/ipfs/interface-go-ipfs-core/path"
)

type RefWriter struct {
	DAG      ipld.DAGService
	Ctx      context.Context
	Paths    []string
	Unique   bool
	MaxDepth int
	PrintFmt string

	seen map[string]int
}

func (n *Node) Rm(paths string, recursive bool) error {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var err error

	enc := cidenc.Default()

	bb := blockstore.NewBlockstore(n.DataStore)
	gclocker := blockstore.NewGCLocker()
	gcbs := blockstore.NewGCBlockstore(bb, gclocker)
	exchange := offlinexch.Exchange(gcbs)
	blocks := blockservice.New(gcbs, exchange)
	dags := dag.NewDAGService(blocks)

	top, err := ResolveNode(ctx, dags, path.New(paths))
	if err != nil {
		return err
	}

	if recursive {
		rw := RefWriter{
			DAG:      dags,
			Ctx:      ctx,
			Unique:   true,
			MaxDepth: -1,
		}
		_, err = rw.EvalRefs(top, enc)
		if err != nil {
			return err
		}

		for _, p := range rw.Paths {
			path.New(p)
			o, err := ResolveNode(ctx, dags, path.New(p))
			if err != nil {
				return err
			}
			cids := []cid.Cid{o.Cid()}
			err = n.RmBlocks(gcbs, cids)
			if err != nil {
				return err
			}
		}
	}
	cids := []cid.Cid{top.Cid()}
	return n.RmBlocks(gcbs, cids)

}

// RmBlocks removes the blocks provided in the cids slice.
// It returns a channel where objects of type RemovedBlock are placed, when
// not using the Quiet option. Block removal is asynchronous and will
// skip any pinned blocks.
func (n *Node) RmBlocks(blocks blockstore.GCBlockstore, cids []cid.Cid) error {
	// make the channel large enough to hold any result to avoid
	// blocking while holding the GCLock

	unlocker := blocks.GCLock()
	defer unlocker.Unlock()

	for _, c := range cids {
		// Kept for backwards compatibility. We may want to
		// remove this sometime in the future.

		/*
			has, err := blocks.Has(c)
			if err != nil {
				out <- &RemovedBlock{Hash: c.String(), Error: err.Error()}
				continue
			}
			if !has && !opts.Force {
				out <- &RemovedBlock{Hash: c.String(), Error: bs.ErrNotFound.Error()}
				continue
			}*/

		err := blocks.DeleteBlock(c)
		if err != nil {
			n.Listener.Error(err.Error())
		} else {
			n.Listener.Info("Remove Block : " + c.String())
		}
	}

	return nil
}

func ResolveNode(ctx context.Context, dag ipld.NodeGetter, p path.Path) (ipld.Node, error) {
	rp, err := ResolvePath(ctx, dag, p)
	if err != nil {
		return nil, err
	}

	node, err := dag.Get(ctx, rp.Cid())
	if err != nil {
		return nil, err
	}
	return node, nil
}

// WriteRefs writes refs of the given object to the underlying writer.
func (rw *RefWriter) EvalRefs(n ipld.Node, enc cidenc.Encoder) (int, error) {
	return rw.evalRefsRecursive(n, 0, enc)
}

func (rw *RefWriter) evalRefsRecursive(n ipld.Node, depth int, enc cidenc.Encoder) (int, error) {
	nc := n.Cid()

	var count int
	for i, ng := range ipld.GetDAG(rw.Ctx, rw.DAG, n) {
		lc := n.Links()[i].Cid
		goDeeper, shouldWrite := rw.visit(lc, depth+1) // The children are at depth+1

		// Avoid "Get()" on the node and continue with next Link.
		// We can do this if:
		// - We printed it before (thus it was already seen and
		//   fetched with Get()
		// - AND we must not go deeper.
		// This is an optimization for pruned branches which have been
		// visited before.
		if !shouldWrite && !goDeeper {
			continue
		}

		// We must Get() the node because:
		// - it is new (never written)
		// - OR we need to go deeper.
		// This ensures printed refs are always fetched.
		nd, err := ng.Get(rw.Ctx)
		if err != nil {
			return count, err
		}

		// Write this node if not done before (or !Unique)
		if shouldWrite {
			if err := rw.evalEdge(nc, lc, n.Links()[i].Name, enc); err != nil {
				return count, err
			}
			count++
		}

		// Keep going deeper. This happens:
		// - On unexplored branches
		// - On branches not explored deep enough
		// Note when !Unique, branches are always considered
		// unexplored and only depth limits apply.
		if goDeeper {
			c, err := rw.evalRefsRecursive(nd, depth+1, enc)
			count += c
			if err != nil {
				return count, err
			}
		}
	}

	return count, nil
}

// visit returns two values:
// - the first boolean is true if we should keep traversing the DAG
// - the second boolean is true if we should print the CID
//
// visit will do branch pruning depending on rw.MaxDepth, previously visited
// cids and whether rw.Unique is set. i.e. rw.Unique = false and
// rw.MaxDepth = -1 disables any pruning. But setting rw.Unique to true will
// prune already visited branches at the cost of keeping as set of visited
// CIDs in memory.
func (rw *RefWriter) visit(c cid.Cid, depth int) (bool, bool) {
	atMaxDepth := rw.MaxDepth >= 0 && depth == rw.MaxDepth
	overMaxDepth := rw.MaxDepth >= 0 && depth > rw.MaxDepth

	// Shortcut when we are over max depth. In practice, this
	// only applies when calling refs with --maxDepth=0, as root's
	// children are already over max depth. Otherwise nothing should
	// hit this.
	if overMaxDepth {
		return false, false
	}

	// We can shortcut right away if we don't need unique output:
	//   - we keep traversing when not atMaxDepth
	//   - always print
	if !rw.Unique {
		return !atMaxDepth, true
	}

	// Unique == true from this point.
	// Thus, we keep track of seen Cids, and their depth.
	if rw.seen == nil {
		rw.seen = make(map[string]int)
	}
	key := string(c.Bytes())
	oldDepth, ok := rw.seen[key]

	// Unique == true && depth < MaxDepth (or unlimited) from this point

	// Branch pruning cases:
	// - We saw the Cid before and either:
	//   - Depth is unlimited (MaxDepth = -1)
	//   - We saw it higher (smaller depth) in the DAG (means we must have
	//     explored deep enough before)
	// Because we saw the CID, we don't print it again.
	if ok && (rw.MaxDepth < 0 || oldDepth <= depth) {
		return false, false
	}

	// Final case, we must keep exploring the DAG from this CID
	// (unless we hit the depth limit).
	// We note down its depth because it was either not seen
	// or is lower than last time.
	// We print if it was not seen.
	rw.seen[key] = depth
	return !atMaxDepth, !ok
}

// Write one edge
func (rw *RefWriter) evalEdge(from, to cid.Cid, linkname string, enc cidenc.Encoder) error {
	if rw.Ctx != nil {
		select {
		case <-rw.Ctx.Done(): // just in case.
			return rw.Ctx.Err()
		default:
		}
	}

	rw.Paths = append(rw.Paths, enc.Encode(to))

	return nil
}
