package lite

func (n *Node) RepoGC() error {

again:
	err := n.Badger.RunValueLogGC(0.125)
	if err == nil {
		goto again
	}

	return err
}
