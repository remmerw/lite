package lite

import (
	"time"

	ds "github.com/ipfs/go-datastore"
	dsq "github.com/ipfs/go-datastore/query"
)

type Datastore struct {
	Listener Listener
}

func (d *Datastore) Sync(ds.Key) error {
	return nil
}

type txn struct {
	ds *Datastore
}

func (t *txn) Sync(ds.Key) error {
	return nil
}

var _ ds.Datastore = (*Datastore)(nil)
var _ ds.TxnDatastore = (*Datastore)(nil)
var _ ds.TTLDatastore = (*Datastore)(nil)

// NewDatastore creates a new badger datastore.
//
// DO NOT set the Dir and/or ValuePath fields of opt, they will be set for you.
func NewDatastore(listener Listener) *Datastore {
	return &Datastore{Listener: listener}
}

// NewTransaction starts a new transaction. The resulting transaction object
// can be mutated without incurring changes to the underlying DataStore until
// the transaction is Committed.
func (d *Datastore) NewTransaction(bool) (ds.Txn, error) {
	return &txn{d}, nil
}

func (d *Datastore) Put(key ds.Key, value []byte) error {
	d.Listener.BlockPut(key.String(), value)
	return nil
}

func (d *Datastore) PutWithTTL(key ds.Key, value []byte, ttl time.Duration) error {
	d.Listener.Error("put with ttl .... ")
	d.Listener.BlockPut(key.String(), value)
	return nil
}

func (d *Datastore) SetTTL(key ds.Key, ttl time.Duration) error {
	d.Listener.Error("set ttl .... ")
	return nil
}

func (d *Datastore) GetExpiration(key ds.Key) (time.Time, error) {
	d.Listener.Error("get expiration .... ")
	return time.Now().Add(time.Hour), nil
}

func (d *Datastore) Get(key ds.Key) (value []byte, err error) {
	data := d.Listener.BlockGet(key.String())

	if data == nil {
		return data, ds.ErrNotFound
	}
	return data, nil
}

func (d *Datastore) Has(key ds.Key) (bool, error) {

	return d.Listener.BlockHas(key.String()), nil
}

func (d *Datastore) GetSize(key ds.Key) (size int, err error) {

	return d.Listener.BlockSize(key.String()), nil
}

func (d *Datastore) Delete(key ds.Key) error {
	d.Listener.BlockDelete(key.String())
	return nil
}

func (d *Datastore) Query(q dsq.Query) (dsq.Results, error) {
	panic("query should be called")
	return nil, nil
}

// DiskUsage implements the PersistentDatastore interface.
// It returns the sum of lsm and value log files sizes in bytes.
func (d *Datastore) DiskUsage() (uint64, error) {
	return 0, nil
}

func (d *Datastore) Close() error {
	return nil
}

func (d *Datastore) Batch() (ds.Batch, error) {
	tx, _ := d.NewTransaction(false)
	return tx, nil
}

var _ ds.Datastore = (*txn)(nil)
var _ ds.TTLDatastore = (*txn)(nil)

func (t *txn) Put(key ds.Key, value []byte) error {
	return t.ds.Put(key, value)
}

func (t *txn) PutWithTTL(key ds.Key, value []byte, ttl time.Duration) error {
	return t.ds.PutWithTTL(key, value, ttl)
}

func (t *txn) GetExpiration(key ds.Key) (time.Time, error) {
	return t.ds.GetExpiration(key)
}

func (t *txn) SetTTL(key ds.Key, ttl time.Duration) error {
	return t.ds.SetTTL(key, ttl)
}

func (t *txn) Get(key ds.Key) ([]byte, error) {
	return t.ds.Get(key)
}

func (t *txn) Has(key ds.Key) (bool, error) {
	return t.ds.Has(key)
}

func (t *txn) GetSize(key ds.Key) (int, error) {
	return t.ds.GetSize(key)
}

func (t *txn) Delete(key ds.Key) error {
	return t.ds.Delete(key)
}

func (t *txn) Query(q dsq.Query) (dsq.Results, error) {
	return t.ds.Query(q)
}

func (t *txn) Commit() error {

	return nil
}

// Alias to commit
func (t *txn) Close() error {

	return t.close()
}

func (t *txn) close() error {
	return nil
}

func (t *txn) Discard() {

}
