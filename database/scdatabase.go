// Copyright 2015 Factom Foundation
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package database

import (
	"github.com/FactomProject/factoid"
)

type FDatabase struct {
	backer       IFDatabase // We can have backing databases.  For now this will be nil
	persist      IFDatabase // We do need LevelDB or Bolt.  It would go here.
	doNotPersist map[string][]byte
	doNotCache   map[string][]byte
}

var _ IFDatabase = (*FDatabase)(nil)

// Do not hold objects in this cache in memory.  They are too big, and there
// is no interesting reason to keep them in memory.
func (db FDatabase) DoNotCache(bucket string) {
	if db.doNotCache == nil {
		db.doNotCache = make(map[string][]byte, 5)
	}
	db.doNotCache[bucket] = []byte(bucket)
	if db.backer != nil {
		db.backer.DoNotCache(bucket)
	}
	if db.persist != nil {
		db.persist.DoNotCache(bucket)
	}
}

// Do not write to disk.  These items are small, we need fast writes, and we don't need
// the overhead of writing to disk.
func (db FDatabase) DoNotPersist(bucket string) {
	if db.doNotPersist == nil {
		db.doNotPersist = make(map[string][]byte, 5)
	}
	db.doNotPersist[bucket] = []byte(bucket)
	if db.backer != nil {
		db.backer.DoNotPersist(bucket)
	}
	if db.persist != nil {
		db.persist.DoNotPersist(bucket)
	}
}

// A Backer database allows the implementation of a least recently
// used cache to purge data from memory.
func (db *FDatabase) SetBacker(b IFDatabase) {
	db.backer = b

	//TODO We should tell our backer about our DoNotCache and DoNotPersist maps.  We
	//don't now, but all we have to do is set up the databases first.
}
func (db FDatabase) GetBacker() IFDatabase {
	return db.backer
}

// A Persist database is needed to persist writes.  This is where
// one can hook up a LevelDB or Bolt database.
func (db *FDatabase) SetPersist(p IFDatabase) {
	db.persist = p

	//TODO We should tell our backer about our DoNotCache and DoNotPersist maps.  We
	//don't now, but all we have to do is set up the databases first.

}
func (db FDatabase) GetPersist() IFDatabase {
	return db.persist
}

/*****************************************************************
 * Database Key for Key/Value Databases that don't support buckets
 *****************************************************************/

type IDBKey interface {
	GetBucket() []byte
	GetKey() []byte
}

type DBKey struct {
	bucket [factoid.ADDRESS_LENGTH]byte
	key    [factoid.KEY_LIMIT]byte
}

var _ IDBKey = (*DBKey)(nil)

func (k DBKey) GetBucket() []byte {
	return k.bucket[:]
}

func (k DBKey) GetKey() []byte {
	return k.key[:]
}

func makeKey(bucket []byte, key []byte) IDBKey {

	if len(bucket) > factoid.ADDRESS_LENGTH || len(key) > factoid.KEY_LIMIT {
		panic("Key or bucket provided to IFDatabase is too long")
	}

	k := new(DBKey)
	copy(k.bucket[:], bucket)
	copy(k.key[:], key)

	return k
}
