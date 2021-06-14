/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package validation

import (
	"fmt"

	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric/core/ledger/internal/version"
	"github.com/hyperledger/fabric/core/ledger/kvledger/txmgmt/privacyenabledstate"
	"github.com/hyperledger/fabric/core/ledger/kvledger/txmgmt/rwsetutil"
	"github.com/hyperledger/fabric/core/ledger/kvledger/txmgmt/statedb"
	"github.com/pkg/errors"
)

var AtomicCommitTimeout uint64 = 10 //num of blocks

// block is used to used to hold the information from its proto format to a structure
// that is more suitable/friendly for validation
type block struct {
	num uint64
	txs []*transaction
}

// transaction is used to hold the information from its proto format to a structure
// that is more suitable/friendly for validation
type transaction struct {
	indexInBlock            int
	id                      string
	rwset                   *rwsetutil.TxRwSet
	validationCode          peer.TxValidationCode
	containsPostOrderWrites bool
	headerType              common.HeaderType
}

// publicAndHashUpdates encapsulates public and hash updates. The intended use of this to hold the updates
// that are to be applied to the statedb  as a result of the block commit
type publicAndHashUpdates struct {
	publicUpdates *privacyenabledstate.PubUpdateBatch
	hashUpdates   *privacyenabledstate.HashedUpdateBatch
}

// newPubAndHashUpdates constructs an empty PubAndHashUpdates
func newPubAndHashUpdates() *publicAndHashUpdates {
	return &publicAndHashUpdates{
		privacyenabledstate.NewPubUpdateBatch(),
		privacyenabledstate.NewHashedUpdateBatch(),
	}
}

// containsPvtWrites returns true if this transaction is not limited to affecting the public data only
func (t *transaction) containsPvtWrites() bool {
	for _, ns := range t.rwset.NsRwSets {
		for _, coll := range ns.CollHashedRwSets {
			if coll.PvtRwSetHash != nil {
				return true
			}
		}
	}
	return false
}

// retrieveHash returns the hash of the private write-set present
// in the public data for a given namespace-collection
func (t *transaction) retrieveHash(ns string, coll string) []byte {
	if t.rwset == nil {
		return nil
	}
	for _, nsData := range t.rwset.NsRwSets {
		if nsData.NameSpace != ns {
			continue
		}

		for _, collData := range nsData.CollHashedRwSets {
			if collData.CollectionName == coll {
				return collData.PvtRwSetHash
			}
		}
	}
	return nil
}

// applyWriteSet adds (or deletes) the key/values present in the write set to the publicAndHashUpdates
func (u *publicAndHashUpdates) applyWriteSet(
	txRWSet *rwsetutil.TxRwSet,
	txHeight *version.Height,
	db *privacyenabledstate.DB,
	containsPostOrderWrites bool,
	decideTxApproved bool,
	blockNum uint64,
) error {
	errTest := errors.New("program in the aplyWriteSet() function")
	fmt.Printf("test: %s", errTest.Error())

	u.publicUpdates.ContainsPostOrderWrites =
		u.publicUpdates.ContainsPostOrderWrites || containsPostOrderWrites
	txops, err := prepareTxOps(txRWSet, u, db)
	logger.Debugf("txops=%#v", txops)
	if err != nil {
		return err
	}
	for compositeKey, keyops := range txops {
		if compositeKey.coll == "" {
			ns, key := compositeKey.ns, compositeKey.key

			//check if a user-chaincode key taking part in private atomic commit
			if ns != "" && ns != "lscc" && ns != "qscc" && ns != "cscc" && ns != "_lifecycle" {
				verValue, err := db.GetState(ns, key)
				if verValue != nil && err == nil {
					logger.Debugf("verValue.PACparticipationFlag: [%d] verValue = [%s] / [%v]", verValue.Version.PACparticipationFlag, verValue, verValue)
					if verValue.Version.PACparticipationFlag != 0 {
						logger.Debugf("before checking PACparticipationFlag and decideTxApproved flags")
						if verValue.Version.PACparticipationFlag+AtomicCommitTimeout < blockNum {
							logger.Warningf("Atomic commit timeout! Key [%s] was locked in block [%d], but now was got block [%d]", key, verValue.Version.PACparticipationFlag, blockNum)
							//unlocking PACparticipationFlag and putting it to batch
							u.putUnlockedWSetKeyToBatch(verValue, ns, key)
						} else if verValue.Version.PACparticipationFlag != 0 && !decideTxApproved {
							logger.Warningf("PACparticipationFlag != 0 -> Transaction skipping")
							return errors.New("PACparticipationFlag != 0")
						}
					}
					logger.Warningf("after checking PACparticipationFlag")
				} else {
					logger.Warningf("verValue = %+v and err = %+v", verValue, err)
				}
			}

			if keyops.isDelete() {
				u.publicUpdates.Delete(ns, key, txHeight)
			} else {
				logger.Debugf("PutValAndMetadata calling... ")
				u.publicUpdates.PutValAndMetadata(ns, key, keyops.value, keyops.metadata, txHeight)
			}
		} else {
			ns, coll, keyHash := compositeKey.ns, compositeKey.coll, []byte(compositeKey.key)
			if keyops.isDelete() {
				u.hashUpdates.Delete(ns, coll, keyHash, txHeight)
			} else {
				u.hashUpdates.PutValHashAndMetadata(ns, coll, keyHash, keyops.value, keyops.metadata, txHeight)
			}
		}
	}
	return nil
}

//putUnlockedWSetKeyToBatch unlocks PACparticipationFlag and puts given VersionedValue to the batch
func (u *publicAndHashUpdates) putUnlockedWSetKeyToBatch(verValue *statedb.VersionedValue, ns string, key string) {
	verValue.Version.PACparticipationFlag = 0
	u.publicUpdates.PutValAndMetadata(ns, key, verValue.Value, verValue.Metadata, verValue.Version)
	logger.Debugf("VersionedValue.PACparticipationFlag for ns [%s] data [%s] was set to [%v]", ns, string(verValue.Value), verValue.Version.PACparticipationFlag)
	logger.Debugf("batch.Updates[ns]: [%+v] / [%s] ", u.publicUpdates.Updates[ns], u.publicUpdates.Updates[ns])
	logger.Debugf("unlocked PACparticipationFlag for key [%s] successfully put to batch", key)
}
