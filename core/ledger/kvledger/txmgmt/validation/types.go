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
	"github.com/pkg/errors"
)

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
				verValue := u.publicUpdates.Get(ns, key)
				if verValue != nil {
					logger.Warningf("before checking PACparticipationFlag")
					if verValue.Version.PACparticipationFlag == true {
						logger.Warningf("PACparticipationFlag = true")
						return errors.New("PACparticipationFlag = true")
					}
					logger.Warningf("after checking PACparticipationFlag")
				}
				logger.Warningf("verValue = nil")
				/*keyHeight, err := db.GetVersion(ns, key)
				if err != nil {
					fmt.Printf("error during getting version: %s", err.Error())
					return err
				}
				if keyHeight.PACparticipationFlag == true {
					return errors.New("PACparticipationFlag = true")
				}*/
			}

			if keyops.isDelete() {
				u.publicUpdates.Delete(ns, key, txHeight)
			} else {
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
