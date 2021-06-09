/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package version

import (
	"fmt"

	"github.com/hyperledger/fabric/common/ledger/util"
	//TODO: remove this after successful debug
	"github.com/hyperledger/fabric/common/flogging"
)

var logger = flogging.MustGetLogger("versionheight")

// Height represents the height of a transaction in blockchain
type Height struct {
	BlockNum uint64
	TxNum    uint64
	//the true key means that the value is locked due to changes
	//are making by a private atomic commit
	PACparticipationFlag bool
}

// NewHeight constructs a new instance of Height
func NewHeight(blockNum, txNum uint64) *Height {
	return &Height{blockNum, txNum, false}
}

// NewHeightWithPACFlag constructs a new instance of Height with set PACparticipationFlag
func NewHeightWithPACFlag(blockNum, txNum uint64, pacParticipationFlag bool) *Height {
	return &Height{blockNum, txNum, pacParticipationFlag}
}

// NewHeightFromBytes constructs a new instance of Height from serialized bytes
func NewHeightFromBytes(b []byte) (*Height, int, error) {
	blockNum, n1, err := util.DecodeOrderPreservingVarUint64(b)
	if err != nil {
		return nil, -1, err
	}
	txNum, n2, err := util.DecodeOrderPreservingVarUint64(b[n1:])
	if err != nil {
		return nil, -1, err
	}
	//checking if the PACParticipationFlag is set in the end of serialized bytes
	//we have to read remaining bytes after blockNum and txNum bytes (so, n1+n2)
	if string(b[n1+n2:]) != "" {
		logger.Debugf("in the condition to check PACParticipationFlag, b[n2:] is: [%s]\n", b[n2:])
		//decode here last part of bytes and return the Height with the value of PACParticipationFlag
		pacParticipationFlag, n3, err := util.DecodeOrderPreservingVarUint64(b[n1+n2:])
		if err != nil {
			return nil, -1, err
		}
		logger.Debugf("pacParticipationFlag is: [%d]", pacParticipationFlag)
		if pacParticipationFlag == 1 {
			return NewHeightWithPACFlag(blockNum, txNum, true), n1 + n2 + n3, nil
		} else {
			return NewHeightWithPACFlag(blockNum, txNum, false), n1 + n2 + n3, nil
		}

	} else {
		//return height with PACParticipationFlag which is set to false by default
		return NewHeight(blockNum, txNum), n1 + n2, nil
	}
}

// ToBytes serializes the Height
func (h *Height) ToBytes() []byte {
	blockNumBytes := util.EncodeOrderPreservingVarUint64(h.BlockNum)
	txNumBytes := util.EncodeOrderPreservingVarUint64(h.TxNum)

	//add PACparticipation flag to serialized bytes (if it is true)
	logger.Debugf("before checking and the h.PACparticipationFlag is: [%t]", h.PACparticipationFlag)
	if h.PACparticipationFlag {
		logger.Debugf("in condition")
		PACTrue := util.EncodeOrderPreservingVarUint64(1)
		txNumBytes = append(txNumBytes, PACTrue...)
	}
	logger.Debugf("ToBytes() result: [%+v]", append(blockNumBytes, txNumBytes...))
	return append(blockNumBytes, txNumBytes...)
}

// Compare return a -1, zero, or +1 based on whether this height is
// less than, equals to, or greater than the specified height respectively.
func (h *Height) Compare(h1 *Height) int {
	res := 0
	switch {
	case h.BlockNum != h1.BlockNum:
		res = int(h.BlockNum - h1.BlockNum)
	case h.TxNum != h1.TxNum:
		res = int(h.TxNum - h1.TxNum)
	default:
		return 0
	}
	if res > 0 {
		return 1
	}
	return -1
}

// String returns string for printing
func (h *Height) String() string {
	if h == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{BlockNum: %d, TxNum: %d, PACParticipationFlag: %t}", h.BlockNum, h.TxNum, h.PACparticipationFlag)
}

// AreSame returns true if both the heights are either nil or equal
func AreSame(h1 *Height, h2 *Height) bool {
	if h1 == nil {
		return h2 == nil
	}
	if h2 == nil {
		return false
	}
	return h1.Compare(h2) == 0
}
