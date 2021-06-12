/*
Copyright IBM Corp. 2016 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package endorser

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/common"
	pb "github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric-protos-go/transientstore"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/common/util"
	"github.com/hyperledger/fabric/core/chaincode/lifecycle"
	"github.com/hyperledger/fabric/core/common/ccprovider"
	"github.com/hyperledger/fabric/core/ledger"
	"github.com/hyperledger/fabric/internal/pkg/identity"
	"github.com/hyperledger/fabric/msp"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

var endorserLogger = flogging.MustGetLogger("endorser")

// The Jira issue that documents Endorser flow along with its relationship to
// the lifecycle chaincode - https://jira.hyperledger.org/browse/FAB-181

//go:generate counterfeiter -o fake/prvt_data_distributor.go --fake-name PrivateDataDistributor . PrivateDataDistributor

type PrivateDataDistributor interface {
	DistributePrivateData(channel string, txID string, privateData *transientstore.TxPvtReadWriteSetWithConfigInfo, blkHt uint64) error
}

type PACInfo struct {
	Shard              string
	HashedVsr          string
	HashedNsr          string
	EncryptedVsr       string
	EncryptedNsr       string
	WholeShardResponse string //based64 TODO: decide does we need this variable?
}

//VsrNsrPair is pair of hashes returned from endorser peer to form PrepareTx
type VsrNsrPair struct {
	//Vsr endorser shard response (hashed positive response)
	Vsr []byte
	//Nsr endorser shard response (hashed negative response)
	Nsr []byte
}

// Support contains functions that the endorser requires to execute its tasks
type Support interface {
	identity.SignerSerializer
	// GetTxSimulator returns the transaction simulator for the specified ledger
	// a client may obtain more than one such simulator; they are made unique
	// by way of the supplied txid
	GetTxSimulator(ledgername string, txid string) (ledger.TxSimulator, error)

	// GetHistoryQueryExecutor gives handle to a history query executor for the
	// specified ledger
	GetHistoryQueryExecutor(ledgername string) (ledger.HistoryQueryExecutor, error)

	// GetTransactionByID retrieves a transaction by id
	GetTransactionByID(chid, txID string) (*pb.ProcessedTransaction, error)

	// IsSysCC returns true if the name matches a system chaincode's
	// system chaincode names are system, chain wide
	IsSysCC(name string) bool

	// Execute - execute proposal, return original response of chaincode
	Execute(txParams *ccprovider.TransactionParams, name string, input *pb.ChaincodeInput) (*pb.Response, *pb.ChaincodeEvent, error)

	// ExecuteLegacyInit - executes a deployment proposal, return original response of chaincode
	ExecuteLegacyInit(txParams *ccprovider.TransactionParams, name, version string, spec *pb.ChaincodeInput) (*pb.Response, *pb.ChaincodeEvent, error)

	// ChaincodeEndorsementInfo returns the information from lifecycle required to endorse the chaincode.
	ChaincodeEndorsementInfo(channelID, chaincodeID string, txsim ledger.QueryExecutor) (*lifecycle.ChaincodeEndorsementInfo, error)

	// CheckACL checks the ACL for the resource for the channel using the
	// SignedProposal from which an id can be extracted for testing against a policy
	CheckACL(channelID string, signedProp *pb.SignedProposal) error

	// EndorseWithPlugin endorses the response with a plugin
	EndorseWithPlugin(pluginName, channnelID string, prpBytes []byte, signedProposal *pb.SignedProposal) (*pb.Endorsement, []byte, error)

	// GetLedgerHeight returns ledger height for given channelID
	GetLedgerHeight(channelID string) (uint64, error)

	// GetDeployedCCInfoProvider returns ledger.DeployedChaincodeInfoProvider
	GetDeployedCCInfoProvider() ledger.DeployedChaincodeInfoProvider
}

//go:generate counterfeiter -o fake/channel_fetcher.go --fake-name ChannelFetcher . ChannelFetcher

// ChannelFetcher fetches the channel context for a given channel ID.
type ChannelFetcher interface {
	Channel(channelID string) *Channel
}

type Channel struct {
	IdentityDeserializer msp.IdentityDeserializer
}

// Endorser provides the Endorser service ProcessProposal
type Endorser struct {
	ChannelFetcher         ChannelFetcher
	LocalMSP               msp.IdentityDeserializer
	PrivateDataDistributor PrivateDataDistributor
	Support                Support
	PvtRWSetAssembler      PvtRWSetAssembler
	Metrics                *Metrics
}

// call specified chaincode (system or user)
func (e *Endorser) callChaincode(txParams *ccprovider.TransactionParams, input *pb.ChaincodeInput, chaincodeName string) (*pb.Response, *pb.ChaincodeEvent, error) {
	defer func(start time.Time) {
		logger := endorserLogger.WithOptions(zap.AddCallerSkip(1))
		logger = decorateLogger(logger, txParams)
		elapsedMillisec := time.Since(start).Milliseconds()
		logger.Infof("finished chaincode: %s duration: %dms", chaincodeName, elapsedMillisec)
	}(time.Now())

	meterLabels := []string{
		"channel", txParams.ChannelID,
		"chaincode", chaincodeName,
	}

	res, ccevent, err := e.Support.Execute(txParams, chaincodeName, input)
	if err != nil {
		e.Metrics.SimulationFailure.With(meterLabels...).Add(1)
		return nil, nil, err
	}

	// per doc anything < 400 can be sent as TX.
	// fabric errors will always be >= 400 (ie, unambiguous errors )
	// "lscc" will respond with status 200 or 500 (ie, unambiguous OK or ERROR)
	if res.Status >= shim.ERRORTHRESHOLD {
		return res, nil, nil
	}

	// Unless this is the weirdo LSCC case, just return
	if chaincodeName != "lscc" || len(input.Args) < 3 || (string(input.Args[0]) != "deploy" && string(input.Args[0]) != "upgrade") {
		return res, ccevent, nil
	}

	// ----- BEGIN -  SECTION THAT MAY NEED TO BE DONE IN LSCC ------
	// if this a call to deploy a chaincode, We need a mechanism
	// to pass TxSimulator into LSCC. Till that is worked out this
	// special code does the actual deploy, upgrade here so as to collect
	// all state under one TxSimulator
	//
	// NOTE that if there's an error all simulation, including the chaincode
	// table changes in lscc will be thrown away
	cds, err := protoutil.UnmarshalChaincodeDeploymentSpec(input.Args[2])
	if err != nil {
		e.Metrics.SimulationFailure.With(meterLabels...).Add(1)
		return nil, nil, err
	}

	// this should not be a system chaincode
	if e.Support.IsSysCC(cds.ChaincodeSpec.ChaincodeId.Name) {
		e.Metrics.SimulationFailure.With(meterLabels...).Add(1)
		return nil, nil, errors.Errorf("attempting to deploy a system chaincode %s/%s", cds.ChaincodeSpec.ChaincodeId.Name, txParams.ChannelID)
	}

	if len(cds.CodePackage) != 0 {
		e.Metrics.SimulationFailure.With(meterLabels...).Add(1)
		return nil, nil, errors.Errorf("lscc upgrade/deploy should not include a code packages")
	}

	_, _, err = e.Support.ExecuteLegacyInit(txParams, cds.ChaincodeSpec.ChaincodeId.Name, cds.ChaincodeSpec.ChaincodeId.Version, cds.ChaincodeSpec.Input)
	if err != nil {
		// increment the failure to indicate instantion/upgrade failures
		meterLabels = []string{
			"channel", txParams.ChannelID,
			"chaincode", cds.ChaincodeSpec.ChaincodeId.Name,
		}
		e.Metrics.InitFailed.With(meterLabels...).Add(1)
		return nil, nil, err
	}

	return res, ccevent, err
}

// SimulateProposal simulates the proposal by calling the chaincode
func (e *Endorser) SimulateProposal(txParams *ccprovider.TransactionParams, chaincodeName string, chaincodeInput *pb.ChaincodeInput) (*pb.Response, []byte, *pb.ChaincodeEvent, error) {
	logger := decorateLogger(endorserLogger, txParams)

	meterLabels := []string{
		"channel", txParams.ChannelID,
		"chaincode", chaincodeName,
	}

	// ---3. execute the proposal and get simulation results
	res, ccevent, err := e.callChaincode(txParams, chaincodeInput, chaincodeName)
	if err != nil {
		logger.Errorf("failed to invoke chaincode %s, error: %+v", chaincodeName, err)
		return nil, nil, nil, err
	}

	if txParams.TXSimulator == nil {
		return res, nil, ccevent, nil
	}

	// Note, this is a little goofy, as if there is private data, Done() gets called
	// early, so this is invoked multiple times, but that is how the code worked before
	// this change, so, should be safe.  Long term, let's move the Done up to the create.
	defer txParams.TXSimulator.Done()

	simResult, err := txParams.TXSimulator.GetTxSimulationResults()
	if err != nil {
		e.Metrics.SimulationFailure.With(meterLabels...).Add(1)
		return nil, nil, nil, err
	}

	if simResult.PvtSimulationResults != nil {
		if chaincodeName == "lscc" {
			// TODO: remove once we can store collection configuration outside of LSCC
			e.Metrics.SimulationFailure.With(meterLabels...).Add(1)
			return nil, nil, nil, errors.New("Private data is forbidden to be used in instantiate")
		}
		pvtDataWithConfig, err := AssemblePvtRWSet(txParams.ChannelID, simResult.PvtSimulationResults, txParams.TXSimulator, e.Support.GetDeployedCCInfoProvider())
		// To read collection config need to read collection updates before
		// releasing the lock, hence txParams.TXSimulator.Done()  moved down here
		txParams.TXSimulator.Done()

		if err != nil {
			e.Metrics.SimulationFailure.With(meterLabels...).Add(1)
			return nil, nil, nil, errors.WithMessage(err, "failed to obtain collections config")
		}
		endorsedAt, err := e.Support.GetLedgerHeight(txParams.ChannelID)
		if err != nil {
			e.Metrics.SimulationFailure.With(meterLabels...).Add(1)
			return nil, nil, nil, errors.WithMessage(err, fmt.Sprintf("failed to obtain ledger height for channel '%s'", txParams.ChannelID))
		}
		// Add ledger height at which transaction was endorsed,
		// `endorsedAt` is obtained from the block storage and at times this could be 'endorsement Height + 1'.
		// However, since we use this height only to select the configuration (3rd parameter in distributePrivateData) and
		// manage transient store purge for orphaned private writesets (4th parameter in distributePrivateData), this works for now.
		// Ideally, ledger should add support in the simulator as a first class function `GetHeight()`.
		pvtDataWithConfig.EndorsedAt = endorsedAt
		if err := e.PrivateDataDistributor.DistributePrivateData(txParams.ChannelID, txParams.TxID, pvtDataWithConfig, endorsedAt); err != nil {
			e.Metrics.SimulationFailure.With(meterLabels...).Add(1)
			return nil, nil, nil, err
		}
	}

	pubSimResBytes, err := simResult.GetPubSimulationBytes()
	if err != nil {
		e.Metrics.SimulationFailure.With(meterLabels...).Add(1)
		return nil, nil, nil, err
	}

	return res, pubSimResBytes, ccevent, nil
}

// preProcess checks the tx proposal headers, uniqueness and ACL
func (e *Endorser) preProcess(up *UnpackedProposal, channel *Channel) error {
	// at first, we check whether the message is valid

	err := up.Validate(channel.IdentityDeserializer)
	if err != nil {
		e.Metrics.ProposalValidationFailed.Add(1)
		return errors.WithMessage(err, "error validating proposal")
	}

	if up.ChannelHeader.ChannelId == "" {
		// chainless proposals do not/cannot affect ledger and cannot be submitted as transactions
		// ignore uniqueness checks; also, chainless proposals are not validated using the policies
		// of the chain since by definition there is no chain; they are validated against the local
		// MSP of the peer instead by the call to ValidateUnpackProposal above
		return nil
	}

	// labels that provide context for failure metrics
	meterLabels := []string{
		"channel", up.ChannelHeader.ChannelId,
		"chaincode", up.ChaincodeName,
	}

	// Here we handle uniqueness check and ACLs for proposals targeting a chain
	// Notice that ValidateProposalMessage has already verified that TxID is computed properly
	if _, err = e.Support.GetTransactionByID(up.ChannelHeader.ChannelId, up.ChannelHeader.TxId); err == nil {
		// increment failure due to duplicate transactions. Useful for catching replay attacks in
		// addition to benign retries
		e.Metrics.DuplicateTxsFailure.With(meterLabels...).Add(1)
		return errors.Errorf("duplicate transaction found [%s]. Creator [%x]", up.ChannelHeader.TxId, up.SignatureHeader.Creator)
	}

	// check ACL only for application chaincodes; ACLs
	// for system chaincodes are checked elsewhere
	if !e.Support.IsSysCC(up.ChaincodeName) {
		// check that the proposal complies with the Channel's writers
		if err = e.Support.CheckACL(up.ChannelHeader.ChannelId, up.SignedProposal); err != nil {
			e.Metrics.ProposalACLCheckFailed.With(meterLabels...).Add(1)
			return err
		}
	}

	return nil
}

// ProcessProposal process the Proposal
func (e *Endorser) ProcessProposal(ctx context.Context, signedProp *pb.SignedProposal) (*pb.ProposalResponse, error) {
	// start time for computing elapsed time metric for successfully endorsed proposals
	startTime := time.Now()
	e.Metrics.ProposalsReceived.Add(1)

	addr := util.ExtractRemoteAddress(ctx)
	endorserLogger.Debug("request from", addr)

	// variables to capture proposal duration metric
	success := false

	up, err := UnpackProposal(signedProp)
	if err != nil {
		e.Metrics.ProposalValidationFailed.Add(1)
		return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: err.Error()}}, err
	}

	var channel *Channel
	if up.ChannelID() != "" {
		channel = e.ChannelFetcher.Channel(up.ChannelID())
		if channel == nil {
			return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: fmt.Sprintf("channel '%s' not found", up.ChannelHeader.ChannelId)}}, nil
		}
	} else {
		channel = &Channel{
			IdentityDeserializer: e.LocalMSP,
		}
	}

	// 0 -- check and validate
	err = e.preProcess(up, channel)
	if err != nil {
		return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: err.Error()}}, err
	}

	defer func() {
		meterLabels := []string{
			"channel", up.ChannelHeader.ChannelId,
			"chaincode", up.ChaincodeName,
			"success", strconv.FormatBool(success),
		}
		e.Metrics.ProposalDuration.With(meterLabels...).Observe(time.Since(startTime).Seconds())
	}()

	pResp, err := e.ProcessProposalSuccessfullyOrError(up)
	if err != nil {
		endorserLogger.Warnw("Failed to invoke chaincode", "channel", up.ChannelHeader.ChannelId, "chaincode", up.ChaincodeName, "error", err.Error())
		return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: err.Error()}}, nil
	}

	if pResp.Endorsement != nil || up.ChannelHeader.ChannelId == "" {
		// We mark the tx as successful only if it was successfully endorsed, or
		// if it was a system chaincode on a channel-less channel and therefore
		// cannot be endorsed.
		success = true

		// total failed proposals = ProposalsReceived-SuccessfulProposals
		e.Metrics.SuccessfulProposals.Add(1)
	}
	return pResp, nil
}

func (e *Endorser) ProcessProposalSuccessfullyOrError(up *UnpackedProposal) (*pb.ProposalResponse, error) {
	txParams := &ccprovider.TransactionParams{
		ChannelID:  up.ChannelHeader.ChannelId,
		TxID:       up.ChannelHeader.TxId,
		SignedProp: up.SignedProposal,
		Proposal:   up.Proposal,
	}

	logger := decorateLogger(endorserLogger, txParams)

	if acquireTxSimulator(up.ChannelHeader.ChannelId, up.ChaincodeName) {
		txSim, err := e.Support.GetTxSimulator(up.ChannelID(), up.TxID())
		if err != nil {
			return nil, err
		}

		// txsim acquires a shared lock on the stateDB. As this would impact the block commits (i.e., commit
		// of valid write-sets to the stateDB), we must release the lock as early as possible.
		// Hence, this txsim object is closed in simulateProposal() as soon as the tx is simulated and
		// rwset is collected before gossip dissemination if required for privateData. For safety, we
		// add the following defer statement and is useful when an error occur. Note that calling
		// txsim.Done() more than once does not cause any issue. If the txsim is already
		// released, the following txsim.Done() simply returns.
		defer txSim.Done()

		hqe, err := e.Support.GetHistoryQueryExecutor(up.ChannelID())
		if err != nil {
			return nil, err
		}

		txParams.TXSimulator = txSim
		txParams.HistoryQueryExecutor = hqe
	}

	cdLedger, err := e.Support.ChaincodeEndorsementInfo(up.ChannelID(), up.ChaincodeName, txParams.TXSimulator)
	if err != nil {
		return nil, errors.WithMessagef(err, "make sure the chaincode %s has been successfully defined on channel %s and try again", up.ChaincodeName, up.ChannelID())
	}

	// 1 -- simulate
	res, simulationResult, ccevent, err := e.SimulateProposal(txParams, up.ChaincodeName, up.Input)
	if err != nil {
		return nil, errors.WithMessage(err, "error in simulation")
	}

	cceventBytes, err := CreateCCEventBytes(ccevent)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal chaincode event")
	}

	prpBytes, err := protoutil.GetBytesProposalResponsePayload(up.ProposalHash, res, simulationResult, cceventBytes, &pb.ChaincodeID{
		Name:    up.ChaincodeName,
		Version: cdLedger.Version,
	})
	if err != nil {
		logger.Warning("Failed marshaling the proposal response payload to bytes", err)
		return nil, errors.WithMessage(err, "failed to create the proposal response")
	}

	// if error, capture endorsement failure metric
	meterLabels := []string{
		"channel", up.ChannelID(),
		"chaincode", up.ChaincodeName,
	}

	switch {
	case res.Status >= shim.ERROR:
		return &pb.ProposalResponse{
			Response: res,
			Payload:  prpBytes,
		}, nil
	case up.ChannelID() == "":
		// Chaincode invocations without a channel ID is a broken concept
		// that should be removed in the future.  For now, return unendorsed
		// success.
		return &pb.ProposalResponse{
			Response: res,
		}, nil
	case res.Status >= shim.ERRORTHRESHOLD:
		meterLabels = append(meterLabels, "chaincodeerror", strconv.FormatBool(true))
		e.Metrics.EndorsementsFailed.With(meterLabels...).Add(1)
		logger.Debugf("chaincode error %d", res.Status)
		return &pb.ProposalResponse{
			Response: res,
		}, nil
	}

	escc := cdLedger.EndorsementPlugin

	logger.Debugf("escc for chaincode %s is %s", up.ChaincodeName, escc)

	// Note, mPrpBytes is the same as prpBytes by default endorsement plugin, but others could change it.
	endorsement, mPrpBytes, err := e.Support.EndorseWithPlugin(escc, up.ChannelID(), prpBytes, up.SignedProposal)
	if err != nil {
		meterLabels = append(meterLabels, "chaincodeerror", strconv.FormatBool(false))
		e.Metrics.EndorsementsFailed.With(meterLabels...).Add(1)
		return nil, errors.WithMessage(err, "endorsement with plugin failed")
	}

	//endorse PAC requests and messages
	ccPropPayl, err := protoutil.UnmarshalChaincodeProposalPayload(txParams.Proposal.Payload)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to get ChaincodeProposalPayload to check if it is PAC-request")
	}
	//check if it is a request for PAC
	if _, ok := ccPropPayl.TransientMap["pac"]; ok {
		endorserLogger.Debugf("request for a PAC was got for TxId: [%s] and ChanicodeName: [%s]", up.ChannelHeader.TxId, up.ChaincodeName)
		endorserLogger.Debugf("ok: [%t]", ok)
		endorserLogger.Debugf("transient map: [%+v]", ccPropPayl.TransientMap)
		err = e.HandleACRequest(txParams.TXSimulator, ccPropPayl, up.ChannelID(), up.ChaincodeName, up.TxID(), res)
		if err != nil {
			return nil, errors.WithMessage(err, "failed to create Vsr Nsr hashes")
		}
	}

	return &pb.ProposalResponse{
		Version:     1,
		Endorsement: endorsement,
		Payload:     mPrpBytes,
		Response:    res,
	}, nil
}

// determine whether or not a transaction simulator should be
// obtained for a proposal.
func acquireTxSimulator(chainID string, chaincodeName string) bool {
	if chainID == "" {
		return false
	}

	// ¯\_(ツ)_/¯ locking.
	// Don't get a simulator for the query and config system chaincode.
	// These don't need the simulator and its read lock results in deadlocks.
	switch chaincodeName {
	case "qscc", "cscc":
		return false
	default:
		return true
	}
}

// shorttxid replicates the chaincode package function to shorten txids.
// ~~TODO utilize a common shorttxid utility across packages.~~
// TODO use a formal type for transaction ID and make it a stringer
func shorttxid(txid string) string {
	if len(txid) < 8 {
		return txid
	}
	return txid[0:8]
}

func CreateCCEventBytes(ccevent *pb.ChaincodeEvent) ([]byte, error) {
	if ccevent == nil {
		return nil, nil
	}

	return proto.Marshal(ccevent)
}

func decorateLogger(logger *flogging.FabricLogger, txParams *ccprovider.TransactionParams) *flogging.FabricLogger {
	return logger.With("channel", txParams.ChannelID, "txID", shorttxid(txParams.TxID))
}

func (e *Endorser) HandleACRequest(txSim ledger.TxSimulator, ccPropPayl *pb.ChaincodeProposalPayload, chanName string, ccName string, txId string, res *pb.Response) error {

	if txSim == nil {
		return errors.Errorf("tx simulator is nil %s", ccName)
	}
	endorserLogger.Debugf("tx simulator is running for TxId: [%s] and ChanicodeName: [%s]", txId, ccName)

	pacDataPath := "/etc/hyperledger/fabric/pacdata/"
	shardKeyPath := pacDataPath + "packeys/" + chanName + "/" + chanName + ".key"

	if _, ok := ccPropPayl.TransientMap["pacCR"]; ok {
		endorserLogger.Debugf("handling AC commit request...")
		//TODO: create BCCSP and getting VsrNsr pair
		//in parallel with endorsement VsrRequest

		//creating BCCSP instance to operate with symmetric cryptography
		ACTxid, err := getTxIdFromTM(ccPropPayl)
		if err != nil {
			return err
		}
		csp, err := sw.NewDefaultSecurityLevel(chanName)
		if err != nil {
			return errors.Errorf("failed to create BCCSP instance for TxId: [%s]. BCCSP: [%+v]", string(ACTxid), csp)
		}
		endorserLogger.Debugf("BCCSP instance successfully created")
		localACTM := make(map[string]PACInfo)
		tmpACInfo := PACInfo{}
		//take from file with this channel name
		err = getLocalPACMapByTxid(ccPropPayl, &localACTM, pacDataPath, chanName)
		if err != nil {
			return err
		}
		ok := false
		for key, val := range localACTM {
			savedThisChanName := string(val.Shard)
			//find this shard channelname in local store to get & send encrypted Vsr or Nsr
			if key != "pac" && key[:7] == "pacpart" && savedThisChanName == chanName {
				tmpACInfo.EncryptedVsr = val.EncryptedVsr
				tmpACInfo.EncryptedNsr = val.EncryptedNsr
				endorserLogger.Debugf("Encrypted Vsr & Nsr was found: tmpACInfo.EncryptedVsr is [%s] and tmpACInfo.EncryptedNsr is [%s]", tmpACInfo.EncryptedVsr, tmpACInfo.EncryptedNsr)
				ok = true
			}
		}
		if !ok {
			return errors.New("failed to find this channel name in the local storage")
		}

		if err := e.endorseVsrRequest(ccPropPayl, chanName, pacDataPath); err != nil {
			//response with Nsr
			endorserLogger.Warnf("Vsr request endorsement failed: [%s]. Sending Nsr...", err)
			encMessage := tmpACInfo.EncryptedNsr
			endorserLogger.Debugf("base64 encoded message: [%s]", encMessage)
			res.Message = encMessage

		} else {
			//response with Vsr
			endorserLogger.Warnf("Vsr request endorsement finished successfully. Sending Vsr...")
			encMessage := tmpACInfo.EncryptedVsr
			endorserLogger.Debugf("base64 encoded message: [%s]", encMessage)
			res.Message = encMessage
		}
	} else if _, ok := ccPropPayl.TransientMap["pacHP"]; ok {
		endorserLogger.Debugf("handling AC hash pairs from other shards...")
		//creating second response to the Atomic Commit client
		//and saving HashPairs of other shards in the peer filesystem
		err := saveHashPairs(ccPropPayl, chanName, pacDataPath)
		if err != nil {
			return errors.Errorf("failed to save atomic commit parties hash pairs: [%+v]", err)
		}

	} else {
		//generating response to the first client request for a private atomic commit
		thisChanACInfo := PACInfo{}
		encodedPACResponseMessage, err := createInitialACResponse(shardKeyPath, txId, chanName, &thisChanACInfo)
		if err != nil {
			return errors.Errorf("failed to create PAC response: [%+v]", err)
		}
		res.Message = encodedPACResponseMessage

		//save Dependency List
		//TODO: start blocks timer of dependency list life
		err = saveDependencyList(ccPropPayl, chanName, txId, pacDataPath, &thisChanACInfo)
		if err != nil {
			return errors.Errorf("failed to save dependecy list: [%+v]", err)
		}
		endorserLogger.Debug("dependency list successfuly saved")
	}

	return nil
}

func createInitialACResponse(shardKeyPath string, txId string, chanName string, thisChanACInfo *PACInfo) (string, error) {

	dir, err := os.Getwd()
	if err != nil {
		return "", errors.Errorf("failed to get working directory path for TxId: [%s]", txId)
	}
	err = os.MkdirAll(chanName, 0755)
	if err != nil {
		return "", errors.Errorf("failed to create endorser temporary path for TxId: [%s]", txId)
	}
	endorserLogger.Debugf("new keys directory was successfuly created in: [%s] for TxId: [%s]", dir+"/"+chanName, txId)
	//TODO: should we delete td automatically somewhere?
	/*defer func() {
		err = os.RemoveAll(td)
		if err != nil {
			endorserLogger.Debugf("Error while deleting temporary dir with crypto keys for a PAC: [%+v]", err)
		}
	}()*/
	hashPair := common.HashPair{}

	err = generateBasedTxidHashPair(&hashPair, chanName, txId, shardKeyPath, thisChanACInfo)
	if err != nil {
		return "", err
	}

	endorserLogger.Debugf("hashPair struct: [%+v]", hashPair)
	message, err := proto.Marshal(&hashPair)
	if err != nil {
		return "", errors.Errorf("failed to marshal hashPair: [%+v]", err)
	}
	//add VsrNsrHashes to Response
	encMessage := base64.StdEncoding.EncodeToString(message)
	endorserLogger.Debugf("base64 encoded message: [%s]", encMessage)
	return encMessage, nil
}

func generateBasedTxidHashPair(hashPair *common.HashPair, chanName string, txId string, shardKeyPath string, thisChanACInfo *PACInfo) error {
	//creating BCCSP instance to operate with symmetric cryptography
	csp, err := sw.NewDefaultSecurityLevel(chanName)
	if err != nil {
		return errors.Errorf("failed to create BCCSP instance for TxId: [%s]. BCCSP: [%+v]", txId, csp)
	}
	endorserLogger.Debugf("BCCSP instance successfully created")

	//getting symmetric key
	//TODO: delete implementation which using absolute path.
	//It is better to generate keys with BCCSP and spread them using the gossip

	hashPreimagesPair := VsrNsrPair{}
	err = generateBasedTxidVsrNsrPair(csp, &hashPreimagesPair, chanName, txId, shardKeyPath)
	if err != nil {
		return err
	}

	thisChanACInfo.EncryptedVsr = base64.StdEncoding.EncodeToString(hashPreimagesPair.Vsr)
	thisChanACInfo.EncryptedNsr = base64.StdEncoding.EncodeToString(hashPreimagesPair.Nsr)

	HashedVsr, err := csp.Hash(hashPreimagesPair.Vsr, &bccsp.SHA256Opts{})
	if err != nil {
		return errors.Errorf("failed to hash Vsr: [%+v]", err)
	}
	endorserLogger.Debugf("Hashed Vsr: string: [%s], hex: [% #x]", base64.StdEncoding.EncodeToString(HashedVsr), HashedVsr)
	HashedNsr, err := csp.Hash(hashPreimagesPair.Nsr, &bccsp.SHA256Opts{})
	if err != nil {
		return errors.Errorf("failed to hash Nsr: [%+v]", err)
	}
	endorserLogger.Debugf("Hashed Nsr: string: [%s], hex: [% #x]", base64.StdEncoding.EncodeToString(HashedNsr), HashedNsr)

	//marshal using protobuf structure
	hashPair.HashedVsr = HashedVsr
	hashPair.HashedNsr = HashedNsr

	return nil
}

func generateBasedTxidVsrNsrPair(csp bccsp.BCCSP, hashPreimagesPair *VsrNsrPair, chanName string, txId string, shardKeyPath string) error {
	key, err := ioutil.ReadFile(shardKeyPath)
	if err != nil {
		return errors.Errorf("failed to read file: [%+v]", err)
	}
	endorserLogger.Debugf("for channel [%s] the PAC-key [%s] was found", chanName, key)
	//importing key splitting the EOF byte
	k, err := csp.KeyImport(key[:32], &bccsp.AES256ImportKeyOpts{Temporary: false})
	if err != nil {
		return errors.Errorf("failed to import key: [%+v]", err)
	}
	endorserLogger.Debugf("key was successfuly imported")
	decryptedVsr := bytes.NewBufferString(txId)
	decryptedVsr.WriteString("1")
	endorserLogger.Debugf("Decrypted Vsr: [%s]", decryptedVsr.String())
	decryptedNsr := bytes.NewBufferString(txId)
	decryptedNsr.WriteString("0")
	endorserLogger.Debugf("Decrypted Nsr: [%s]", decryptedNsr.String())
	PRNGReader := bytes.NewReader([]byte(txId))
	aesOpts := bccsp.AESCBCPKCS7ModeOpts{
		PRNG: PRNGReader,
	}
	Vsr, err := csp.Encrypt(k, decryptedVsr.Bytes(), aesOpts)
	if err != nil {
		return errors.Errorf("failed to encrypt Vsr: [%+v]", err)
	}
	endorserLogger.Debugf("Encrypted Vsr: string: [%s], hex: [% #x] or [%x]", base64.StdEncoding.EncodeToString(Vsr), Vsr, Vsr)
	Nsr, err := csp.Encrypt(k, decryptedNsr.Bytes(), aesOpts)
	if err != nil {
		return errors.Errorf("failed to encrypt Nsr: [%+v]", err)
	}
	endorserLogger.Debugf("Encrypted Nsr: string: [%s], hex: [% #x] or [%x]", base64.StdEncoding.EncodeToString(Nsr), Nsr, Nsr)

	hashPreimagesPair.Vsr = Vsr
	hashPreimagesPair.Nsr = Nsr
	return nil
}

func saveDependencyList(ccpp *pb.ChaincodeProposalPayload, cn string, tid string, pdp string, thisChanACInfo *PACInfo) error {
	pacMap := make(map[string]PACInfo)
	endorserLogger.Debugf("saving dependency list from transient map: [%+v]", ccpp.TransientMap)
	for key, val := range ccpp.TransientMap {
		v := string(val)
		//omitting this shard channelname and not pac keys
		if key != "pac" && key[:7] == "pacpart" { //should we omit the current channel?
			if v == cn {
				pacMap[key] = PACInfo{
					Shard:        v,
					EncryptedVsr: thisChanACInfo.EncryptedVsr,
					EncryptedNsr: thisChanACInfo.EncryptedNsr}
			} else {
				pacMap[key] = PACInfo{
					Shard: v}
			}
			endorserLogger.Debugf("Shard [%s] AC dependency successfuly created in memory", v)
		}
	}
	m, err := json.MarshalIndent(pacMap, "", "\t")
	if err != nil {
		return err
	}

	err = os.MkdirAll(pdp+cn, 0755)
	if err != nil {
		return err
	}
	endorserLogger.Debugf("directory [%s] successfully created", pdp+cn)

	dlFileName := "pac" + tid + ".json"
	if err := savePACMapLocally(m, pdp+cn+"/"+dlFileName); err != nil {
		return err
	}
	return nil
}

func saveHashPairs(ccpp *pb.ChaincodeProposalPayload, cn string, pdp string) error {
	localPACMap := make(map[string]PACInfo)
	updatedPACMap := make(map[string]PACInfo)
	tmpPACInfo := PACInfo{}

	//get txid for current channel to update
	//the corresponding local file with dependency list

	if err := getLocalPACMapByTxid(ccpp, &localPACMap, pdp, cn); err != nil {
		return err
	}
	for key := range ccpp.TransientMap {
		//omitting this shard channelname and not pac keys
		if len(key) <= 7 || len(key)-2 < 0 {
			continue
		}
		if key[:7] == "pacpart" && key[len(key)-2:] == "HP" {
			endorserLogger.Debugf("checking HashPair key - %s", key)
			//check if this shard is in the local dependency list
			dlKey := key[:len(key)-2]
			if localPACMap[dlKey].Shard == string(ccpp.TransientMap[dlKey]) {
				//TODO: should we check that HashPair was not saved before? to prevent the brute force attack by client
				//TODO: should we check here that paylad was not changed by malicious client?

				//saving HashPair
				endorserLogger.Debugf("saving HashPair for tmap key [%s]...", key)
				tmpPACInfo = localPACMap[dlKey]
				tmpHashPair := common.HashPair{}
				err := proto.Unmarshal(ccpp.TransientMap[key], &tmpHashPair)
				if err != nil {
					return err
				}
				based64Vsr := base64.StdEncoding.EncodeToString(tmpHashPair.HashedVsr)
				endorserLogger.Debugf("based64Vsr: [%s]", based64Vsr)
				based64Nsr := base64.StdEncoding.EncodeToString(tmpHashPair.HashedNsr)
				endorserLogger.Debugf("based64Nsr: [%s]", based64Nsr)

				tmpPACInfo.HashedVsr = based64Vsr
				tmpPACInfo.HashedNsr = based64Nsr
				updatedPACMap[dlKey] = tmpPACInfo

			} else {
				return errors.Errorf("pac shards are not the same for key: [%s], localPACMap value: [%s], TransientMap value: [%s]", dlKey, localPACMap[dlKey].Shard, string(ccpp.TransientMap[dlKey]))
			}
		}
	}

	m, err := json.MarshalIndent(updatedPACMap, "", "\t")
	if err != nil {
		return err
	}
	filePath, err := getFilePathByTxid(ccpp, pdp, cn)
	if err != nil {
		return err
	}
	if err := savePACMapLocally(m, filePath); err != nil {
		return err
	}
	return nil
}

func (e *Endorser) endorseVsrRequest(ccpp *pb.ChaincodeProposalPayload, cn string, pdp string) error {
	//we need:
	//1. to check that txid.json is in the local directory
	//(it proves that AC initial_request was successfuly endorsed)
	//2. to check that txid.json contains hash pairs for every channel inside itself
	//(it proves that endorsers got hash pairs from AC client)
	//3. to check that txid was added to the ledger with TX_VALIDATION_CODE 0 (i.e. VALID)
	//(it proves that PREPARE_TX was successfully added to the ledger)

	localPACMap := make(map[string]PACInfo)

	//so lets do 1.
	if err := getLocalPACMapByTxid(ccpp, &localPACMap, pdp, cn); err != nil {
		return err
	}
	//lets do 2.
	for key := range localPACMap {
		if localPACMap[key].HashedNsr == "" {
			return errors.Errorf("HashedNsr was not received by the endorser for channel %s", localPACMap[key].Shard)
		}
		if localPACMap[key].HashedVsr == "" {
			return errors.Errorf("HashedVsr was not received by the endorser for channel %s", localPACMap[key].Shard)
		}
	}

	//lets do 3.
	txid, err := getTxIdFromTM(ccpp)
	if err != nil {
		return err
	}
	pt, err := e.Support.GetTransactionByID(cn, txid)
	if err != nil {
		return err
	}
	if pt.ValidationCode != int32(pb.TxValidationCode_VALID) {
		return errors.Errorf("prepareTx commit checking failed: Validation code for txid [%s] is invalid: [%s]", txid, pb.TxValidationCode(pt.ValidationCode).String())
	}
	return nil
}

func savePACMapLocally(m []byte, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	endorserLogger.Debugf("file [%s] successfully prepared for writing", f)
	_, err = f.Write(m)
	if err != nil {
		return err
	}
	f.Close()
	endorserLogger.Debugf("pac data was successfully written. Printing...")
	savedData, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	endorserLogger.Debugf("%s", savedData)
	return nil
}

func getLocalPACMapByTxid(ccpp *pb.ChaincodeProposalPayload, localPACMap *map[string]PACInfo, pdp string, cn string) error {

	filePath, err := getFilePathByTxid(ccpp, pdp, cn)
	if err != nil {
		return err
	}

	endorserLogger.Debugf("getting data from file %s...\nData:\n", filePath)

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, localPACMap)
	if err != nil {
		return err
	}
	return nil
}

func getFilePathByTxid(ccpp *pb.ChaincodeProposalPayload, pdp string, cn string) (string, error) {
	txid, err := getTxIdFromTM(ccpp)
	if err != nil {
		return "", err
	}
	dlFileName := "pac" + txid + ".json"
	filePath := pdp + cn + "/" + dlFileName
	return filePath, nil
}

func getTxIdFromTM(ccpp *pb.ChaincodeProposalPayload) (string, error) {
	txid, ok := ccpp.TransientMap["pactxid"]
	if !ok {
		return "", errors.Errorf("Failed to find txid key in transient map")
	}
	return string(txid), nil
}
