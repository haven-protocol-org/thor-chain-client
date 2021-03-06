package haven

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/haven-protocol-org/monero-go-utils/crypto"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gitlab.com/thorchain/thornode/bifrost/blockscanner"
	"gitlab.com/thorchain/thornode/bifrost/config"
	"gitlab.com/thorchain/thornode/bifrost/metrics"
	"gitlab.com/thorchain/thornode/bifrost/thorclient"
	"gitlab.com/thorchain/thornode/bifrost/thorclient/types"
	stypes "gitlab.com/thorchain/thornode/bifrost/thorclient/types"
	"gitlab.com/thorchain/thornode/bifrost/tss"
	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
	tssp "gitlab.com/thorchain/tss/go-tss/tss"
)

// Client observes bitcoin chain and allows to sign and broadcast tx
type Client struct {
	logger            zerolog.Logger
	cfg               config.ChainConfiguration
	chain             common.Chain
	privViewKey       [32]byte
	privSpendKey      [32]byte
	pubSpenKey        [32]byte
	pubViewKey        [32]byte
	blockScanner      *blockscanner.BlockScanner
	blockMetaAccessor BlockMetaAccessor
	ksWrapper         *KeySignWrapper
	bridge            *thorclient.ThorchainBridge
	globalErrataQueue chan<- types.ErrataBlock
	nodePubKey        common.PubKey
}

type TxVout struct {
	Address string
	Amount  uint64
	Coin    common.Asset
}

// BlockCacheSize the number of block meta that get store in storage.
const BlockCacheSize = 100

// NewClient generates a new Client
func NewClient(thorKeys *thorclient.Keys, cfg config.ChainConfiguration, server *tssp.TssServer, bridge *thorclient.ThorchainBridge, m *metrics.Metrics, keySignPartyMgr *thorclient.KeySignPartyMgr) (*Client, error) {

	tssKm, err := tss.NewKeySign(server)
	if err != nil {
		return nil, fmt.Errorf("fail to create tss signer: %w", err)
	}
	thorPrivateKey, err := thorKeys.GetPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("fail to get THORChain private key: %w", err)
	}

	privViewKey, privSpendKey := getHavenPrivateKey(thorPrivateKey)
	// if err != nil {
	// 	return nil, fmt.Errorf("fail to convert private key for BTC: %w", err)
	// }

	// try to generate a haven wallet
	pubSpenKey, pubViewKey, ok := generateHavenWallet(privViewKey, privSpendKey, "cfg.WalletName", cfg.Password)
	if !ok {
		return nil, fmt.Errorf("Fail to create a haven wallet!")
	}

	// try to login to wallet
	if !loginToWallet("cfg.WalletName", cfg.Password) {
		return nil, fmt.Errorf("Fail to open the haven wallet!")
	}

	ksWrapper, err := NewKeySignWrapper(privViewKey, privSpendKey, bridge, tssKm, keySignPartyMgr)
	if err != nil {
		return nil, fmt.Errorf("fail to create keysign wrapper: %w", err)
	}

	nodePubKey, err := common.NewPubKeyFromCrypto(thorKeys.GetSignerInfo().GetPubKey())
	if err != nil {
		return nil, fmt.Errorf("fail to get the node pubkey: %w", err)
	}

	c := &Client{
		logger:       log.Logger.With().Str("module", "haven").Logger(),
		cfg:          cfg,
		chain:        cfg.ChainID,
		privViewKey:  *privViewKey,
		privSpendKey: *privSpendKey,
		pubSpenKey:   pubSpenKey,
		pubViewKey:   pubViewKey,
		ksWrapper:    ksWrapper,
		bridge:       bridge,
		nodePubKey:   nodePubKey,
	}

	var path string // if not set later, will in memory storage
	if len(c.cfg.BlockScanner.DBPath) > 0 {
		path = fmt.Sprintf("%s/%s", c.cfg.BlockScanner.DBPath, c.cfg.BlockScanner.ChainID)
	}
	storage, err := blockscanner.NewBlockScannerStorage(path)
	if err != nil {
		return c, fmt.Errorf("fail to create blockscanner storage: %w", err)
	}

	c.blockScanner, err = blockscanner.NewBlockScanner(c.cfg.BlockScanner, storage, m, bridge, c)
	if err != nil {
		return c, fmt.Errorf("fail to create block scanner: %w", err)
	}

	c.blockMetaAccessor, err = NewLevelDBBlockMetaAccessor(storage.GetInternalDb())
	if err != nil {
		return c, fmt.Errorf("fail to create utxo accessor: %w", err)
	}

	return c, nil
}

// Start starts the block scanner
func (c *Client) Start(globalTxsQueue chan types.TxIn, globalErrataQueue chan types.ErrataBlock) {
	c.blockScanner.Start(globalTxsQueue)
	c.globalErrataQueue = globalErrataQueue
}

// Stop stops the block scanner
func (c *Client) Stop() {
	c.blockScanner.Stop()
}

// GetConfig - get the chain configuration
func (c *Client) GetConfig() config.ChainConfiguration {
	return c.cfg
}

// GetChain returns haven Chain
func (c *Client) GetChain() common.Chain {
	return common.XHVChain
}

// GetHeight returns current block height
func (c *Client) GetHeight() (int64, error) {
	return GetHeight()
}

// GetAddress return current signer address, it will be bech32 encoded address
func (c *Client) GetAddress(poolPubKey common.PubKey) string {
	addr, err := poolPubKey.GetAddress(common.XHVChain)
	if err != nil {
		c.logger.Error().Err(err).Str("pool_pub_key", poolPubKey.String()).Msg("fail to get pool address")
		return ""
	}
	return addr.String()
}

// GetAccountByAddress return empty account for now
func (c *Client) GetAccountByAddress(address string) (common.Account, error) {
	return common.Account{}, nil
}

// GetAccount returns account with balance for an address
func (c *Client) GetAccount(pkey common.PubKey) (common.Account, error) {

	// make a new account instance to return in case of an error
	acct := common.Account{}

	// get all block metas
	blockMetas, err := c.blockMetaAccessor.GetBlockMetas()
	if err != nil {
		return acct, fmt.Errorf("fail to get block meta: %w", err)
	}

	// calculate total spendable amount in all blocks
	total := 0.0
	for _, item := range blockMetas {
		for _, utxo := range item.GetUTXOs(pkey) {
			total += utxo.Value
		}
	}
	total = total * 1000000000000 // 12 zeros

	// return a new Account with the total amount spendable.
	return common.NewAccount(0, 0, common.AccountCoins{
		common.AccountCoin{
			Amount: uint64(total),
			Denom:  common.XHVAsset.String(),
		},
	}, false), nil
}

// OnObservedTxIn gets called from observer when we have a valid observation
// For bitcoin chain client we want to save the utxo we can spend later to sign
func (c *Client) OnObservedTxIn(txIn types.TxInItem, blockHeight int64) {

	// get the txItem value
	value := float64(txIn.Coins.GetCoin(common.XHVAsset).Amount.Uint64()) / 1000000000000

	// get the block meta for this height
	blockMeta, err := c.blockMetaAccessor.GetBlockMeta(blockHeight)
	if nil != err {
		c.logger.Err(err).Msgf("fail to get block meta on block height(%d)", blockHeight)
	}
	if nil == blockMeta {
		c.logger.Error().Msgf("can't get block meta for height: %d", blockHeight)
		return
	}

	// create a new unspent transaction output and save to the block it belongs to.
	utxo := NewUnspentTransactionOutput(txIn.Tx, 0, value, blockHeight, txIn.ObservedVaultPubKey)
	blockMeta.AddUTXO(utxo)
	if err := c.blockMetaAccessor.SaveBlockMeta(blockHeight, blockMeta); err != nil {
		c.logger.Err(err).Msgf("fail to save block meta to storage,block height(%d)", blockHeight)
	}
}

// FetchTxs retrieves txs for a block height
func (c *Client) FetchTxs(height int64) (types.TxIn, error) {

	block, err := GetBlock(height)
	if err != nil {
		return types.TxIn{}, fmt.Errorf("fail to get block: %w", err)
	}

	// Check for reorg
	if err := c.processReorg(block); err != nil {
		c.logger.Err(err).Msg("fail to process bitcoin re-org")
	}

	// update block meta
	blockMeta, err := c.blockMetaAccessor.GetBlockMeta(block.Block_Header.Height)
	if err != nil {
		return types.TxIn{}, fmt.Errorf("fail to get block meta from storage: %w", err)
	}
	if blockMeta == nil {
		blockMeta = NewBlockMeta(block.Block_Header.Prev_Hash, block.Block_Header.Height, block.Block_Header.Hash)
	} else {
		blockMeta.PreviousHash = block.Block_Header.Prev_Hash
		blockMeta.BlockHash = block.Block_Header.Hash
	}
	if err := c.blockMetaAccessor.SaveBlockMeta(block.Block_Header.Height, blockMeta); err != nil {
		return types.TxIn{}, fmt.Errorf("fail to save block meta into storage: %w", err)
	}

	// update prune block meta
	pruneHeight := height - BlockCacheSize
	if pruneHeight > 0 {
		defer func() {
			if err := c.blockMetaAccessor.PruneBlockMeta(pruneHeight); err != nil {
				c.logger.Err(err).Msgf("fail to prune block meta, height(%d)", pruneHeight)
			}
		}()
	}

	// get txs as txInItems
	txs, err := c.extractTxs(block)
	if err != nil {
		return types.TxIn{}, fmt.Errorf("fail to extract txs from block: %w", err)
	}

	// send thorchain network fee
	if err := c.sendNetworkFee(height); err != nil {
		c.logger.Err(err).Msg("fail to send network fee")
	}

	return txs, nil
}

func (c *Client) sendNetworkFee(height int64) error {

	// // TODO: an endpoint to get the AverageTxSize and AverageFeeRate
	// result, err := c.client.GetBlockStats(height, nil)
	// if err != nil {
	// 	return fmt.Errorf("fail to get block stats")
	// }
	// // fee rate and tx size should not be 0
	// if result.AverageFeeRate == 0 || result.AverageTxSize == 0 {
	// 	return nil
	// }

	// txid, err := c.bridge.PostNetworkFee(height, common.BTCChain, result.AverageTxSize, sdk.NewUint(uint64(result.AverageFeeRate)))
	// if err != nil {
	// 	return fmt.Errorf("fail to post network fee to thornode: %w", err)
	// }
	// c.logger.Debug().Str("txid", txid.String()).Msg("send network fee to THORNode successfully")
	return nil
}

func (c *Client) processReorg(block Block) error {
	previousHeight := block.Block_Header.Height - 1
	prevBlockMeta, err := c.blockMetaAccessor.GetBlockMeta(previousHeight)
	if err != nil {
		return fmt.Errorf("fail to get block meta of height(%d) : %w", previousHeight, err)
	}
	if prevBlockMeta == nil {
		return nil
	}
	// the block's previous hash need to be the same as the block hash chain client recorded in block meta
	// blockMetas[PreviousHeight].BlockHash == Block.PreviousHash
	if strings.EqualFold(prevBlockMeta.BlockHash, block.Block_Header.Prev_Hash) {
		return nil
	}

	c.logger.Info().Msgf("re-org detected, current block height:%d ,previous block hash is : %s , however block meta at height: %d, block hash is %s", block.Block_Header.Height, block.Block_Header.Prev_Hash, prevBlockMeta.Height, prevBlockMeta.BlockHash)
	return c.reConfirmTx()
}

// reConfirmTx will be kicked off only when chain client detected a re-org on bitcoin chain
// it will read through all the block meta data from local storage , and go through all the UTXOes.
// For each UTXO , it will send a RPC request to bitcoin chain , double check whether the TX exist or not
// if the tx still exist , then it is all good, if a transaction previous we detected , however doesn't exist anymore , that means
// the transaction had been removed from chain,  chain client should report to thorchain
func (c *Client) reConfirmTx() error {
	blockMetas, err := c.blockMetaAccessor.GetBlockMetas()
	if err != nil {
		return fmt.Errorf("fail to get block metas from local storage: %w", err)
	}

	for _, blockMeta := range blockMetas {
		var errataTxs []types.ErrataTx
		for _, utxo := range blockMeta.UnspentTransactionOutputs {
			txID := utxo.TxID
			if c.confirmTx(utxo.TxID) {
				c.logger.Info().Msgf("block height: %d, tx: %s still exist", blockMeta.Height, txID)
				continue
			}
			// this means the tx doesn't exist in chain ,thus should errata it
			errataTxs = append(errataTxs, types.ErrataTx{
				TxID:  common.TxID(txID),
				Chain: common.XHVChain,
			})
			// remove the UTXO from block meta , so signer will not spend it
			blockMeta.RemoveUTXO(utxo.GetKey())
		}
		if len(errataTxs) == 0 {
			continue
		}
		c.globalErrataQueue <- types.ErrataBlock{
			Height: blockMeta.Height,
			Txs:    errataTxs,
		}
		// Let's get the block again to fix the block hash
		r, err := GetBlock(blockMeta.Height)
		if err != nil {
			c.logger.Err(err).Msgf("fail to get block verbose tx result: %d", blockMeta.Height)
		}
		blockMeta.PreviousHash = r.Block_Header.Prev_Hash
		blockMeta.BlockHash = r.Block_Header.Hash
		if err := c.blockMetaAccessor.SaveBlockMeta(blockMeta.Height, blockMeta); err != nil {
			c.logger.Err(err).Msgf("fail to save block meta of height: %d ", blockMeta.Height)
		}
	}
	return nil
}

// confirmTx check a tx is valid on chain post reorg
func (c *Client) confirmTx(txHash string) bool {

	// first check if tx is in mempool, just signed it for example
	// if no error it means its valid mempool tx and move on
	poolTxs, err := GetPoolTxs()
	if err != nil {
		fmt.Errorf("Error Getting Pool Txs: %w", err)
		return false
	}

	// check if the tx is still in the pool. If it is, that means it is a valid tx.
	for _, tx := range poolTxs {
		if tx == txHash {
			return true
		}
	}

	// then get raw tx and check if it has confirmations or not
	// if no confirmation and not in mempool then invalid
	var txHashes = make([]string, 0)
	txHashes = append(txHashes, txHash)
	txs, err := GetTxes(txHashes)
	if err != nil {
		fmt.Errorf("Error Getting Tx: %s", txHash)
		return false
	}

	// check if the tx has confirmations
	currentHeight, err := GetHeight()
	if currentHeight > txs[0].Block_Height {
		return true
	}

	return false
}

// extractTxs extracts txs from a block to type TxIn
func (c *Client) extractTxs(block Block) (types.TxIn, error) {

	// prepare the TxIn
	txIn := types.TxIn{
		Chain: c.GetChain(),
	}

	// get txs from daemon
	txs, err := GetTxes(block.Tx_Hashes)
	if err != nil {
		return txIn, fmt.Errorf("Failed to get txs from daemon: %w", err)
	}

	// populate txItems
	var txItems []types.TxInItem
	for ind, tx := range txs {

		// parse tx extra
		parsedTxExtra, err := c.parseTxExtra(tx.Extra)
		if err != nil {
			fmt.Errorf("Error Parsing Tx Extra: %w\n", err)
			continue
		}

		// get tx public key
		var txPubKey [32]byte
		if len(parsedTxExtra[1]) != 1 {
			continue
		}
		copy(txPubKey[:], parsedTxExtra[1][0][0:32])

		// get the output
		output, err := c.getOutput(&tx, &txPubKey)
		if err != nil {
			fmt.Errorf("Error Decrypting Tx Output: %w\n", err)
			continue
		}
		if output == (TxVout{}) {
			// We don't own any output in this tx, so skip it
			continue
		}

		// we don't know the sender
		sender := ""

		// get the gas
		var fee int64
		if val, ok := parsedTxExtra[0x17]; ok {
			if string(val[0]) != "N" {
				fee = tx.Rct_Signatures.TxnFee
			} else {
				fee = tx.Rct_Signatures.TxnFee_Usd
			}
		} else {
			fee = tx.Rct_Signatures.TxnFee
		}

		var gas = common.Gas{
			common.NewCoin(common.BTCAsset, cosmos.NewUint((uint64(fee)))),
		}

		// get the memo
		memo := ""
		if val, ok := parsedTxExtra[0x18]; ok {
			memo = string(val[0])
		} else {
			continue
		}

		// construct txItems
		txItems = append(txItems, types.TxInItem{
			BlockHeight: block.Block_Header.Height,
			Tx:          block.Tx_Hashes[ind],
			Sender:      sender,
			To:          output.Address,
			Coins: common.Coins{
				common.NewCoin(common.XHVAsset, cosmos.NewUint(output.Amount)),
			},
			Memo: memo,
			Gas:  gas,
		})
	}
	txIn.TxArray = txItems
	txIn.Count = strconv.Itoa(len(txItems))
	return txIn, nil
}

func (c *Client) getOutput(tx *RawTx, txPubKey *[32]byte) (TxVout, error) {

	var txVout = TxVout{}

	// generate the shared secrets for both ygg and asgard
	sharedSecretYgg, err := crypto.GenerateKeyDerivation(txPubKey, &c.privViewKey)
	if err != nil {
		return txVout, fmt.Errorf("Error Creating Ygg Shared Secret: %w\n", err)
	}
	// sharedSecretAsgard, err := crypto.GenerateKeyDerivation(txPubKey, &c.ksWrapper.tssKeyManager.getPrivViewKey())
	// if err != nil {
	// 	return txVout, fmt.Errorf("Error Creating Asgard Shared Secret: %w\n", err)
	// }

	for ind, vout := range tx.Vout {

		var targetKey [32]byte
		assetType := ""
		if len(vout.Target.Key) != 0 {
			targetRaw, _ := hex.DecodeString(vout.Target.Key)
			copy(targetKey[:], targetRaw)
			assetType = "XHV"
		}
		// else {
		// 	targetRaw, _ := hex.DecodeString(vout.Target.Offshore)
		// 	copy(targetKey[:], targetRaw)
		// 	assetType = "xUSD"
		// }

		// derive the spent keys for both vaults
		derivedPublicSpendKeyYgg, err := crypto.SubSecretFromTarget((*sharedSecretYgg)[:], uint64(ind), &targetKey)
		if err != nil {
			return txVout, fmt.Errorf("Error Deriving Ygg Public Spend Key: %w\n", err)
		}
		// derivedPublicSpendKeyAsgard, err := crypto.SubSecretFromTarget((*sharedSecretAsgard)[:], uint64(ind), &targetKey)
		// if err != nil {
		// 	return txVout, fmt.Errorf("Error Deriving Asgard Public Spend Key: %w\n", err)
		// }

		// TODO: Check if the tss asgard keys functions are correct
		found := ""
		if *derivedPublicSpendKeyYgg == c.pubSpenKey {
			found = "ygg"
		}
		// else if *derivedPublicSpendKeyAsgard == c.ksWrapper.tssKeyManager.getPubSpendKey() {
		// 	found = "asgard"
		// }

		if len(found) == 0 {
			// decode the tx amount and mask
			var scalar *[32]byte
			if found == "ygg" {
				scalar = crypto.DerivationToScalar(sharedSecretYgg[:], uint64(ind))
			}
			// else {
			// 	scalar = crypto.DerivationToScalar(sharedSecretAsgard[:], uint64(ind))
			// }
			ecdhInfo := crypto.EcdhDecode(tx.Rct_Signatures.EcdhInfo[ind], *scalar)

			// Calculate the amount commitment from decoded ecdh info
			var C, Ctmp [32]byte
			success := crypto.AddKeys2(&Ctmp, ecdhInfo.Mask, ecdhInfo.Amount, crypto.H)

			if success {
				if assetType == "XHV" {
					// Onshore amount (XHV)
					Craw, _ := hex.DecodeString(tx.Rct_Signatures.OutPk[ind])
					copy(C[:], Craw)
				}
				// else {
				// 	// Offshore amount (xUSD)
				// 	Craw, _ := hex.DecodeString(rawTx.Rct_Signatures.OutPk_Usd[ind])
				// 	copy(C[:], Craw)
				// }

				// check if the provided output commitment mathces with the one we calculated
				if crypto.EqualKeys(C, Ctmp) {

					// Decode the amount
					Amount := crypto.H2d(ecdhInfo.Amount)

					// Determine which vault vas the target
					var derivedPublicSpendKey string
					if found == "ygg" {
						derivedPublicSpendKey = hex.EncodeToString(derivedPublicSpendKeyYgg[:])
					}
					// else {
					// 	derivedPublicSpendKey = hex.EncodeToString(derivedPublicSpendKeyAsgard[:])
					// }

					// populate txVout
					txVout.Address = derivedPublicSpendKey
					txVout.Amount = Amount
					txVout.Coin = common.XHVAsset

					// NOTE: We can just skip the rest of the outputs and return here because we expect we only own 1 output
					return txVout, nil
				}
			} else {
				fmt.Errorf("Calculation of the commitment failed for output index = %d", ind)
			}
		}
	}

	// We don't own any output in this tx
	return txVout, nil
}

// isYggdrasil - when the pubkey and node pubkey is the same that means it is signing from yggdrasil
func (c *Client) isAsgard(key common.PubKey) bool {
	asgards, err := c.bridge.GetAsgards()
	if err != nil {
		c.logger.Err(err).Msg("fail to get asgard vaults from thorchain")
		return false
	}
	for _, item := range asgards {
		if item.PubKey.Equals(key) {
			return true
		}
	}
	return false
}

// SignTx is going to generate the outbound transaction, and also sign it
func (c *Client) SignTx(tx stypes.TxOutItem, thorchainHeight int64) ([]byte, error) {

	// check if the chain is correct
	// if !tx.Chain.Equals(common.XHVChain) {
	// 	return nil, errors.New("not XHV chain!")
	// }

	// // get the from address
	// sourceAddr, err := tx.VaultPubKey.GetAddress(common.XHVChain)
	// if err != nil {
	// 	return nil, fmt.Errorf("fail to get source address: %w", err)
	// }

	// // get the wallet address
	// walletAddr, err := GetWalletAddress()
	// if err != {
	// 	return nil, fmt.Errorf("fail to get wallet address: %w", err)
	// }

	// // check if they match or not
	// if sourceAddr.String() != walletAddr {
	// 	return nil, errors.New("Source Address is not the haven wallet this node controls!")
	// }

	// get the amount
	// var amount uint64
	// if len(tx.Coins) != 1 {
	// 	return nil, errors.New("Haven doesn't support sending multiple asset types in a single transaction for now!")
	// }
	// amount = tx.Coins[0].Amount
	// outputAsset = tx.Coins[0].Asset.Symbol

	// // create a dsts structure
	// var dsts = make([]map[string]interface{}, 1)
	// dsts[0]["amount"] = amount
	// dsts[0]["address"] = tx.ToAddress.String()

	// // check if we have create a tx from ygg
	// if tx.VaultPubKey.Equals(c.nodePubKey) {
	// 	signedTx, err := CreateTx(dsts, outputAsset, tx.Memo);
	// } else if isAsgard(tx.VaultPubKey) {
	// 	// Sign tx from asgard
	// 	signable := c.ksWrapper.GetSignable(tx.VaultPubKey)

	// } else {
	// 	return nil, errors.New("Unknow vault!")
	// }

	// TODO: if we create multiple transactions we will have multiple Tx_Blobs. What should we do in that case. Concatanete them?
	// Also don't forget we migth need to do hex.EncodeString() for each
	// return signedTx.Tx_Blob_List[0], nil
	var rt = make([]byte, 32)
	return rt, nil
}

// BroadcastTx will broadcast the given payload to XHV chain
func (c *Client) BroadcastTx(txOut stypes.TxOutItem, payload []byte) error {

	//TODO: payload type

	// retrieve block meta
	// chainBlockHeight, err := c.GetHeight()
	// if err != nil {
	// 	return fmt.Errorf("fail to get chain block height: %w", err)
	// }
	// blockMeta, err := c.blockMetaAccessor.GetBlockMeta(chainBlockHeight)
	// if err != nil {
	// 	return fmt.Errorf("fail to get block meta: %w", err)
	// }
	// if blockMeta == nil {
	// 	blockMeta = NewBlockMeta("", chainBlockHeight, "")
	// }
	// err = c.updateBlockMeta(txOut, blockMeta, redeemTx)
	// if err != nil {
	// 	return fmt.Errorf("fail to update block meta: %s", err)
	// }

	// // broadcast tx
	// resp := SendRawTransaction(payload)

	// if resp.Status != "OK" {
	// 	// TODO: this is a fake reason text. Find the original and replace this.
	// 	if resp.Reason == "TX is alread in the chain" {
	// 		return nil
	// 	}

	// 	// revert block meta
	// 	err2 := c.revertBlockMeta(txOut, blockMeta, redeemTx)
	// 	if err2 != nil {
	// 		c.logger.Err(err2).Msg("fail to revert block meta")
	// 	}
	// 	return fmt.Errorf("fail to broadcast transaction to chain: %s", resp.Reason)
	// }

	return nil
}

func (c *Client) parseTxExtra(extra []byte) (map[byte][][]byte, error) {

	var parsedTxExtra = make(map[byte][][]byte)

	for ind := 0; ind < len(extra); ind++ {

		if extra[ind] == 0 {
			// Padding
			var len = int(extra[ind+1])
			ind += len
		} else if extra[ind] == 0x01 {
			// Pubkey - 32 byte key (fixed length)
			if len(extra)-ind <= 32 {
				return nil, fmt.Errorf("Tx pubKey has insufficient length!")
			}
			var ba = make([]byte, 32)
			ba = extra[ind+1 : ind+33]
			parsedTxExtra[0x01] = append(parsedTxExtra[0x01], ba)
			ind += 32
		} else if extra[ind] == 2 {
			// Nonce
			var len = int(extra[ind+1])
			ind += len
		} else if extra[ind] == 3 {
			// Merge mining key
			ind += 40
		} else if extra[ind] == 4 {
			// Additional pubkeys
			ind += 32
		} else if extra[ind] == 0xde {
			// miner gate tag
			var len = int(extra[ind+1])
			ind += len
		} else if extra[ind] == 0x17 {
			// Offshore data
			var length = int(extra[ind+1])
			if len(extra)-ind <= length {
				return nil, fmt.Errorf("Offshore data has insufficient length!")
			}
			var ba = make([]byte, length)
			ba = extra[ind+2 : ind+2+length]
			parsedTxExtra[0x17] = append(parsedTxExtra[0x17], ba)
			ind += length
		} else if extra[ind] == 0x18 {
			// Thorchain memo data
			var length = int(extra[ind+1])
			if len(extra)-ind <= length {
				return nil, fmt.Errorf("Thorchain memo data has insufficient length!")
			}
			var ba = make([]byte, length)
			ba = extra[ind+2 : ind+2+length]
			parsedTxExtra[0x18] = append(parsedTxExtra[0x18], ba)
			ind += length
		} else {
			return nil, fmt.Errorf("fail to parse tx extra!")
		}
	}

	return parsedTxExtra, nil
}
