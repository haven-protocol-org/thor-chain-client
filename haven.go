package haven

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/haven-protocol-org/monero-go-utils/crypto"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	tssp "gitlab.com/thorchain/tss/go-tss/tss"

	"gitlab.com/thorchain/thornode/bifrost/blockscanner"
	"gitlab.com/thorchain/thornode/bifrost/config"
	"gitlab.com/thorchain/thornode/bifrost/metrics"
	"gitlab.com/thorchain/thornode/bifrost/thorclient"
	"gitlab.com/thorchain/thornode/bifrost/thorclient/types"
	"gitlab.com/thorchain/thornode/bifrost/tss"
	"gitlab.com/thorchain/thornode/common"
	"gitlab.com/thorchain/thornode/common/cosmos"
)

// Client observes bitcoin chain and allows to sign and broadcast tx
type Client struct {
	logger            	zerolog.Logger
	cfg               	config.ChainConfiguration
	chain             	common.Chain
	privViewKey			[32]byte
	privSpendKey		[32]byte
	blockScanner      	*blockscanner.BlockScanner
	blockMetaAccessor 	BlockMetaAccessor
	ksWrapper         	*KeySignWrapper
	bridge           	*thorclient.ThorchainBridge
	globalErrataQueue 	chan<- types.ErrataBlock
	nodePubKey        	common.PubKey
}

type TxVout struct {
	Address string
	Amount uint64
	Coin string
}

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

	privViewKey, privSpendKey, err := getHavenPrivateKey(thorPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("fail to convert private key for BTC: %w", err)
	}

	// try to generate a haven wallet
	if !generateHavenWallet(privViewKey, privSpendKey, cfg.WalletName, cfg.Password) {
		return nil, fmt.Errorf("Fail to create a haven wallet!")
	}

	// try to login to wallet
	if !loginToWallet(cfg.WalletName, cfg.Password) {
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
		logger:     		log.Logger.With().Str("module", "haven").Logger(),
		cfg:        		cfg,
		chain:      		cfg.ChainID,
		privViewKey			privViewKey,
		privSpendKey		privSpendKey,
		ksWrapper:  		ksWrapper,
		bridge:     		bridge,
		nodePubKey: 		nodePubKey,
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
	return common.XHVCHain
}

// GetHeight returns current block height
func (c *Client) GetHeight() (int64, error) {
	return GetHeight()
}

// GetAddress return current signer address, it will be bech32 encoded address
func (c *Client) GetAddress(poolPubKey common.PubKey) string {
	addr, err := poolPubKey.GetAddress(common.XHVCHain)
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
	total = total * 1000000000000

	// return a new Account with the total amount spendable.
	//TODO: 0,0 in the beginng???
	return common.NewAccount(0, 0, common.AccountCoins{
		common.AccountCoin{
			Amount: uint64(totalAmt),
			Denom:  common.XHVAsset.String(),
		},
	}, false), nil
}

// OnObservedTxIn gets called from observer when we have a valid observation
// For bitcoin chain client we want to save the utxo we can spend later to sign
func (c *Client) OnObservedTxIn(txIn types.TxInItem, blockHeight int64) {

	// get the txItem value
	value := float64(txIn.Coins.GetCoin(common.BTCAsset).Amount.Uint64()) / 1000000000000

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

	// TODO: an endpoint to get the AverageTxSize and AverageFeeRate
	result, err := c.client.GetBlockStats(height, nil)
	if err != nil {
		return fmt.Errorf("fail to get block stats")
	}
	// fee rate and tx size should not be 0
	if result.AverageFeeRate == 0 || result.AverageTxSize == 0 {
		return nil
	}

	txid, err := c.bridge.PostNetworkFee(height, common.BTCChain, result.AverageTxSize, sdk.NewUint(uint64(result.AverageFeeRate)))
	if err != nil {
		return fmt.Errorf("fail to post network fee to thornode: %w", err)
	}
	c.logger.Debug().Str("txid", txid.String()).Msg("send network fee to THORNode successfully")
	return nil
}

func (c *Client) processReorg(block Block) error {
	previousHeight := block.Height - 1
	prevBlockMeta, err := c.blockMetaAccessor.GetBlockMeta(previousHeight)
	if err != nil {
		return fmt.Errorf("fail to get block meta of height(%d) : %w", previousHeight, err)
	}
	if prevBlockMeta == nil {
		return nil
	}
	// the block's previous hash need to be the same as the block hash chain client recorded in block meta
	// blockMetas[PreviousHeight].BlockHash == Block.PreviousHash
	if strings.EqualFold(prevBlockMeta.BlockHash, block.PreviousHash) {
		return nil
	}

	c.logger.Info().Msgf("re-org detected, current block height:%d ,previous block hash is : %s , however block meta at height: %d, block hash is %s", block.Height, block.PreviousHash, prevBlockMeta.Height, prevBlockMeta.BlockHash)
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
			txID := utxo.TxID.String()
			if c.confirmTx(&utxo.TxID) {
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
func (c *Client) confirmTx(txHash *chainhash.Hash) bool {
	
	// first check if tx is in mempool, just signed it for example
	// if no error it means its valid mempool tx and move on
	poolTxs, err := GetPoolTxs()
	if err != nil {
		fmt.Errorf("Error Getting Pool Txs: %w", err)
		return false
	}

	// check if the tx is still in the pool. If it is, that means it is a valid tx.
	for _, tx := range poolTxs {
		if tx == txHash.String() {
			return true
		}
	}


	// then get raw tx and check if it has confirmations or not
	// if no confirmation and not in mempool then invalid
	var txHashes = make([]string, 0)
	txHashes = append(txHashes, txHash.String())
	txs, err := GetTxes(txHashes)
	if err != nil {
		fmt.Errorf("Error Getting Tx: %s", txHash)
		return false
	}

	// check if the tx has confirmations
	currentHeight, err := GetHeight()
	if txs[0].Block_Height == currentHeight {
		return false
	}

	return true
}

// extractTxs extracts txs from a block to type TxIn
func (c *Client) extractTxs(block Block) (types.TxIn, error) {

	// get txs from daemon
	txs, err := GetTxs(block.Tx_Hashes)
	if err != nil {
		return nil, fmt.Errorf("Failed to get txs from daemon: %w", err)
	}

	// prepare the TxIn
	txIn := types.TxIn{
		Chain: c.GetChain(),
	}

	// populate txItems
	var txItems []types.TxInItem
	for ind, tx := range txs {

		// parse tx extra
		var status, parsedTxExtra = c.parseTxExtra(tx.Extra)
		if status != nil {
			fmt.Printf("Error: %q\n", status)
		}

		// we don't know the sender
		sender = ""

		// get the gas
		gas := 0
		if val, ok := parsedTxExtra[0x17]; ok {
			if string(val[0]) != 'N' {
				gas = tx.Rct_Signatures.TxnFee
			}else{
				gas = tx.Rct_Signatures.TxnFee_Usd
			}
		}else{
			gas = tx.Rct_Signatures.TxnFee
		}

		// get tx public key
		var txPubKey [32]byte
		if len(parsedTxExtra[1]) != 1 {
			continue
		}
		copy(txPubKey[:], parsedTxExtra[1][0][0:32])

		// get the memo
		memo := ""
		if val, ok := parsedTxExtra[0x18]; ok {
			memo = string(val[0])
		} else {
			continue
		}

		// get the output
		output := c.getOutput(&tx, &txPubKey)

		// construct txItems
		txItems = append(txItems, types.TxInItem{
			BlockHeight: block.Block_Header.Height,
			Tx:          block.Tx_Hashes[ind],
			Sender:      sender,
			To:          output.Address,
			Coins: common.Coins{
				common.NewCoin(output.Coin, cosmos.NewUint(output.Amount)),
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

	// generate the shared secret
	sharedSecret, status := crypto.GenerateKeyDerivation(&txPubKey, &viewKey)
	if status != nil {
		return nil, fmt.Errorf("Error Creating Shared Secret: %q\n", status)
	}

	for ind, vout := range tx.Vout {

		var targetKey [32]byte
		assetType := ""
		if len(vout.Target.Key) != 0 {
			targetRaw, _ := hex.DecodeString(vout.Target.Key)
			copy(targetKey[:], targetRaw)
			assetType = "XHV"
		} else {
			targetRaw, _ := hex.DecodeString(vout.Target.Offshore)
			copy(targetKey[:], targetRaw)
			assetType = "xUSD"
		}

		derivedPublicSpendKey, status := crypto.SubSecretFromTarget((*sharedSecret)[:], uint64(ind), &targetKey)
		if status != nil {
			fmt.Errorf("Error Deriving a Public Spend Key: %q\n", status)
			continue
		}

		// TODO: We need to check for both ygg and asgard vault outputs
		found := false
		if *derivedPublicSpendKey == publicSpendKey {
			found = true
		}

		if found {
			// decode the tx amount and mask
			scalar := crypto.DerivationToScalar(sharedSecret[:], uint64(ind))
			ecdhInfo := crypto.EcdhDecode(rawTx.Rct_Signatures.EcdhInfo[ind], *scalar)

			// Calculate the amount commitment from decoded ecdh info
			var C, Ctmp [32]byte
			success := crypto.AddKeys2(&Ctmp, ecdhInfo.Mask, ecdhInfo.Amount, crypto.H)

			if success {
				if outputAsset == "XHV" {
					// Onshore amount (XHV)
					Craw, _ := hex.DecodeString(rawTx.Rct_Signatures.OutPk[ind])
					copy(C[:], Craw)
				} else {
					// Offshore amount (xUSD)
					Craw, _ := hex.DecodeString(rawTx.Rct_Signatures.OutPk_Usd[ind])
					copy(C[:], Craw)
				}

				// check if the provided output commitment mathces with the one we calculated
				if crypto.EqualKeys(C, Ctmp) {
					Amount :=  crypto.H2d(ecdhInfo.Amount)
					// NOTE: We can just skip the rest of the outputs and return here because we expect we only own 1 output
					return TxVout{
						Address: string(derivedPublicSpendKey),
						Amount: Amount
						Coin: assetType
					}, nil
				}
			} else {
				fmt.Errorf("Calculation of the commitment failed for output index = %d", ind)
			}
		}
	}

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
			if len(extra) - ind <= 32 {
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
			var len = int(extra[ind+1])
			if len(extra) - ind <= len {
				return nil, fmt.Errorf("Offshore data has insufficient length!")
			}
			var ba = make([]byte, len)
			ba = extra[ind+2 : ind+2+len]
			parsedTxExtra[0x17] = append(parsedTxExtra[0x17], ba)
			ind += len
		} else if extra[ind] == 0x18 {
			// Thorchain memo data
			var len = int(extra[ind+1])
			if len(extra) - ind <= len {
				return nil, fmt.Errorf("Thorchain memo data has insufficient length!")
			}
			var ba = make([]byte, len)
			ba = extra[ind+2 : ind+2+len]
			parsedTxExtra[0x18] = append(parsedTxExtra[0x18], ba)
			ind += len
		} else {
			return nil, fmt.Errorf("fail to parse tx extra!")
		}
	}

	return parsedTxExtra, nil
}
