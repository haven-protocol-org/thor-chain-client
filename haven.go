package haven

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/btcsuite/btcd/btcec" // TODO: btc imports must be updated with haven imports
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcutil"
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
	logger            zerolog.Logger
	cfg               config.ChainConfiguration
	chain             common.Chain
	privateKey        *btcec.PrivateKey //TODO: must be xhv priv key
	blockScanner      *blockscanner.BlockScanner
	blockMetaAccessor BlockMetaAccessor
	ksWrapper         *KeySignWrapper
	bridge            *thorclient.ThorchainBridge
	globalErrataQueue chan<- types.ErrataBlock
	nodePubKey        common.PubKey
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

	//TODO: implement get private key function
	havenPrivateKey, err := getHavenPrivateKey(thorPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("fail to convert private key for BTC: %w", err)
	}

	ksWrapper, err := NewKeySignWrapper(havenPrivateKey, bridge, tssKm, keySignPartyMgr)
	if err != nil {
		return nil, fmt.Errorf("fail to create keysign wrapper: %w", err)
	}

	nodePubKey, err := common.NewPubKeyFromCrypto(thorKeys.GetSignerInfo().GetPubKey())
	if err != nil {
		return nil, fmt.Errorf("fail to get the node pubkey: %w", err)
	}

	c := &Client{
		logger:     log.Logger.With().Str("module", "haven").Logger(),
		cfg:        cfg,
		chain:      cfg.ChainID,
		privateKey: havenPrivateKey,
		ksWrapper:  ksWrapper,
		bridge:     bridge,
		nodePubKey: nodePubKey,
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
	return "XHV" // common.XHVCHain
}

// GetHeight returns current block height
func (c *Client) GetHeight() (int64, error) {
	return GetHeight()
}

// GetAddress return current signer address, it will be bech32 encoded address
func (c *Client) GetAddress(poolPubKey common.PubKey) string {
	addr, err := poolPubKey.GetAddress("XHV") // common.XHVCHain
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
	totalAmt, err := btcutil.NewAmount(total) // TODO: must be haven amount type
	if err != nil {
		return acct, fmt.Errorf("fail to convert total amount: %w", err)
	}

	// return a new Account with the total amount spendable.
	//TODO: 0,0 in the beginng???
	return common.NewAccount(0, 0, common.AccountCoins{
		common.AccountCoin{
			Amount: uint64(totalAmt),
			Denom:  common.BTCAsset.String(), // TODO: common.XHVAsset.String()
		},
	}, false), nil
}

// OnObservedTxIn gets called from observer when we have a valid observation
// For bitcoin chain client we want to save the utxo we can spend later to sign
func (c *Client) OnObservedTxIn(txIn types.TxInItem, blockHeight int64) {

	// convert TxID to btc hash type
	hash, err := chainhash.NewHashFromStr(txIn.Tx) // TODO: make a haven hash type if necessary
	if err != nil {
		c.logger.Error().Err(err).Str("txID", txIn.Tx).Msg("fail to add spendable utxo to storage")
		return
	}

	// NOTE: The fact that we are calling GetCoin function must mean that each txIn can have multiple asset types.
	// because some chains have multiple assets in the same chain.
	value := float64(txIn.Coins.GetCoin(common.BTCAsset).Amount.Uint64()) / common.One

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
	utxo := NewUnspentTransactionOutput(*hash, 0, value, blockHeight, txIn.ObservedVaultPubKey)
	blockMeta.AddUTXO(utxo)
	if err := c.blockMetaAccessor.SaveBlockMeta(blockHeight, blockMeta); err != nil {
		c.logger.Err(err).Msgf("fail to save block meta to storage,block height(%d)", blockHeight)
	}
}

// FetchTxs retrieves txs for a block height
func (c *Client) FetchTxs(height int64) (types.TxIn, error) {

	block, err := GetBlock(height)
	if err != nil {
		// TODO: check if this error valid for us
		// time.Sleep(c.cfg.BlockScanner.BlockHeightDiscoverBackoff)
		// if rpcErr, ok := err.(*btcjson.RPCError); ok && rpcErr.Code == btcjson.ErrRPCInvalidParameter {
		// 	// this means the tx had been broadcast to chain, it must be another signer finished quicker then us
		// 	return types.TxIn{}, btypes.UnavailableBlock
		// }
		return types.TxIn{}, fmt.Errorf("fail to get block: %w", err)
	}

	// TODO: figure out the reorg
	// if err := c.processReorg(block); err != nil {
	// 	c.logger.Err(err).Msg("fail to process bitcoin re-org")
	// }

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

	txs, err := c.extractTxs(block)
	if err != nil {
		return types.TxIn{}, fmt.Errorf("fail to extract txs from block: %w", err)
	}

	// TODO: what is that
	if err := c.sendNetworkFee(height); err != nil {
		c.logger.Err(err).Msg("fail to send network fee")
	}
	return txs, nil
}

// extractTxs extracts txs from a block to type TxIn
func (c *Client) extractTxs(block Block) (types.TxIn, error) {

	// get txs from daemon
	txs, err := GetTxs(block)
	if err != nil {
		return nil, fmt.Errorf("Failed to get txs from daemon: %w", err)
	}

	// prepare the TxIn
	txIn := types.TxIn{
		Chain: c.GetChain(),
	}

	// populate txItems
	var txItems []types.TxInItem
	for _, tx := range txs {

		// TODO: do we need ignore tx function?
		// if c.ignoreTx(&tx) {
		// 	continue
		// }

		// we don't know the sender
		sender = ""

		// TODO: implement get memo and get gas
		// memo, err := c.getMemo(&tx)
		// if err != nil {
		// 	return types.TxIn{}, fmt.Errorf("fail to get memo from tx: %w", err)
		// }
		// gas, err := c.getGas(&tx)
		// if err != nil {
		// 	return types.TxIn{}, fmt.Errorf("fail to get gas from tx: %w", err)
		// }

		output := c.getOutput(sender, &tx)
		amount, err := btcutil.NewAmount(output.Value)
		if err != nil {
			return types.TxIn{}, fmt.Errorf("fail to parse float64: %w", err)
		}
		amt := uint64(amount.ToUnit(btcutil.AmountSatoshi))
		txItems = append(txItems, types.TxInItem{
			BlockHeight: block.Height,
			Tx:          tx.Txid,
			Sender:      sender,
			To:          output.ScriptPubKey.Addresses[0],
			Coins: common.Coins{
				common.NewCoin(common.BTCAsset, cosmos.NewUint(amt)),
			},
			Memo: memo,
			Gas:  gas,
		})

	}
	txIn.TxArray = txItems
	txIn.Count = strconv.Itoa(len(txItems))
	return txIn, nil
}

func (c *Client) getOutput(tx *RawTx) (interface{}, error) {

	// we should return the an amount and a public spend key

	// parse tx extra
	var status, parsedTxExtra = c.parseTxExtra(tx.Extra)
	if status != nil {
		fmt.Printf("Error: %q\n", status)
	}

	// get tx public key
	var txPubKey [32]byte
	// TODO: don't forget we can have multiple tx public keys
	copy(txPubKey[:], parsedTxExtra[1][0][0:32])

	// generate the shared secret
	sharedSecret, status := crypto.GenerateKeyDerivation(&txPubKey, &viewKey)
	if status != nil {
		fmt.Printf("Error Creating Shared Secret: %q\n", status)
		continue
	}

	for ind, vout := range tx.Vout {

		derivedTarget, status := crypto.DerivePublicKey((*sharedSecret)[:], uint64(ind), &publicSpendKey)
		if status != nil {
			fmt.Printf("Error Deriving a Target: %q\n", status)
			continue
		}

		//TODO: we also should record the output asset type here
		// so that we can pass it in the txIn to the observer
		found := false
		if len(vout.Target.Key) != 0 {
			var targetRaw, _ = hex.DecodeString(vout.Target.Key)
			var target [32]byte
			copy(target[:], targetRaw)
			if *derivedTarget == target {
				found = true
			}
		} else {
			var targetRaw, _ = hex.DecodeString(vout.Target.Offshore)
			var target [32]byte
			copy(target[:], targetRaw)
			if *derivedTarget == target {
				found = true
			}
		}

		if found {
			// decode the tx amount
			fmt.Printf("We are the receiver. Trying to decode the amount (index = %d)\n", ind)
			scalar := crypto.DerivationToScalar(sharedSecret[:], uint64(ind));
			ecdhInfo := crypto.EcdhDecode(rawTx.Rct_Signatures.EcdhInfo[ind], *scalar)
			var C, Ctmp [32]byte
			check := crypto.AddKeys2(&Ctmp, ecdhInfo.Mask, ecdhInfo.Amount, crypto.H)
			if check {
			  if len(vout.Target.Key) != 0 {
			    // Onshore amount (XHV)
			    Craw, _ := hex.DecodeString(rawTx.Rct_Signatures.OutPk[ind])
			    copy(C[:], Craw)
			  } else {
			    // Offshore amount (xUSD)
			    Craw, _ := hex.DecodeString(rawTx.Rct_Signatures.OutPk_Usd[ind])
			    copy(C[:], Craw)
			  }
			  if (crypto.EqualKeys(C, Ctmp)) {
			    //fmt.Printf("RCT outPk = %q\n", rawTx.Rct_Signatures.OutPk)
			    //fmt.Printf("RCT outpk_usd = %q\n", rawTx.Rct_Signatures.OutPk_Usd)
			    //fmt.Printf("C = %x, Ctmp = %x\n", C, Ctmp)				  
			    fmt.Printf("Mask: %x \n  Amount: %d \n", ecdhInfo.Mask, crypto.H2d(ecdhInfo.Amount))
			  }
			}

		} else {
			// ignore tx. We aren't reciver
		}

	}
}

func (c *Client) parseTxExtra(extra []byte) (map[byte][][]byte, error) {

	var parsedTxExtra = make(map[byte][][]byte)

	for ind := 0; ind < len(extra); ind++ {

		if extra[ind] == 0 {
			// Padding
		} else if extra[ind] == 0x01 {
			// Pubkey - 32 byte key (fixed length)
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
		} else if extra[ind] == 0xde {
			// miner gate tag
			var len = int(extra[ind+1])
			ind += len
		} else if extra[ind] == 0x17 {
			// Offshore data
			var len = int(extra[ind+1])
			var ba = make([]byte, len)
			ba = extra[ind+2 : ind+2+len]
			parsedTxExtra[0x17] = append(parsedTxExtra[0x17], ba)
			ind += len
		} else if extra[ind] == 0x18 {
		        // Thorchain data
			var len = int(extra[ind+1])
			var ba = make([]byte, len)
			ba = extra[ind+2 : ind+2+len]
			parsedTxExtra[0x18] = append(parsedTxExtra[0x18], ba)
			ind += len
		} else {
		}
	}

	var err error // TODO: error handling while parsing
	return parsedTxExtra, err
}
