package haven

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec" // TODO: btc imports must be updated with haven imports
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcutil"
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
	// just to get rid of  the error
	txIn := types.TxIn{
		Chain: c.GetChain(),
	}
	var txItems []types.TxInItem
	txIn.TxArray = txItems
	return txIn, nil
}
