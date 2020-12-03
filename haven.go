package haven

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec" // TODO: must be removed
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
