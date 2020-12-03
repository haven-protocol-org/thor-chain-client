package haven

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/secp256k1"
	"gitlab.com/thorchain/thornode/bifrost/thorclient"
	"gitlab.com/thorchain/thornode/bifrost/tss"
	"gitlab.com/thorchain/thornode/common"
)

// KeySignWrapper is a wrap of private key and also tss instance
// it also implement the txscript.Signable interface, and will decide which method to use based on the pubkey
type KeySignWrapper struct {
	privateKey      *btcec.PrivateKey
	pubKey          common.PubKey
	tssKeyManager   tss.ThorchainKeyManager
	logger          zerolog.Logger
	keySignPartyMgr *thorclient.KeySignPartyMgr
}

// NewKeysignWrapper create a new instance of Keysign Wrapper
func NewKeySignWrapper(privateKey *btcec.PrivateKey, bridge *thorclient.ThorchainBridge, tssKeyManager tss.ThorchainKeyManager, keySignPartyMgr *thorclient.KeySignPartyMgr) (*KeySignWrapper, error) {
	pubKey, err := GetBech32AccountPubKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("fail to get the pubkey: %w", err)
	}
	return &KeySignWrapper{
		privateKey:      privateKey,
		pubKey:          pubKey,
		tssKeyManager:   tssKeyManager,
		logger:          log.Logger.With().Str("module", "keysign_wrapper").Logger(),
		keySignPartyMgr: keySignPartyMgr,
	}, nil
}

// GetBech32AccountPubKey calculate the pubkey given private key
func GetBech32AccountPubKey(key *btcec.PrivateKey) (common.PubKey, error) {
	// TODO: change name of this function from GetBech32AccountPubKey to getPubKeyFromPrivateKey
	buf := key.PubKey().SerializeCompressed()
	var pk secp256k1.PubKeySecp256k1
	copy(pk[:], buf)
	return common.NewPubKeyFromCrypto(pk)
}

// getHavenPrivateKey contructs a private key from a thorchain private key
func getHavenPrivateKey(key crypto.PrivKey) (*btcec.PrivateKey, error) {
	priKey, ok := key.(secp256k1.PrivKeySecp256k1)
	if !ok {
		return nil, errors.New("invalid private key type")
	}
	privateKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), priKey[:])
	return privateKey, nil
}
