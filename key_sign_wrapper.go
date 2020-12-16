package haven

import (
	"fmt"

	moneroCrypto "github.com/haven-protocol-org/monero-go-utils/crypto"
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
	privViewKey     [32]byte
	privSpendKey    [32]byte
	pubKey          common.PubKey
	tssKeyManager   tss.ThorchainKeyManager
	logger          zerolog.Logger
	keySignPartyMgr *thorclient.KeySignPartyMgr
}

// NewKeysignWrapper create a new instance of Keysign Wrapper
func NewKeySignWrapper(privViewKey *[32]byte, privSpendKey *[32]byte, bridge *thorclient.ThorchainBridge, tssKeyManager tss.ThorchainKeyManager, keySignPartyMgr *thorclient.KeySignPartyMgr) (*KeySignWrapper, error) {
	pubKey, err := GetBech32AccountPubKey(privSpendKey)
	if err != nil {
		return nil, fmt.Errorf("fail to get the pubkey: %w", err)
	}
	return &KeySignWrapper{
		privViewKey:     privViewKey,
		privSpendKey:    privSpendKey,
		pubKey:          pubKey,
		tssKeyManager:   tssKeyManager,
		logger:          log.Logger.With().Str("module", "keysign_wrapper").Logger(),
		keySignPartyMgr: keySignPartyMgr,
	}, nil
}

// GetBech32AccountPubKey calculate the pubkey given private key
func GetBech32AccountPubKey(key *[32]byte) (common.PubKey, error) {
	var buf [32]byte
	moneroCrypto.PublicFromSecret(&buf, key)
	var pk secp256k1.PubKeySecp256k1
	copy(pk[:], buf)
	return common.NewPubKeyFromCrypto(pk)
}

// getHavenPrivateKey contructs a private key from a thorchain private key
func getHavenPrivateKey(key crypto.PrivKey) (secretViewKey *[32]byte, secretSpendKey *[32]byte) {
	priKey, ok := key.(secp256k1.PrivKeySecp256k1)
	// generate secret spend key
	h := moneroCrypto.NewHash()
	var keyHash [32]byte
	h.Write(priKey[:])
	h.Sum(keyHash[:0])
	moneroCrypto.SecretFromSeed(secretSpendKey, &keyHash)
	// genere secret view key
	moneroCrypto.ViewFromSpend(secretViewKey, secretSpendKey)
	return
}
