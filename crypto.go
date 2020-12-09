package monero

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/curve25519"
)

func hashToScalar(data []byte) common.Hash {
	return crypto.Keccak256Hash(data)
	// var reducedHash [32]byte
	// edwards25519.ScReduce(&reducedHash, &([64]byte(hash)))
}

func ecdhHash(sharedSecret []byte) common.Hash {
	var data []byte
	data = []byte("amount")
	data = append(data, sharedSecret...)
	return hashToScalar(data)
}

func genCommitmentMask(sharedSecret []byte) common.Hash {
	var data []byte
	data = []byte("commitment_mask")
	data = append(data, sharedSecret...)
	return hashToScalar(data)
}

func xor8(keyV []byte, keyK []byte) {
	for ind := 0; ind < 8; ind++ {
		keyV[ind] ^= keyK[ind]
	}
}

func generateKeyDerivation(key1 []byte, key2 []byte) []byte {
	derivation, err := curve25519.X25519(key1, key2)
	if err != nil {
		// do nothing
	}
	return derivation
}

func ecdhDecode(ecdhInfo map[string]string, sharedSecret []byte) {
	var mask = genCommitmentMask(sharedSecret)
	fmt.Printf("mask: %x\n", mask)
	xor8([]byte(ecdhInfo["amount"]), ecdhHash(sharedSecret).Bytes())
	fmt.Printf("amount: %x", ecdhInfo["amount"])
}
