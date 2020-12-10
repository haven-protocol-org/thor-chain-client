package crypto

import (
	"fmt"

	"github.com/patcito/monero/crypto"
	"golang.org/x/crypto/curve25519"
)

func ecdhHash(sharedSecret []byte) [32]byte {
	var data []byte
	data = []byte("amount")
	data = append(data, sharedSecret...)
	var result [32]byte
	crypto.hashToScalar(&result, data)
	return result
}

func genCommitmentMask(sharedSecret []byte) [32]byte {
	var data []byte
	data = []byte("commitment_mask")
	data = append(data, sharedSecret...)
	var result [32]byte
	crypto.hashToScalar(&result, data)
	return result
}

func xor8(keyV []byte, keyK []byte) {
	for ind := 0; ind < 8; ind++ {
		keyV[ind] ^= keyK[ind]
	}
}

func ecdhDecode(ecdhInfo map[string]string, sharedSecret []byte) {
	var mask = genCommitmentMask(sharedSecret)
	fmt.Printf("mask: %x\n", mask)
	xor8([]byte(ecdhInfo["amount"]), ecdhHash(sharedSecret))
	fmt.Printf("amount: %x", ecdhInfo["amount"])
}
