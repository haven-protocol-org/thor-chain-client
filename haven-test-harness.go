// nolint:errcheck
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/rpc"

	"github.com/haven-protocol-org/monero-go-utils/crypto"
	"github.com/powerman/rpc-codec/jsonrpc2"
)

type GetInfoResult struct {
	Alt_Blocks_Count            int
	Bloc_Size_Limit             uint
	Block_Size_Median           uint
	Block_Weight_Limit          uint
	Block_Weight_Median         uint
	Bootstrap_Daemon_Address    string
	Cumulative_Difficulty       int
	Cumulative_Difficulty_Top64 int
	Database_Size               int
	Difficulty                  int64
	Difficulty_Top64            int64
	Free_Space                  int64
	Grey_Peerlist_Size          int
	Height                      int
	Height_Without_Bootstrap    int
	Incoming_Connections_Count  int
	Mainnet                     bool
	Nettype                     string
	Offline                     bool
	Outgoing_Connections_Count  int
	Rpc_Connections_Count       int
	Stagenet                    bool
	Start_Time                  int
	Status                      string
	Target                      int
	Target_Height               int
	Testnet                     bool
	Top_Block_Hash              string
	Tx_Count                    int
	Tx_Pool_Size                int
	Untrusted                   bool
	Update_Available            bool
	Version                     string
	Was_Bootstrap_Ever_Used     bool
	White_Peerlist_Size         int
	Wide_Cumulative_Difficulty  string
	Wide_Difficulty             string
}

type BlockHeader struct {
	Block_Size    int
	Depth         int
	Difficulty    int64
	Hash          string
	Height        int64
	Major_version int
	Minor_version int
	Nonce         int64
	Num_txes      int
	Orphan_status bool
	Prev_hash     string
	Reward        int64
	Timestamp     int64
}

type Block struct {
	Blob          string
	Block_Header  BlockHeader
	Json          string
	Miner_Tx_Hash string
	Status        string
	Untrusted     bool
	Tx_Hashes     []string
}

type VinKey struct {
	Amount      int64
	Key_Offsets []int64
	K_Image     string
}

type VinEntry struct {
	Key      VinKey
	Onshore  VinKey
	Offshore VinKey
}

type VoutKey struct {
	Key      string
	Offshore string
}

type VoutEntry struct {
	Amount int64
	Target VoutKey
}

type RctSignatures struct {
	Type               int
	TxnFee             int64
	TxnFee_Usd         int64
	TxnOffshoreFee     int64
	TxnOffshoreFee_Usd int64
	EcdhInfo           []map[string][]byte
	OutPk              []string
	OutPk_Usd          []string
}

type RawTx struct {
	Version        int
	Unlock_Time    int
	Vin            []VinEntry
	Vout           []VoutEntry
	Extra          []byte
	Rct_Signatures RctSignatures
}

func ParseTxExtra(extra []byte) (error, map[byte][][]byte) {

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
		} else {
		}
	}

	var err error

	return err, parsedTxExtra
}

func GetBlock(height int) (error, Block) {

	// Connect to daemon RPC server
	clientHTTP := jsonrpc2.NewHTTPClient("http://127.0.0.1:27750/json_rpc")
	defer clientHTTP.Close()

	req := map[string]int{"height": height}

	var reply Block
	var err error

	// Get Height
	err = clientHTTP.Call("get_block", req, &reply)
	if err == rpc.ErrShutdown || err == io.ErrUnexpectedEOF {
		fmt.Printf("Error(): %q\n", err)
	} else if err != nil {
		rpcerr := jsonrpc2.ServerError(err)
		fmt.Printf("Error(): code=%d msg=%q data=%v reply=%v\n", rpcerr.Code, rpcerr.Message, rpcerr.Data, reply)
	}

	return err, reply
}

func GetTxes(txes []string) (error, []RawTx) {

	requestBody, err := json.Marshal(map[string]interface{}{"txs_hashes": txes, "decode_as_json": true})
	if err != nil {
		fmt.Printf("Marshaling Error: %q\n", err)
		return err, nil
	}

	resp, err := http.Post("http://127.0.0.1:27750/get_transactions", "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		fmt.Printf("Http Error: %q\n", err)
		return err, nil
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Read Error: %q\n", err)
		return err, nil
	}

	type GetTxResult struct {
		Status      string
		Txs_As_Json []string
	}

	var txResult GetTxResult
	var rawTxs []RawTx

	// parse the returned resutl
	json.Unmarshal(body, &txResult)

	// parse each tx in the result and save
	for _, jsonTx := range txResult.Txs_As_Json {
		var rawTx RawTx
		json.Unmarshal([]byte(jsonTx), &rawTx)
		rawTxs = append(rawTxs, rawTx)
	}

	return err, rawTxs
}

func GetHeight() (error, int) {

	// Connect to daemon RPC server
	clientHTTP := jsonrpc2.NewHTTPClient("http://127.0.0.1:17750/json_rpc")
	defer clientHTTP.Close()

	var reply GetInfoResult
	var err error

	// Get Height
	err = clientHTTP.Call("get_info", nil, &reply)
	if err == rpc.ErrShutdown || err == io.ErrUnexpectedEOF {
		fmt.Printf("Error(): %q\n", err)
	} else if err != nil {
		rpcerr := jsonrpc2.ServerError(err)
		fmt.Printf("Error(): code=%d msg=%q data=%v reply=%v\n", rpcerr.Code, rpcerr.Message, rpcerr.Data, reply)
	}

	return err, reply.Height
}

func GetVersion() (error, string) {

	// Connect to daemon RPC server
	clientHTTP := jsonrpc2.NewHTTPClient("http://127.0.0.1:17750/json_rpc")
	defer clientHTTP.Close()

	var reply GetInfoResult
	var err error

	// Get Height
	err = clientHTTP.Call("get_info", nil, &reply)
	if err == rpc.ErrShutdown || err == io.ErrUnexpectedEOF {
		fmt.Printf("Err3(): %q\n", err)
	} else if err != nil {
		rpcerr := jsonrpc2.ServerError(err)
		fmt.Printf("Err3(): code=%d msg=%q data=%v reply=%v\n", rpcerr.Code, rpcerr.Message, rpcerr.Data, reply)
	}

	return err, reply.Version
}

func h2d(key [32]byte) uint64 {
	var val uint64 = 0
	var j int = 0
	for j = 7; j >= 0; j-- {
		val = uint64(val*256 + uint64(key[j]))
	}
	return val
}

func main() {

	// get block
	status, blk := GetBlock(5005)
	if status != nil {
		return
	}

	// get the tx data
	status, rawTxes := GetTxes(blk.Tx_Hashes)

	// decode viewKey
	viewKeyRaw, _ := hex.DecodeString("67196f0bb28a661933e5d8bffe13d063b57be21323ce84e844c800878b5d9102")
	var viewKey [32]byte
	copy(viewKey[:], viewKeyRaw)

	// decode spendKey
	publicSpendKeyRaw, _ := hex.DecodeString("5d33ee523d3f304d2e1892f57bc7f96761cf892ef98fc1ddd3e4763bc0e6e13c")
	var publicSpendKey [32]byte
	copy(publicSpendKey[:], publicSpendKeyRaw)

	for _, rawTx := range rawTxes {

		// parse tx extra
		var status, parsedTxExtra = ParseTxExtra(rawTx.Extra)
		if status != nil {
			fmt.Printf("Error: %q\n", status)
		}

		// get tx public key
		var txPubKey [32]byte
		copy(txPubKey[:], parsedTxExtra[1][0][0:32])

		// generate the shared secret
		sharedSecret, status := crypto.GenerateKeyDerivation(&txPubKey, &viewKey)
		if status != nil {
			fmt.Printf("Error Creating Shared Secret: %q\n", status)
			continue
		}

		for ind, vout := range rawTx.Vout {

			derivedTarget, status := crypto.DerivePublicKey((*sharedSecret)[:], uint64(ind), &publicSpendKey)
			if status != nil {
				fmt.Printf("Error Deriving a Target: %q\n", status)
				continue
			}

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
				fmt.Printf("We are the reciver. Trying to decode the amount.. %d\n", ind)
				ecdhInfo := crypto.EcdhDecode(rawTx.Rct_Signatures.EcdhInfo[ind], *sharedSecret)
				fmt.Printf("MAsk: %x \n  Amount: %d \n", ecdhInfo.Mask, h2d(ecdhInfo.Amount))

				// TODO: check if the provided commitment is correct
			} else {
				// ignore tx. We aren't reciver
			}

		}

		fmt.Printf("--------\n")

		// Decode the ECDHINFO blocks to get the amounts
	}
}
