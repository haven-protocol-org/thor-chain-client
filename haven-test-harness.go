// nolint:errcheck
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/rpc"

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
	EcdhInfo           []map[string]string
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

type CreatedTx struct {
	Amount_List      []uint64
	Fee_List         []uint64
	Multisig_Txset   string
	Tx_Hash_List     []string
	Tx_Key_List      []string
	Unsigned_Txset   string
	Tx_Blob_List     []string
	Tx_Metadata_List []string
}

func ParseTxExtra(extra []byte) (error, map[byte][][]byte) {

	var parsedTxExtra = make(map[byte][][]byte)

	for ind := 0; ind < len(extra); ind++ {

		if extra[ind] == 0 {
			// Padding
			var len = int(extra[ind+1])
			ind += len
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
			ind += 32
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

func CreateTx(dsts []map[string]interface{}, asset string) (CreatedTx, error) {

	// Connect to Wallet RPC server
	clientHTTP := jsonrpc2.NewHTTPClient("http://127.0.0.1:12345/json_rpc")
	defer clientHTTP.Close()

	// create a request
	req := map[string]interface{}{"destinations": dsts, "priority": 0, "ring_size": 12, "get_tx_keys": true, "get_tx_hex": true, "get_tx_metadata": true, "do_not_relay": true}

	var reply CreatedTx
	var err error

	// call the rpc method
	if asset == "XHV" {
		err = clientHTTP.Call("transfer_split", req, &reply)
	} else {
		err = clientHTTP.Call("offshore_transfer", req, &reply)
	}

	// check for errors
	if err == rpc.ErrShutdown || err == io.ErrUnexpectedEOF {
		fmt.Printf("Error(): %q\n", err)
		return reply, err
	} else if err != nil {
		rpcerr := jsonrpc2.ServerError(err)
		fmt.Printf("Error(): code=%d msg=%q data=%v reply=%v\n", rpcerr.Code, rpcerr.Message, rpcerr.Data, reply)
		return reply, err
	}

	return reply, nil
}

func sendRawTx(txHash string) BroadcastTxResponse {

	var reply BroadcastTxResponse

	requestBody, err := json.Marshal(map[string]interface{}{"tx_as_hex": txHash, "do_not_relay": false})
	if err != nil {
		reply.Status = "Marshaling Request Error"
		reply.Reason = fmt.Sprintf("%+v", err)
	}

	resp, err := http.Post("http://127.0.0.1:27750/sendrawtransaction", "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		reply.Status = "Http Error"
		reply.Reason = fmt.Sprintf("%+v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		reply.Status = "Read Error"
		reply.Reason = fmt.Sprintf("%+v", err)
	}

	// parse the returned resutl
	err := json.Unmarshal(body, &reply)
	if err != nil {
		reply.Status = "Unmarshaling Response Error"
		reply.Reason = fmt.Sprintf("%+v", err)
	}

	return reply
}

func OpenWallet(walletName string, password string) bool {
	// Connect to daemon RPC server
	clientHTTP := jsonrpc2.NewHTTPClient("http://127.0.0.1:12345/json_rpc")
	defer clientHTTP.Close()

	req := map[string]interface{}{"filename": walletName, "password": password}

	type Reply struct {
	}

	var reply Reply
	var err error

	// Get Height
	err = clientHTTP.Call("open_wallet", req, &reply)
	if err == rpc.ErrShutdown || err == io.ErrUnexpectedEOF {
		fmt.Printf("Error(): %q\n", err)
		return false
	} else if err != nil {
		rpcerr := jsonrpc2.ServerError(err)
		fmt.Printf("Error(): code=%d msg=%q data=%v reply=%v\n", rpcerr.Code, rpcerr.Message, rpcerr.Data, reply)
		return false
	}

	return true
}

func main() {

	walletName := ""
	password := ""

	if !OpenWallet(walletName, password) {
		fmt.Errorf("Fail to open the haven wallet!")
	}

	var dsMap = make(map[string]interface{})
	var dsts = make([]map[string]interface{}, 1)

	dsMap["amount"] = 15000000000000 // 15 haven
	dsMap["address"] = "hvtaQ6uCjVWhLBniot3JS2S2eyoyvLzVCD3BGkkoLfqoayPj6Ejtc747bga2tNRPWtPAtJCtW9bH31e2kpBWMMcN1JskKRAadb"

	dsts[0] = dsMap
	resp, _ := CreateTx(dsts, "XHV")

	sendRawTx(resp.Tx_Blob_List[0])
}
