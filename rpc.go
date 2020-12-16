package haven

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
	Height                      uint64
	Height_Without_Bootstrap    uint64
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
	Block_Height   uint64
}

// GetHeight gets the height of the haven blockchain
func GetHeight() (uint64, error) {

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

	return reply.Height, err
}

// GetVersion gets the version of the running haven daemon
func GetVersion() (string, error) {

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

	return reply.Version, err
}

func GetBlock(height int) (Block, error) {

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
		return nil, err
	} else if err != nil {
		rpcerr := jsonrpc2.ServerError(err)
		fmt.Printf("Error(): code=%d msg=%q data=%v reply=%v\n", rpcerr.Code, rpcerr.Message, rpcerr.Data, reply)
		return nil, err
	}

	return reply, err
}

func GetTxes(txes []string) ([]RawTx, error) {

	requestBody, err := json.Marshal(map[string]interface{}{"txs_hashes": txes, "decode_as_json": true})
	if err != nil {
		fmt.Printf("Marshaling Error: %q\n", err)
		return nil, err
	}

	resp, err := http.Post("http://127.0.0.1:27750/get_transactions", "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		fmt.Printf("Http Error: %q\n", err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Read Error: %q\n", err)
		return nil, err
	}

	type Tx struct {
		Block_Height uint64
	}

	type GetTxResult struct {
		Status      string
		Txs_As_Json []string
		Txs         []Tx
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
		rawTxs.Block_Height = txResult.Txs[ind].Block_Height
	}

	return rawTxs, err
}

func GetPoolTxs() ([]string, error) {

	resp, err := http.Get("http://127.0.0.1:27750/get_transaction_pool")
	if err != nil {
		fmt.Printf("Http Error: %q\n", err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Read Error: %q\n", err)
		return nil, err
	}

	type Tx struct {
		Id_Hash string
	}

	type getPoolTxs struct {
		Transactions []Tx
	}

	var result getPoolTxs

	// parse the returned resutl
	err = json.Unmarshal(body, &result)
	if err != nil {
		fmt.Printf("There was an error decoding the json. err = %s", err)
		return nil, err
	}

	var returnResult = make([]string, 0)
	for _, Tx := range result.Transactions {
		returnResult = append(returnResult, Tx.Id_Hash)
	}

	return returnResult, nil
}
