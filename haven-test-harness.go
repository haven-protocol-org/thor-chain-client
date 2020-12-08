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

type GetInfo_Result struct {
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

type GetVersion_Result struct {
	Status    string
	Untrusted bool
	Version   int
}

type Block_Header struct {
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

type BLOCK struct {
	Blob          string
	Block_Header  Block_Header
	Json          string
	Miner_Tx_Hash string
	Status        string
	Untrusted     bool
	Tx_Hashes     []string
}

type key struct {
	Amount      int64
	Key_Offsets []int64
	K_Image     string
}

type Vin_Arr struct {
	Key      key
	Onshore  key
	Offshore key
}

type TX struct {
	Version     int
	Unlock_Time int
	Vin         []Vin_Arr
}

func GetBlock(height int) (error, BLOCK) {

	// Connect to daemon RPC server
	clientHTTP := jsonrpc2.NewHTTPClient("http://127.0.0.1:27750/json_rpc")
	defer clientHTTP.Close()

	req := map[string]int{"height": height}

	var reply BLOCK
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

func GetTxes(txes []string) {

	requestBody, err := json.Marshal(map[string]interface{}{"txs_hashes": txes, "decode_as_json": true})
	if err != nil {
		fmt.Printf("Marshaling Error: %q\n", err)
	}

	resp, err := http.Post("http://127.0.0.1:27750/get_transactions", "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		fmt.Printf("Http Error: %q\n", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Read Error: %q\n", err)
	}

	type GET_TX_RESULT struct {
		Status      string
		Txs_As_Json []string
	}

	var myres GET_TX_RESULT

	json.Unmarshal(body, &myres)

	// var myTxs []TX

	for ind, tx := range myres.Txs_As_Json {
		var mytx TX
		json.Unmarshal([]byte(tx), &mytx)
	}

	fmt.Printf("TXS: %s", myres.Txs_As_Json[3])
}

func GetHeight() (error, int) {

	// Connect to daemon RPC server
	clientHTTP := jsonrpc2.NewHTTPClient("http://127.0.0.1:17750/json_rpc")
	defer clientHTTP.Close()

	var reply GetInfo_Result
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

	var reply GetInfo_Result
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

func main() {

	// Local vars
	var status error
	// var height int
	// var version string
	var blk BLOCK
	//var txes []string

	// Get the height of the chain
	// status, height = GetHeight()
	// if (status != nil) {
	// } else {
	// fmt.Printf("Height = %d\n", height)
	// }

	// status, version = GetVersion()
	// if (status != nil) {
	// } else {
	// fmt.Printf("Version = %s\n", version)
	// }

	status, blk = GetBlock(5005)
	if status != nil {
		return
	}

	GetTxes(blk.Tx_Hashes)

	// fmt.Printf("Block = %s\n", blk.Json)
	/*
		if (len(blk.Tx_Hashes) > 0) {
		    status, []txes = GetTxes(blk.Tx_Hashes)
		}
	*/
}
