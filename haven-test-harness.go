// nolint:errcheck
package main

import (
	"fmt"
	"io"
	"net/rpc"

	"github.com/powerman/rpc-codec/jsonrpc2"
)

type BlockHeader struct {
}                     

type GetInfo_Result struct {
     alt_blocks_count uint
     block_size_limit uint
     block_size_median uint
     block_weight_limit uint
     block_weight_median uint
     bootstrap_daemon_address string
     cumulative_difficulty uint64
     cumulative_difficulty_top64 uint64
     database_size uint64
     difficulty uint64
     difficulty_top64 uint64
     free_space uint64
     grey_peerlist_size uint
     height uint
     height_without_bootstrap uint
     incoming_connections_count uint
     mainnet bool
     nettype string
     offline bool
     outgoing_connections_count uint
     rpc_connections_count uint
     stagenet bool
     start_time uint
     status string
     target uint
     target_height uint
     testnet bool
     top_block_hash string
     tx_count uint
     tx_pool_size uint
     untrusted bool
     update_available bool
     version string
     was_bootstrap_ever_used bool
     white_peerlist_size uint
     wide_cumulative_difficulty string
     wide_difficulty string
}

type GetVersion_Result struct {
     Status string
     Untrusted bool
     Version int
}

func GetHeight() {
     
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
     } else {
         fmt.Printf("Status=%v Height=%d Reply=%v\n", reply.status, reply.height, reply);
     }
}

func main() {

	GetHeight()

	// Client use HTTP transport.
	clientHTTP := jsonrpc2.NewHTTPClient("http://127.0.0.1:17750/json_rpc")
	defer clientHTTP.Close()

	var reply GetVersion_Result
	var err error

	// Synchronous call using named params and HTTP with context.
	err = clientHTTP.Call("get_version", nil, &reply)
	if err == rpc.ErrShutdown || err == io.ErrUnexpectedEOF {
		fmt.Printf("Err3(): %q\n", err)
	} else if err != nil {
		rpcerr := jsonrpc2.ServerError(err)
		fmt.Printf("Err3(): code=%d msg=%q data=%v reply=%v\n", rpcerr.Code, rpcerr.Message, rpcerr.Data, reply)
	} else {
		fmt.Printf("Status=%v Untrusted=%q Version=%d\n", reply.Status, reply.Untrusted, reply.Version);
	}

}
