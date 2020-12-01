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
     Alt_Blocks_Count int
     Bloc_Size_Limit uint
     Block_Size_Median uint
     Block_Weight_Limit uint
     Block_Weight_Median uint
     Bootstrap_Daemon_Address string
     Cumulative_Difficulty int
     Cumulative_Difficulty_Top64 int
     Database_Size int
     Difficulty int64
     Difficulty_Top64 int64
     Free_Space int64
     Grey_Peerlist_Size int
     Height int
     Height_Without_Bootstrap int
     Incoming_Connections_Count int
     Mainnet bool
     Nettype string
     Offline bool
     Outgoing_Connections_Count int
     Rpc_Connections_Count int
     Stagenet bool
     Start_Time int
     Status string
     Target int
     Target_Height int
     Testnet bool
     Top_Block_Hash string
     Tx_Count int
     Tx_Pool_Size int
     Untrusted bool
     Update_Available bool
     Version string
     Was_Bootstrap_Ever_Used bool
     White_Peerlist_Size int
     Wide_Cumulative_Difficulty string
     Wide_Difficulty string
}

type GetVersion_Result struct {
     Status string
     Untrusted bool
     Version int
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
     var height int
     var version string

     // Get the height of the chain
     status, height = GetHeight()
     if (status != nil) {
     } else {
	fmt.Printf("Height = %d\n", height)
     }
     
     status, version = GetVersion()
     if (status != nil) {
     } else {
	fmt.Printf("Version = %s\n", version)
     }
}