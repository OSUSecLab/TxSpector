package mongo

// Databse 1, store the basic transaction metadata
type Transac struct {
	// Transaction 
	Tx_BlockHash string
	Tx_BlockNum string 
	Tx_FromAddr string
	Tx_Gas string
	Tx_GasPrice string
	Tx_Hash string 
	Tx_Input string 
	Tx_Nonce string
	Tx_ToAddr string
	Tx_Index string
	Tx_Value string

	Tx_Trace string

	Re_contractAddress string
	Re_CumulativeGasUsed string
	Re_GasUsed string
	Re_Status  string
	Re_FailReason string
}

var BashNum int = 50
var BashTxs = make([]interface{}, BashNum)
var CurrentNum int = 0
