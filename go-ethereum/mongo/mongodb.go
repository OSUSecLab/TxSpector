package mongo

import (
	"bytes"
	"os"
	"gopkg.in/mgo.v2"
)

var SessionGlobal *mgo.Session
var TraceGlobal = bytes.NewBuffer(make([]byte, 0, 10485760))
var CurrentTx string
var CurrentBlockNum uint64
var TxVMErr string
var ErrorFile *os.File

func InitMongoDb() {
	var err error
    	if SessionGlobal, err = mgo.Dial(""); err != nil {
        	panic(err)
   	}

	ErrorFile, err = os.OpenFile("db_error.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
}
