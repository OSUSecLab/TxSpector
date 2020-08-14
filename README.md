# TxSpector
TxSpector is the first generic logic-driven framework for uncovering attacks on Ethereum Blockchain from transactions.

## Revised Go-Ethereum 
### Generate transaction trace by replaying transactions in the Ethereum Blockchain
To collect transaction trace, we revised the offcial [Go-Ethereum EVM](https://github.com/ethereum/go-ethereum) to record transaction info, such as its date, sender, reciver, and so on. To obtain all the transaction traces in Ethereum Blockchain, you can just replay all the transactions by syncing. For only one transaction, you can simulate the interaction with the geth client. The traces will be recorded in the MongoDB dataset named "geth" automatically. 

## Revised files
*go-ethereum/mongo/mongodb.go initializes the mongodb and creates some global data, such as transaction related metadata. <br />
*go-ethereum/mongo/bashdb.go creates the struct Transac that is used to store the transaction related info, including the transaction trace. <br />
*go-ethereum/core/state_processor.go and core/state_transition.go deal with the logic that execute transactions. <br />
*go-ethereum/core/state_prefetcher.go and core/vm/evm.go are changed to remove the redundency casued by prefetching. <br />
*go-ethereum/core/vm/interpreter.go, in Run function, every opcode is executed and its related trace is recored into the dataset. <br />
*go-ethereum/core/vm/instructions.go, every opcode related function is changed to return the results that we need for the furture anlysis, which are the arguments of the opcode. <br />
*go-ethereum/core/vm/tx_pool.go stores the left transaction traces into the "geth" mongodb dataset. <br />

# Detector 

## Requirements
Modules needed from python are put in the detector/requirements.txt. In addition, we need souffle. Other versions may also work.
```
souffle==1.5.1
```

## Analyze the transaction trace and detect attacks
With the traces being collected, TxSpector can parse the trace into the EFG (execution flow graph). Then the trace opcode based EFG is converted into the IR based EFG and the logic relations are exported afterwards. Specifically, logic relations represent the data and control dependencies of the transactions. An example is a transaction trace example stored in the directory example 0x37085f336b5d3e588e37674544678f8cb0fc092a6de5d83bd647e20e5232897b.txt, to generate facts/logic relations, the command should be as the following: <br />
```
./bin/analyze_geth.sh  trace_file  facts_dir
```
```
./detector/bin/analyze_geth.sh 0x37085f336b5d3e588e37674544678f8cb0fc092a6de5d83bd647e20e5232897b.txt facts
```

Before detecting the attacks, we need to generate a facts "sc_addr.facts" by ourself, in which we only need to fill the receiver smart contract address. This facts file will be used to detect reentrancy attack. You can use the browser Etherscan [0x37085f336b5d3e588e37674544678f8cb0fc092a6de5d83bd647e20e5232897b](https://etherscan.io/tx/0x37085f336b5d3e588e37674544678f8cb0fc092a6de5d83bd647e20e5232897b) to obtain the info or use the go-ethereum to get the related info. 



After the facts are generated, users can customize their detection rules to detect related attacks. We define some rules in the directory rules. An example is that with the generated facts, we can use the following command: <br />
```
souffle -F facts_dir detection_rule_file
```
```
souffle -F facts ./detector/rules/1Reentrancy.dl (detect reentrancy attack)
```

Now we have the final results in file ReenResult.csv that have some metadata for forensic analysis. <br />

## Files
* directory bin storess the files that are used to analyze. <br />
* directory rules stores the rules to detect the attacks, including reentrancy attack, unchecked call attack,  failed send attack, timestamp dependence attack and other similar opcodes dependency attack, unsecured balance attack, misuse of origin attack, sucidal attack, and securify based reentrancy attack. <br />
* directory src stores the code <br />
   src/opcode.py stores the opcodes of EVM <br />
   src/evm_efg.py parses the transaction trace and builds a trace-based EFG (Execution Flow Graph) <br />
   src/tac_efg.py generates a IR (Intermediate Representation) based EFG <br />
   src/exporter.py exports the needed facts <br />
   other files are helpers to analyze <br />
