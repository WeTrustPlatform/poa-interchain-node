package main

import (
	"context"
	"flag"
	"io/ioutil"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/WeTrustPlatform/interchain-node/bind/mainchain"
	"github.com/WeTrustPlatform/interchain-node/bind/sidechain"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

//go:generate mkdir -p ../../bind/mainchain/
//go:generate mkdir -p ../../bind/sidechain/
//go:generate abigen --sol ../../interchain-node-contracts/contracts/MainChain.sol --pkg mainchain --out ../../bind/mainchain/main.go
//go:generate abigen --sol ../../interchain-node-contracts/contracts/SideChain.sol --pkg sidechain --out ../../bind/sidechain/main.go

func main() {
	// Command line flags
	keyJSONPath := flag.String("keyjson", "", "Path to the JSON private key file of the sealer")
	password := flag.String("password", "", "Passphrase needed to unlock the sealer's JSON key")
	mainChainEndpoint := flag.String("mainchainendpoint", "", "URL or path of the main chain endpoint")
	sideChainEndpoint := flag.String("sidechainendpoint", "", "URL or path of the side chain endpoint")
	mainChainWallet := flag.String("mainchainwallet", "", "Ethereum address of the multisig wallet on the main chain")
	sideChainWallet := flag.String("sidechainwallet", "", "Ethereum address of the multisig wallet on the side chain")

	flag.Parse()

	// Connect to both chains
	mainChainClient, _ := ethclient.Dial(*mainChainEndpoint)
	sideChainClient, _ := ethclient.Dial(*sideChainEndpoint)

	sideChainWalletAddress := common.HexToAddress(*sideChainWallet)
	mainChainWalletAddress := common.HexToAddress(*mainChainWallet)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Open the account key file
	keyJSON, err := ioutil.ReadFile(*keyJSONPath)
	if err != nil {
		log.Fatalf("Key json read error: %v", err)
	}

	// Create a transactor
	auth, err := bind.NewTransactor(strings.NewReader(string(keyJSON[:])), *password)
	if err != nil {
		log.Fatalf("Failed to create authorized transactor: %v", err)
	}

	// Attach the wallet
	sc, err := sidechain.NewSideChain(sideChainWalletAddress, sideChainClient)

	// Get the latest block
	latestBlock, err := mainChainClient.BlockByNumber(ctx, nil)
	if err != nil {
		log.Fatal("Can't get latest block:", err)
	}

	log.Printf("Latest block: %v", latestBlock.Number())

	start := big.NewInt(0)
	end := latestBlock.Number()
	one := big.NewInt(1)

	// Loop over the blocks
	for i := start; i.Cmp(end) <= 0; i.Add(i, one) {

		// Get the block details
		block, err := mainChainClient.BlockByNumber(ctx, i)
		if err != nil {
			log.Println("Can't get block:", err)
			continue
		}

		txs := block.Transactions()

		// Loop over the transactions
		for j, tx := range txs {
			to := tx.To()

			// If money is sent to the wallet address, mirror the transaction on the other chain
			if to != nil && *to == mainChainWalletAddress {
				// Check that the transaction was successful
				receipt, err := mainChainClient.TransactionReceipt(ctx, tx.Hash())
				if err != nil {
					log.Printf("Can't get transaction receipt: %v", err)
					continue
				}

				log.Printf("Receipt: %v", receipt)

				if receipt.Status == types.ReceiptStatusFailed {
					log.Printf("Transaction failed %v", tx)
					continue
				}

				// Decode event logs
				abi, _ := abi.JSON(strings.NewReader(mainchain.MainChainABI))
				logs := receipt.Logs

				var depositEvent struct {
					Sender   common.Address
					Receiver common.Address
					Value    *big.Int
				}

				for _, l := range logs {
					err := abi.Unpack(&depositEvent, "Deposit", l.Data)
					if err != nil {
						log.Printf("Event log unpack error: %v", err)
						continue
					}

					// Indexed attributes go in l.Topics instead of l.Data
					depositEvent.Sender = common.BytesToAddress(l.Topics[1].Bytes())
					depositEvent.Receiver = common.BytesToAddress(l.Topics[2].Bytes())

					log.Printf("sender: %v", depositEvent.Sender.Hex())
					log.Printf("receiver: %v", depositEvent.Receiver.Hex())
					log.Printf("value: %v", depositEvent.Value)
				}

				log.Println("Mirroring transaction")

				// Submit the transaction
				wtx, err := sc.SubmitTransactionSC(auth, tx.Hash(), depositEvent.Receiver, tx.Value(), []byte(`foo`))
				if err != nil {
					log.Printf("Deposit error: %v", err)
					continue
				}

				log.Printf("Transaction mirrored: %v", wtx)
			}

			log.Printf("Transaction proceeded in block %v: %v\n", i, j)
		}

		//log.Println("Block proceeded:", i)
	}
}
