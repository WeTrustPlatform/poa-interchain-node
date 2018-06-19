/*
Copyright (C) 2018 WeTrustPlatform

This file is part of poa-interchain-node.

poa-interchain-node is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

poa-interchain-node is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with poa-interchain-node.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"bufio"
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/WeTrustPlatform/poa-interchain-node"
	"github.com/WeTrustPlatform/poa-interchain-node/bind/mainchain"
	"github.com/WeTrustPlatform/poa-interchain-node/bind/sidechain"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/jessevdk/go-flags"
)

var opts struct {
	MainChain         bool   `short:"m" long:"mainchain" required:"false" description:"Watch the main chain only"`
	SideChain         bool   `short:"s" long:"sidechain" required:"false" description:"Watch the side chain only"`
	KeyJSONPath       string `short:"k" long:"keyjson" required:"true" description:"Path to the JSON private key file of the sealer"`
	Password          string `short:"p" long:"password" required:"false" description:"Passphrase needed to unlock the sealer's JSON key"`
	MainChainEndpoint string `long:"mainchainendpoint" required:"true" description:"URL or path of the main chain endpoint"`
	SideChainEndpoint string `long:"sidechainendpoint" required:"true" description:"URL or path of the side chain endpoint"`
	MainChainWallet   string `long:"mainchainwallet" required:"true" description:"Ethereum address of the multisig wallet on the main chain"`
	SideChainWallet   string `long:"sidechainwallet" required:"true" description:"Ethereum address of the multisig wallet on the side chain"`
}

func handleError(err error) {
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(0)
	}
}

// For each Deposit on the main chain, call SubmitTransactionSC on the side chain
func processMCDeposits(ctx context.Context, auth *bind.TransactOpts,
	mc *mainchain.MainChain, sc *sidechain.SideChain, wg *sync.WaitGroup) {
	i, _ := mc.FilterDeposit(&bind.FilterOpts{
		Start:   0,
		End:     nil,
		Context: ctx,
	}, []common.Address{}, []common.Address{})
	for i.Next() {
		tx, err := sc.SubmitTransactionSC(auth, i.Event.Raw.TxHash, i.Event.To, i.Event.Value, []byte{})
		log.Println("[mc2sc]", i.Event.Raw.BlockNumber, tx, err)
	}
	wg.Done()
}

// For each Deposit on the side chain, call SubmitSignatureMC on the side chain
func processSCDeposits(ctx context.Context, auth *bind.TransactOpts,
	mc *mainchain.MainChain, sc *sidechain.SideChain,
	addr common.Address, key *keystore.Key, wg *sync.WaitGroup) {
	i, _ := sc.FilterDeposit(&bind.FilterOpts{
		Start:   0,
		End:     nil,
		Context: ctx,
	}, []common.Address{}, []common.Address{})
	for i.Next() {
		tx, err := icn.SubmitSignatureMC(ctx, addr, auth, sc, i.Event, key.PrivateKey)
		log.Println("[sc2mc]", i.Event.Raw.BlockNumber, tx, err)
	}
	wg.Done()
}

// For each SignatureAdded on the side chain, call SubmitTransaction on the main chain
func processSCSignatureAdded(ctx context.Context, auth *bind.TransactOpts,
	mc *mainchain.MainChain, sc *sidechain.SideChain,
	wg *sync.WaitGroup) {
	i, _ := sc.FilterSignatureAdded(&bind.FilterOpts{Start: 0, End: nil, Context: ctx})
	for i.Next() {
		enough, _ := icn.HasEnoughSignaturesMC(ctx, sc, auth.From, i.Event.TxHash)
		if enough {
			resp, _ := sc.GetTransactionMC(&bind.CallOpts{Pending: false, From: auth.From, Context: ctx}, i.Event.TxHash)
			tx, err := mc.SubmitTransaction(auth, i.Event.TxHash, resp.Destination, resp.Value, resp.Data, resp.V, resp.R, resp.S)
			log.Println("[sc2mc]", i.Event.Raw.BlockNumber, tx, err)
		}
	}
	wg.Done()
}

func main() {
	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(0)
	}

	// Prompt passphrase if not passed as a flag
	if opts.Password == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter your passphrase: ")
		opts.Password, _ = reader.ReadString('\n')
		opts.Password = strings.TrimSuffix(opts.Password, "\n")
	}

	// Default behavior is to watch both chains
	if !opts.MainChain && !opts.SideChain {
		opts.SideChain = true
		opts.MainChain = true
	}

	// Connect to both chains
	mainChainClient, err := ethclient.Dial(opts.MainChainEndpoint)
	handleError(err)
	sideChainClient, err := ethclient.Dial(opts.SideChainEndpoint)
	handleError(err)

	sideChainWalletAddress := common.HexToAddress(opts.SideChainWallet)
	mainChainWalletAddress := common.HexToAddress(opts.MainChainWallet)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Open the account key file
	keyJSON, err := ioutil.ReadFile(opts.KeyJSONPath)
	handleError(err)

	// Create a transactor
	key, err := keystore.DecryptKey(keyJSON, opts.Password)
	handleError(err)
	auth := bind.NewKeyedTransactor(key.PrivateKey)

	// Attach the wallet
	sc, err := sidechain.NewSideChain(sideChainWalletAddress, sideChainClient)
	handleError(err)
	mc, err := mainchain.NewMainChain(mainChainWalletAddress, mainChainClient)
	handleError(err)

	var wg sync.WaitGroup

	// Watch the main chain
	if opts.MainChain {
		wg.Add(1)
		go processMCDeposits(ctx, auth, mc, sc, &wg)
	}

	// Watch the side chain
	if opts.SideChain {
		wg.Add(2)
		go processSCDeposits(ctx, auth, mc, sc, sideChainWalletAddress, key, &wg)
		go processSCSignatureAdded(ctx, auth, mc, sc, &wg)
	}

	wg.Wait()
}
