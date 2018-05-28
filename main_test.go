package icn

import (
	"context"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/WeTrustPlatform/interchain-node/bind/mainchain"
	"github.com/WeTrustPlatform/interchain-node/bind/sidechain"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestMsgHash(t *testing.T) {
	type args struct {
		contractAddress common.Address
		txHash          common.Hash
		toAddress       common.Address
		value           *big.Int
		data            []byte
		version         uint8
	}
	tests := []struct {
		name string
		args args
		want common.Hash
	}{
		{
			name: "Computes solidity compatible hash",
			args: args{
				common.HexToAddress("75076e4fbba61f65efb41d64e45cff340b1e518a"),
				common.HexToHash("03c85f1da84d9c6313e0c34bcb5ace945a9b12105988895252b88ce5b769f82b"),
				common.HexToAddress("f17f52151ebef6c7334fad080c5704d77216b732"),
				big.NewInt(100000000),
				[]byte{},
				1,
			},
			want: common.HexToHash("6b0673bcb3726c0f7956ef57a9542ed225bfe74f1d2a75414d198d55e8956da5"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MsgHash(tt.args.contractAddress, tt.args.txHash, tt.args.toAddress, tt.args.value, tt.args.data, tt.args.version); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MsgHash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseSignature(t *testing.T) {
	type args struct {
		sig []byte
	}
	tests := []struct {
		name  string
		args  args
		wantV uint8
		wantR common.Hash
		wantS common.Hash
	}{
		{
			name: "Parses signature correctly",
			args: args{
				sig: common.Hex2Bytes("a27a17b20a8dcc6fedb6196b84624ce3f3961a2423642fe13003a816c383f93205adf64e0805449d18b866991ce19e5439567cd3613ae1775e90fb4a8b0cbc6800"),
			},
			wantV: 27,
			wantR: common.HexToHash("a27a17b20a8dcc6fedb6196b84624ce3f3961a2423642fe13003a816c383f932"),
			wantS: common.HexToHash("05adf64e0805449d18b866991ce19e5439567cd3613ae1775e90fb4a8b0cbc68"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotV, gotR, gotS := ParseSignature(tt.args.sig)
			if gotV != tt.wantV {
				t.Errorf("ParseSignature() gotV = %v, want %v", gotV, tt.wantV)
			}
			if !reflect.DeepEqual(gotR, tt.wantR) {
				t.Errorf("ParseSignature() gotR = %v, want %v", gotR, tt.wantR)
			}
			if !reflect.DeepEqual(gotS, tt.wantS) {
				t.Errorf("ParseSignature() gotS = %v, want %v", gotS, tt.wantS)
			}
		})
	}
}

func TestFindDeposits(t *testing.T) {
	ctx := context.Background()

	sealer1Key, _ := crypto.GenerateKey()
	sealer1 := bind.NewKeyedTransactor(sealer1Key)
	sealer2Key, _ := crypto.GenerateKey()
	sealer2 := bind.NewKeyedTransactor(sealer2Key)

	alloc := core.GenesisAlloc{
		sealer1.From: core.GenesisAccount{Balance: big.NewInt(10000000000)},
	}

	sim := backends.NewSimulatedBackend(alloc)

	address, _, sc, _ := sidechain.DeploySideChain(sealer1, sim, []common.Address{sealer1.From, sealer2.From}, 2)

	abi, _ := abi.JSON(strings.NewReader(sidechain.SideChainABI))

	sealer1.Value = big.NewInt(1000000000)
	sc.Deposit(sealer1, sealer2.From)
	sc.Deposit(sealer1, sealer2.From)
	sc.Deposit(sealer1, sealer2.From)
	sim.Commit()
	sc.Deposit(sealer1, sealer2.From)
	sc.Deposit(sealer1, sealer2.From)
	sim.Commit()

	t.Run("Returns the right number of logs for all blocks", func(t *testing.T) {
		deposits := make(chan DepositInfo)
		done := make(chan bool)

		go FindDeposits(
			ctx,
			sim,
			abi,
			deposits,
			done,
			big.NewInt(0),
			nil,
			address)

		found := 0
		for n := 1; n > 0; {
			select {
			case <-deposits:
				found++
			case <-done:
				n--
			}
		}

		have := found
		want := 5
		if have != want {
			t.Errorf("found = %v, want %v", have, want)
		}
	})

	t.Run("Returns the right number of logs for a given block", func(t *testing.T) {
		deposits := make(chan DepositInfo)
		done := make(chan bool)

		go FindDeposits(
			ctx,
			sim,
			abi,
			deposits,
			done,
			big.NewInt(2),
			big.NewInt(3),
			address)

		found := 0
		for n := 1; n > 0; {
			select {
			case <-deposits:
				found++
			case <-done:
				n--
			}
		}

		have := found
		want := 2
		if have != want {
			t.Errorf("found = %v, want %v", have, want)
		}
	})
}

func TestMainChainToSideChain(t *testing.T) {
	ctx := context.Background()

	key0, _ := crypto.GenerateKey()
	miner := bind.NewKeyedTransactor(key0)
	sealer1Key, _ := crypto.GenerateKey()
	sealer1 := bind.NewKeyedTransactor(sealer1Key)
	sealer1Auth := bind.NewKeyedTransactor(sealer1Key)
	sealer2Key, _ := crypto.GenerateKey()
	sealer2 := bind.NewKeyedTransactor(sealer2Key)
	sealer2Auth := bind.NewKeyedTransactor(sealer2Key)
	tester1Key, _ := crypto.GenerateKey()
	tester1 := bind.NewKeyedTransactor(tester1Key)
	tester2Key, _ := crypto.GenerateKey()
	tester2 := bind.NewKeyedTransactor(tester2Key)

	scAddr := crypto.CreateAddress(sealer1.From, 0)
	mcAddr := crypto.CreateAddress(sealer2.From, 0)

	scClient := backends.NewSimulatedBackend(core.GenesisAlloc{
		scAddr:       core.GenesisAccount{Balance: big.NewInt(50000000000)},
		sealer1.From: core.GenesisAccount{Balance: big.NewInt(10000000000)},
		sealer2.From: core.GenesisAccount{Balance: big.NewInt(10000000000)},
		tester1.From: core.GenesisAccount{Balance: big.NewInt(10000000000)},
	})
	mcClient := backends.NewSimulatedBackend(core.GenesisAlloc{
		mcAddr:       core.GenesisAccount{Balance: big.NewInt(50000000000)},
		miner.From:   core.GenesisAccount{Balance: big.NewInt(10000000000)},
		sealer1.From: core.GenesisAccount{Balance: big.NewInt(10000000000)},
		sealer2.From: core.GenesisAccount{Balance: big.NewInt(10000000000)},
		tester2.From: core.GenesisAccount{Balance: big.NewInt(10000000000)},
	})

	_, _, sc, _ := sidechain.DeploySideChain(sealer1, scClient, []common.Address{sealer1.From, sealer2.From}, 2)
	_, _, mc, _ := mainchain.DeployMainChain(sealer2, mcClient, []common.Address{sealer1.From, sealer2.From}, 2)

	tester2.Value = big.NewInt(200000000)
	tx, _ := mc.Deposit(tester2, tester1.From)
	mcClient.Commit()

	mci, _ := mc.FilterDeposit(&bind.FilterOpts{Start: 0, End: nil, Context: ctx}, []common.Address{}, []common.Address{})
	for mci.Next() {
		sc.SubmitTransactionSC(sealer1Auth, mci.Event.Raw.TxHash, mci.Event.To, mci.Event.Value, []byte{})
		scClient.Commit()
		sc.SubmitTransactionSC(sealer2Auth, mci.Event.Raw.TxHash, mci.Event.To, mci.Event.Value, []byte{})
		scClient.Commit()
	}

	t.Run("Transaction is confirmed after the number of required votes on the SC is reached", func(t *testing.T) {
		confirmed, _ := sc.IsConfirmed(&bind.CallOpts{
			Context: ctx,
			Pending: false,
			From:    sealer1.From,
		}, tx.Hash())
		if !confirmed {
			t.Errorf("confirmed = %v, want %v", confirmed, true)
		}
	})

	t.Run("Sender has been debited on the mainchain", func(t *testing.T) {
		have, _ := mcClient.BalanceAt(ctx, tester2.From, nil)
		want := big.NewInt(10000000000 - 200000000 - int64(tx.Gas()))
		if !reflect.DeepEqual(have, want) {
			t.Errorf("have = %v, want %v", have, want)
		}
	})

	t.Run("Recipient has been credited on the sidechain", func(t *testing.T) {
		have, _ := scClient.BalanceAt(ctx, tester1.From, nil)
		want := big.NewInt(10000000000 + 200000000)
		if !reflect.DeepEqual(have, want) {
			t.Errorf("have = %v, want %v", have, want)
		}
	})

	t.Run("Main chain smart contract has been credited", func(t *testing.T) {
		have, _ := mcClient.BalanceAt(ctx, mcAddr, nil)
		want := big.NewInt(50000000000 + 200000000)
		if !reflect.DeepEqual(have, want) {
			t.Errorf("have = %v, want %v", have, want)
		}
	})

	t.Run("Side chain smart contract has been debited", func(t *testing.T) {
		have, _ := scClient.BalanceAt(ctx, scAddr, nil)
		want := big.NewInt(50000000000 - 200000000)
		if !reflect.DeepEqual(have, want) {
			t.Errorf("have = %v, want %v", have, want)
		}
	})
}

func TestSideChainToMainChain(t *testing.T) {
	ctx := context.Background()

	minerKey, _ := crypto.GenerateKey()
	miner := bind.NewKeyedTransactor(minerKey)
	sealer1Key, _ := crypto.GenerateKey()
	sealer1 := bind.NewKeyedTransactor(sealer1Key)
	sealer1Auth := bind.NewKeyedTransactor(sealer1Key)
	sealer2Key, _ := crypto.GenerateKey()
	sealer2 := bind.NewKeyedTransactor(sealer2Key)
	sealer2Auth := bind.NewKeyedTransactor(sealer2Key)
	tester1Key, _ := crypto.GenerateKey()
	tester1 := bind.NewKeyedTransactor(tester1Key)
	tester2Key, _ := crypto.GenerateKey()
	tester2 := bind.NewKeyedTransactor(tester2Key)

	scAddr := crypto.CreateAddress(sealer1.From, 0)
	mcAddr := crypto.CreateAddress(sealer2.From, 0)

	scClient := backends.NewSimulatedBackend(core.GenesisAlloc{
		scAddr:       core.GenesisAccount{Balance: big.NewInt(50000000000)},
		sealer1.From: core.GenesisAccount{Balance: big.NewInt(10000000000)},
		sealer2.From: core.GenesisAccount{Balance: big.NewInt(10000000000)},
		tester1.From: core.GenesisAccount{Balance: big.NewInt(10000000000)},
	})
	mcClient := backends.NewSimulatedBackend(core.GenesisAlloc{
		mcAddr:       core.GenesisAccount{Balance: big.NewInt(50000000000)},
		miner.From:   core.GenesisAccount{Balance: big.NewInt(10000000000)},
		sealer1.From: core.GenesisAccount{Balance: big.NewInt(10000000000)},
		sealer2.From: core.GenesisAccount{Balance: big.NewInt(10000000000)},
		tester2.From: core.GenesisAccount{Balance: big.NewInt(10000000000)},
	})

	_, _, sc, _ := sidechain.DeploySideChain(sealer1, scClient, []common.Address{sealer1.From, sealer2.From}, 2)
	mainchain.DeployMainChain(sealer2, mcClient, []common.Address{sealer1.From, sealer2.From}, 2)

	tester1.Value = big.NewInt(200000000)
	tx, _ := sc.Deposit(tester1, tester2.From)
	scClient.Commit()

	sci, _ := sc.FilterDeposit(&bind.FilterOpts{Start: 0, End: nil, Context: ctx}, []common.Address{}, []common.Address{})
	for sci.Next() {
		SubmitSignatureMC(ctx, scAddr, sealer1Auth, sc, sci.Event, sealer1Key)
		scClient.Commit()
		SubmitSignatureMC(ctx, scAddr, sealer2Auth, sc, sci.Event, sealer2Key)
		scClient.Commit()
	}

	t.Run("SignatureAdded events are emitted on the sidechain", func(t *testing.T) {
		var count int
		iter, _ := sc.FilterSignatureAdded(&bind.FilterOpts{Start: 0, End: nil, Context: ctx})
		for iter.Next() {
			if iter.Event.TxHash == tx.Hash() {
				count++
			}
		}

		have := count
		want := 2
		if have != want {
			t.Errorf("have = %v, want %v", have, want)
		}
	})
}
