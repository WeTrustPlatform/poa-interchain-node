package icn

import (
	"context"
	"math/big"
	"reflect"
	"strings"
	"testing"

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

	key1, _ := crypto.GenerateKey()
	sealer1 := bind.NewKeyedTransactor(key1)
	key2, _ := crypto.GenerateKey()
	sealer2 := bind.NewKeyedTransactor(key2)

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
