package main

import "C"

import (
	// std
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	// helpers

	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"

	// tendermint
	abci "github.com/cometbft/cometbft/abci/types"
	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"

	// cosmos sdk
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"

	// wasmd
	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"

	// cosmwasm-testing
	"github.com/osmosis-labs/test-tube/osmosis-test-tube/result"
	"github.com/osmosis-labs/test-tube/osmosis-test-tube/testenv"
	// osmosis
	// lockuptypes "github.com/osmosis-labs/osmosis/v16/x/lockup/types"
)

var (
	envCounter  uint64 = 0
	envRegister        = sync.Map{}
	mu          sync.Mutex
	chainID     = "Oraichain"
)

//export InitTestEnv
func InitTestEnv() uint64 {
	// Temp fix for concurrency issue
	mu.Lock()
	defer mu.Unlock()

	envCounter += 1
	id := envCounter

	nodeHome, err := os.MkdirTemp("", ".osmosis-test-tube-temp-")
	if err != nil {
		panic(err)
	}

	env := new(testenv.TestEnv)
	env.App = testenv.SetupOsmosisApp(nodeHome)
	env.NodeHome = nodeHome
	env.ParamTypesRegistry = *testenv.NewParamTypeRegistry()

	env.SetupParamTypes()

	// Allow testing unoptimized contract
	wasmtypes.MaxWasmSize = 1024 * 1024 * 1024 * 1024 * 1024

	env.Ctx = env.App.BaseApp.NewContextLegacy(true, tmproto.Header{Height: 0, ChainID: chainID, Time: time.Now().UTC()})

	blockTime := env.Ctx.BlockTime().Add(time.Duration(5) * time.Second)
	env.BeginNewBlock(false, blockTime, chainID)

	reqEndBlock := &abci.RequestFinalizeBlock{Height: env.Ctx.BlockHeight()}
	env.App.FinalizeBlock(reqEndBlock)
	env.App.Commit()

	envRegister.Store(id, *env)

	return id
}

//export CleanUp
func CleanUp(envId uint64) {
	env := loadEnv(envId)
	err := os.RemoveAll(env.NodeHome)
	if err != nil {
		panic(err)
	}
	envRegister.Delete(envId)
}

//export InitAccount
func InitAccount(envId uint64, coinsJson string) *C.char {
	env := loadEnv(envId)
	var coins sdk.Coins

	if err := json.Unmarshal([]byte(coinsJson), &coins); err != nil {
		panic(err)
	}

	priv := env.SetupAccount(coins)

	base64Priv := base64.StdEncoding.EncodeToString(priv.Bytes())

	envRegister.Store(envId, env)

	return C.CString(base64Priv)
}

//export InitAccountWithSecret
func InitAccountWithSecret(envId uint64, coinsJson string, secret string) *C.char {
	env := loadEnv(envId)
	var coins sdk.Coins

	if err := json.Unmarshal([]byte(coinsJson), &coins); err != nil {
		panic(err)
	}

	priv := secp256k1.GenPrivKeyFromSecret([]byte(secret))
	env.SetupAccountWithPrivKey(coins, priv)

	base64Priv := base64.StdEncoding.EncodeToString(priv.Bytes())

	envRegister.Store(envId, env)

	return C.CString(base64Priv)
}

//export SetupValidator
func SetupValidator(envId uint64, coinsJson string) *C.char {
	env := loadEnv(envId)
	var coins sdk.Coins

	if err := json.Unmarshal([]byte(coinsJson), &coins); err != nil {
		panic(err)
	}
	validator := env.SetupValidator(coins)

	envRegister.Store(envId, env)

	return C.CString(validator.OperatorAddress)

}

//export SetupValidatorWithSecret
func SetupValidatorWithSecret(envId uint64, coinsJson string, secret string) *C.char {
	env := loadEnv(envId)
	var coins sdk.Coins

	if err := json.Unmarshal([]byte(coinsJson), &coins); err != nil {
		panic(err)
	}

	validator := env.SetupValidatorWithPrivKey(coins, secp256k1.GenPrivKeyFromSecret([]byte(secret)))

	envRegister.Store(envId, env)

	return C.CString(validator.OperatorAddress)
}

//export IncreaseTime
func IncreaseTime(envId uint64, seconds uint64) {
	env := loadEnv(envId)
	env.BeginNewBlock(false, env.Ctx.BlockTime().Add(time.Duration(seconds)*time.Second), env.Ctx.ChainID())
	envRegister.Store(envId, env)
	EndBlock(envId)
}

//export SetBlockTime
func SetBlockTime(envId uint64, nanoseconds uint64) {
	env := loadEnv(envId)
	env.BeginNewBlock(false, time.Unix(0, int64(nanoseconds)), env.Ctx.ChainID())
	envRegister.Store(envId, env)
	EndBlock(envId)
}

//export SetChainID
func SetChainID(envId uint64, chainID string) {
	env := loadEnv(envId)
	env.BeginNewBlock(false, env.Ctx.BlockTime(), chainID)
	envRegister.Store(envId, env)
	EndBlock(envId)
}

//export BeginBlock
func BeginBlock(envId uint64) {
	env := loadEnv(envId)
	env.BeginNewBlock(false, env.Ctx.BlockTime().Add(time.Duration(5)*time.Second), env.Ctx.ChainID())
	envRegister.Store(envId, env)
}

//export EndBlock
func EndBlock(envId uint64) {
	env := loadEnv(envId)
	reqEndBlock := &abci.RequestFinalizeBlock{Height: env.Ctx.BlockHeight()}
	env.App.FinalizeBlock(reqEndBlock)
	env.App.Commit()
	envRegister.Store(envId, env)
}

//export WasmSudo
func WasmSudo(envId uint64, bech32Address, msgJson string) *C.char {
	env := loadEnv(envId)
	// Temp fix for concurrency issue
	mu.Lock()
	defer mu.Unlock()

	accAddr, err := sdk.AccAddressFromBech32(bech32Address)
	if err != nil {
		panic(err)
	}

	msgBytes := []byte(msgJson)

	res, err := env.App.WasmKeeper.Sudo(env.Ctx, accAddr, msgBytes)
	if err != nil {
		return encodeErrToResultBytes(result.ExecuteError, err)
	}

	envRegister.Store(envId, env)

	return encodeBytesResultBytes(res)
}

//export Execute
func Execute(envId uint64, base64ReqDeliverTx string) *C.char {
	env := loadEnv(envId)

	txBytes, err := base64.StdEncoding.DecodeString(base64ReqDeliverTx)
	if err != nil {
		return encodeErrToResultBytes(result.ExecuteError, err)
	}

	res, err := env.App.FinalizeBlock(&abci.RequestFinalizeBlock{
		Txs:    [][]byte{txBytes},
		Height: env.Ctx.BlockHeight(),
		Time:   env.Ctx.BlockTime(),
	})

	if err != nil {
		return encodeErrToResultBytes(result.ExecuteError, err)
	}

	envRegister.Store(envId, env)

	bz, err := proto.Marshal(res)
	if err != nil {
		return encodeErrToResultBytes(result.ExecuteError, err)
	}

	return encodeBytesResultBytes(bz)
}

//export Query
func Query(envId uint64, path, base64QueryMsgBytes string) *C.char {
	env := loadEnv(envId)
	queryMsgBytes, err := base64.StdEncoding.DecodeString(base64QueryMsgBytes)
	if err != nil {
		panic(err)
	}

	req := &abci.RequestQuery{}
	req.Data = queryMsgBytes

	route := env.App.GRPCQueryRouter().Route(path)
	if route == nil {
		err := errors.New("No route found for `" + path + "`")
		return encodeErrToResultBytes(result.QueryError, err)
	}
	res, err := route(env.Ctx, req)

	if err != nil {
		return encodeErrToResultBytes(result.QueryError, err)
	}

	return encodeBytesResultBytes(res.Value)
}

//export GetBlockTime
func GetBlockTime(envId uint64) int64 {
	env := loadEnv(envId)
	return env.Ctx.BlockTime().UnixNano()
}

//export GetBlockHeight
func GetBlockHeight(envId uint64) int64 {
	env := loadEnv(envId)
	return env.Ctx.BlockHeight()
}

//export AccountSequence
func AccountSequence(envId uint64, bech32Address string) uint64 {
	env := loadEnv(envId)

	addr, err := sdk.AccAddressFromBech32(bech32Address)

	if err != nil {
		panic(err)
	}

	seq, err := env.App.AccountKeeper.GetSequence(env.Ctx, addr)

	if err != nil {
		panic(err)
	}

	return seq
}

//export AccountNumber
func AccountNumber(envId uint64, bech32Address string) uint64 {
	env := loadEnv(envId)

	addr, err := sdk.AccAddressFromBech32(bech32Address)

	if err != nil {
		panic(err)
	}

	acc := env.App.AccountKeeper.GetAccount(env.Ctx, addr)
	return acc.GetAccountNumber()
}

//export Simulate
func Simulate(envId uint64, base64TxBytes string) *C.char { // => base64GasInfo
	env := loadEnv(envId)
	// Temp fix for concurrency issue
	mu.Lock()
	defer mu.Unlock()

	txBytes, err := base64.StdEncoding.DecodeString(base64TxBytes)
	if err != nil {
		panic(err)
	}

	gasInfo, _, err := env.App.Simulate(txBytes)

	if err != nil {
		return encodeErrToResultBytes(result.ExecuteError, err)
	}

	bz, err := proto.Marshal(&gasInfo)
	if err != nil {
		panic(err)
	}

	return encodeBytesResultBytes(bz)
}

//export SetParamSet
func SetParamSet(envId uint64, subspaceName, base64ParamSetBytes string) *C.char {
	env := loadEnv(envId)

	// Temp fix for concurrency issue
	mu.Lock()
	defer mu.Unlock()

	paramSetBytes, err := base64.StdEncoding.DecodeString(base64ParamSetBytes)
	if err != nil {
		panic(err)
	}

	subspace, ok := env.App.ParamsKeeper.GetSubspace(subspaceName)
	if !ok {
		err := errors.New("No subspace found for `" + subspaceName + "`")
		return encodeErrToResultBytes(result.ExecuteError, err)
	}

	pReg := env.ParamTypesRegistry

	any := codectypes.Any{}
	err = proto.Unmarshal(paramSetBytes, &any)

	if err != nil {
		return encodeErrToResultBytes(result.ExecuteError, err)
	}

	pset, err := pReg.UnpackAny(&any)

	if err != nil {
		return encodeErrToResultBytes(result.ExecuteError, err)
	}

	subspace.SetParamSet(env.Ctx, pset)

	// return empty bytes if no error
	return encodeBytesResultBytes([]byte{})
}

//export GetParamSet
func GetParamSet(envId uint64, subspaceName, typeUrl string) *C.char {
	env := loadEnv(envId)

	subspace, ok := env.App.ParamsKeeper.GetSubspace(subspaceName)
	if !ok {
		err := errors.New("No subspace found for `" + subspaceName + "`")
		return encodeErrToResultBytes(result.ExecuteError, err)
	}

	pReg := env.ParamTypesRegistry
	pset, ok := pReg.GetEmptyParamsSet(typeUrl)

	if !ok {
		err := errors.New("No param set found for `" + typeUrl + "`")
		return encodeErrToResultBytes(result.ExecuteError, err)
	}
	subspace.GetParamSet(env.Ctx, pset)

	bz, err := proto.Marshal(pset)

	if err != nil {
		panic(err)
	}

	return encodeBytesResultBytes(bz)
}

//export GetValidatorAddress
func GetValidatorAddress(envId uint64, n int32) *C.char {
	env := loadEnv(envId)
	return C.CString(env.GetValidatorAddresses()[n])
}

//export GetValidatorAddresses
func GetValidatorAddresses(envId uint64) *C.char {
	env := loadEnv(envId)
	addresses := env.GetValidatorAddresses()
	return C.CString(strings.Join(addresses, ","))
}

//export GetValidatorPrivateKey
func GetValidatorPrivateKey(envId uint64, n int32) *C.char {
	env := loadEnv(envId)

	priv := env.ValPrivs[n]
	base64Priv := base64.StdEncoding.EncodeToString(priv.Bytes())
	return C.CString(base64Priv)
}

//export GetValidatorPrivateKeys
func GetValidatorPrivateKeys(envId uint64) *C.char {
	env := loadEnv(envId)
	var valPrivs []string
	for _, priv := range env.ValPrivs {
		base64Priv := base64.StdEncoding.EncodeToString(priv.Bytes())
		valPrivs = append(valPrivs, base64Priv)
	}

	return C.CString(strings.Join(valPrivs, ","))
}

// ========= utils =========

func loadEnv(envId uint64) testenv.TestEnv {
	item, ok := envRegister.Load(envId)
	env := testenv.TestEnv(item.(testenv.TestEnv))
	if !ok {
		panic(fmt.Sprintf("env not found: %d", envId))
	}
	return env
}

func encodeErrToResultBytes(code byte, err error) *C.char {
	return C.CString(result.EncodeResultFromError(code, err))
}

func encodeBytesResultBytes(bytes []byte) *C.char {
	return C.CString(result.EncodeResultFromOk(bytes))
}

// must define main for ffi build
func main() {}
