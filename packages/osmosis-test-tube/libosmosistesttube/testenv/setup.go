package testenv

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	sdkmath "cosmossdk.io/math"
	// helpers
	errorsmod "cosmossdk.io/errors"
	"github.com/CosmWasm/wasmd/app/params"
	"golang.org/x/exp/rand"

	// tendermint
	"cosmossdk.io/log"
	abci "github.com/cometbft/cometbft/abci/types"
	dbm "github.com/cosmos/cosmos-db"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"

	// cosmos-sdk
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/server"
	simtestutil "github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"
	banktestutil "github.com/cosmos/cosmos-sdk/x/bank/testutil"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	slashingtypes "github.com/cosmos/cosmos-sdk/x/slashing/types"

	stakingkeeper "github.com/cosmos/cosmos-sdk/x/staking/keeper"
	stakingtypes "github.com/cosmos/cosmos-sdk/x/staking/types"

	// wasmd
	"github.com/CosmWasm/wasmd/x/wasm"
	wasmtypes "github.com/CosmWasm/wasmd/x/wasm/types"

	// osmosis
	"github.com/CosmWasm/wasmd/app"
)

type TestEnv struct {
	App                *app.WasmApp
	Ctx                sdk.Context
	ValPrivs           []cryptotypes.PrivKey
	ParamTypesRegistry ParamTypeRegistry
	NodeHome           string
}

// DebugAppOptions is a stub implementing AppOptions
type DebugAppOptions struct{}

// Get implements AppOptions
func (ao DebugAppOptions) Get(o string) interface{} {
	if o == server.FlagTrace {
		return true
	}
	return nil
}

var emptyWasmOpts []wasm.Option = nil

const (
	Bech32Prefix = "orai"

	// Bech32PrefixAccAddr defines the Bech32 prefix of an account's address
	Bech32PrefixAccAddr = Bech32Prefix
	// Bech32PrefixAccPub defines the Bech32 prefix of an account's public key
	Bech32PrefixAccPub = Bech32Prefix + sdk.PrefixPublic
	// Bech32PrefixValAddr defines the Bech32 prefix of a validator's operator address
	Bech32PrefixValAddr = Bech32Prefix + sdk.PrefixValidator + sdk.PrefixOperator
	// Bech32PrefixValPub defines the Bech32 prefix of a validator's operator public key
	Bech32PrefixValPub = Bech32Prefix + sdk.PrefixValidator + sdk.PrefixOperator + sdk.PrefixPublic
	// Bech32PrefixConsAddr defines the Bech32 prefix of a consensus node address
	Bech32PrefixConsAddr = Bech32Prefix + sdk.PrefixValidator + sdk.PrefixConsensus
	// Bech32PrefixConsPub defines the Bech32 prefix of a consensus node public key
	Bech32PrefixConsPub = Bech32Prefix + sdk.PrefixValidator + sdk.PrefixConsensus + sdk.PrefixPublic
)

func SetupOsmosisApp(nodeHome string) *app.WasmApp {
	db := dbm.NewMemDB()

	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount(app.Bech32PrefixAccAddr, app.Bech32PrefixAccPub)
	cfg.SetBech32PrefixForValidator(app.Bech32PrefixValAddr, app.Bech32PrefixValPub)
	cfg.SetBech32PrefixForConsensusNode(app.Bech32PrefixConsAddr, app.Bech32PrefixConsPub)

	appInstance := app.NewWasmApp(
		log.NewNopLogger(),
		db,
		nil,
		true,
		simtestutil.NewAppOptionsWithFlagHome(nodeHome),
		emptyWasmOpts,
	)

	encCfg := params.EncodingConfig{
		InterfaceRegistry: appInstance.InterfaceRegistry(),
		Codec:             appInstance.AppCodec(),
		TxConfig:          appInstance.TxConfig(),
		Amino:             appInstance.LegacyAmino(),
	}
	genesisState := app.NewDefaultGenesisState(encCfg.Codec, appInstance.BasicModuleManager)

	// Set up Wasm genesis state
	wasmGen := wasm.GenesisState{
		Params: wasmtypes.Params{
			// Allow store code without gov
			CodeUploadAccess:             wasmtypes.AllowEverybody,
			InstantiateDefaultPermission: wasmtypes.AccessTypeEverybody,
		},
	}
	genesisState[wasm.ModuleName] = encCfg.Codec.MustMarshalJSON(&wasmGen)

	// Set up staking genesis state
	stakingParams := stakingtypes.DefaultParams()
	stakingParams.UnbondingTime = time.Hour * 24 * 7 * 2 // 2 weeks
	stakingGen := stakingtypes.GenesisState{
		Params: stakingParams,
	}
	genesisState[stakingtypes.ModuleName] = encCfg.Codec.MustMarshalJSON(&stakingGen)

	// Set up incentive genesis state
	stateBytes, err := json.MarshalIndent(genesisState, "", " ")

	requireNoErr(err)

	concensusParams := simtestutil.DefaultConsensusParams
	concensusParams.Block = &cmtproto.BlockParams{
		MaxBytes: 22020096,
		MaxGas:   -1,
	}

	// replace sdk.DefaultDenom with "orai", a bit of a hack, needs improvement
	stateBytes = []byte(strings.Replace(string(stateBytes), "\"stake\"", "\"orai\"", -1))

	appInstance.InitChain(
		&abci.RequestInitChain{
			ChainId:         "Oraichain",
			Validators:      []abci.ValidatorUpdate{},
			ConsensusParams: concensusParams,
			AppStateBytes:   stateBytes,
		},
	)

	return appInstance
}

func (env *TestEnv) SetupAccount(coins sdk.Coins) cryptotypes.PrivKey {
	priv := secp256k1.GenPrivKey()
	env.SetupAccountWithPrivKey(coins, priv)
	return priv
}

func (env *TestEnv) SetupAccountWithPrivKey(coins sdk.Coins, priv cryptotypes.PrivKey) sdk.AccAddress {
	accAddr := sdk.AccAddress(priv.PubKey().Address())

	for _, coin := range coins {
		// create denom if not exist
		_, hasDenomMetaData := env.App.BankKeeper.GetDenomMetaData(env.Ctx, coin.Denom)
		if !hasDenomMetaData {
			denomMetaData := banktypes.Metadata{
				DenomUnits: []*banktypes.DenomUnit{{
					Denom:    coin.Denom,
					Exponent: 0,
				}},
				Base: coin.Denom,
			}

			env.App.BankKeeper.SetDenomMetaData(env.Ctx, denomMetaData)
		}

	}

	err := banktestutil.FundAccount(env.Ctx, env.App.BankKeeper, accAddr, coins)
	if err != nil {
		panic(errorsmod.Wrapf(err, "Failed to fund account"))
	}

	return accAddr
}

func (env *TestEnv) SetupValidatorWithPrivKey(coins sdk.Coins, valPriv cryptotypes.PrivKey) stakingtypes.Validator {
	valAddrFancy := env.setupValidator(stakingtypes.Bonded, valPriv)

	env.ValPrivs = append(env.ValPrivs, valPriv)
	err := banktestutil.FundAccount(env.Ctx, env.App.BankKeeper, valAddrFancy.Bytes(), coins)
	if err != nil {
		panic(errorsmod.Wrapf(err, "Failed to fund account"))
	}
	validator, _ := env.App.StakingKeeper.GetValidator(env.Ctx, valAddrFancy)
	return validator
}

func (env *TestEnv) SetupValidator(coins sdk.Coins) stakingtypes.Validator {
	valPriv := secp256k1.GenPrivKey()
	return env.SetupValidatorWithPrivKey(coins, valPriv)
}

func (env *TestEnv) BeginNewBlock(executeNextEpoch bool, blockTime time.Time, chainID string) {
	var valAddr []byte

	validators, _ := env.App.StakingKeeper.GetAllValidators(env.Ctx)
	if len(validators) >= 1 {
		valAddrFancy, err := validators[rand.Intn(len(validators))].GetConsAddr()
		requireNoErr(err)
		valAddr = valAddrFancy
	} else {
		validator := env.SetupValidator(sdk.NewCoins(sdk.NewInt64Coin("orai", 9223372036854775807)))
		valConsAddr, _ := validator.GetConsAddr()
		valAddr = valConsAddr
	}

	env.beginNewBlockWithProposer(executeNextEpoch, valAddr, blockTime, env.Ctx.BlockHeight()+1, chainID)
}

func (env *TestEnv) GetValidatorAddresses() []string {
	validators, _ := env.App.StakingKeeper.GetAllValidators(env.Ctx)
	var addresses []string
	for _, validator := range validators {
		addresses = append(addresses, validator.OperatorAddress)
	}

	return addresses
}

// beginNewBlockWithProposer begins a new block with a proposer.
func (env *TestEnv) beginNewBlockWithProposer(executeNextEpoch bool, proposer sdk.ValAddress, blockTime time.Time, blockHeight int64, chainID string) {
	validator, err := env.App.StakingKeeper.GetValidator(env.Ctx, proposer)
	requireNoErr(err)

	valConsAddr, err := validator.GetConsAddr()
	requireNoErr(err)

	valAddr := valConsAddr

	header := cmtproto.Header{ChainID: chainID, Height: blockHeight, Time: blockTime}
	env.Ctx = env.Ctx.WithBlockTime(blockTime).WithBlockHeight(blockHeight)
	voteInfos := []abci.VoteInfo{{
		Validator:   abci.Validator{Address: valAddr, Power: 1000},
		BlockIdFlag: cmtproto.BlockIDFlagCommit,
	}}
	env.Ctx = env.Ctx.WithVoteInfos(voteInfos)

	_, err = env.App.BeginBlocker(env.Ctx)
	requireNoErr(err)

	env.Ctx = env.App.NewContextLegacy(false, header)
}

func (env *TestEnv) setupValidator(bondStatus stakingtypes.BondStatus, valPriv cryptotypes.PrivKey) sdk.ValAddress {

	valPub := valPriv.PubKey()
	valAddr := sdk.ValAddress(valPub.Address())
	params, err := env.App.StakingKeeper.GetParams(env.Ctx)
	requireNoErr(err)
	bondDenom := params.BondDenom
	selfBond := sdk.NewCoins(sdk.Coin{Amount: sdkmath.NewInt(100), Denom: bondDenom})

	err = banktestutil.FundAccount(env.Ctx, env.App.BankKeeper, sdk.AccAddress(valPub.Address()), selfBond)
	requireNoErr(err)

	stakingMsgServer := stakingkeeper.NewMsgServerImpl(env.App.StakingKeeper)
	stakingCoin := sdk.NewCoin(bondDenom, selfBond[0].Amount)
	ZeroCommission := stakingtypes.NewCommissionRates(sdkmath.LegacyZeroDec(), sdkmath.LegacyZeroDec(), sdkmath.LegacyZeroDec())
	msg, err := stakingtypes.NewMsgCreateValidator(valAddr.String(), valPub, stakingCoin, stakingtypes.Description{}, ZeroCommission, sdkmath.OneInt())
	requireNoErr(err)
	res, err := stakingMsgServer.CreateValidator(env.Ctx, msg)
	requireNoErr(err)
	requireNoNil("staking handler", res)

	env.App.BankKeeper.SendCoinsFromModuleToModule(env.Ctx, stakingtypes.NotBondedPoolName, stakingtypes.BondedPoolName, sdk.NewCoins(stakingCoin))

	val, err := env.App.StakingKeeper.GetValidator(env.Ctx, valAddr)
	requireNoErr(err)

	val = val.UpdateStatus(bondStatus)
	env.App.StakingKeeper.SetValidator(env.Ctx, val)

	consAddr, err := val.GetConsAddr()
	requireNoErr(err)

	signingInfo := slashingtypes.NewValidatorSigningInfo(
		consAddr,
		env.Ctx.BlockHeight(),
		0,
		time.Unix(0, 0),
		false,
		0,
	)
	env.App.SlashingKeeper.SetValidatorSigningInfo(env.Ctx, consAddr, signingInfo)

	return valAddr
}

func (env *TestEnv) SetupParamTypes() {

}

func requireNoErr(err error) {
	if err != nil {
		panic(err)
	}
}

func requireNoNil(name string, nilable any) {
	if nilable == nil {
		panic(fmt.Sprintf("%s must not be nil", name))
	}
}
