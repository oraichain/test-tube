use test_tube::cosmrs::proto::cosmos::base::abci::v1beta1::GasInfo;
use test_tube::cosmrs::Any;

use cosmwasm_std::{Coin, Timestamp};

use prost::Message;
use test_tube::account::SigningAccount;

use test_tube::runner::result::{RunnerExecuteResult, RunnerResult};
use test_tube::runner::Runner;
use test_tube::BaseApp;

pub const FEE_DENOM: &str = "orai";
pub const OSMO_ADDRESS_PREFIX: &str = "orai";
pub const CHAIN_ID: &str = "Oraichain";
pub const DEFAULT_GAS_ADJUSTMENT: f64 = 1.2;

#[derive(Debug, PartialEq)]
pub struct OsmosisTestApp {
    inner: BaseApp,
}

impl Default for OsmosisTestApp {
    fn default() -> Self {
        OsmosisTestApp::new()
    }
}

impl OsmosisTestApp {
    pub fn new() -> Self {
        Self {
            inner: BaseApp::new(
                FEE_DENOM,
                CHAIN_ID,
                OSMO_ADDRESS_PREFIX,
                DEFAULT_GAS_ADJUSTMENT,
            ),
        }
    }

    /// Get the current block time as a timestamp
    pub fn get_block_timestamp(&self) -> Timestamp {
        self.inner.get_block_timestamp()
    }

    /// Get the current block time in nanoseconds
    pub fn get_block_time_nanos(&self) -> i64 {
        self.inner.get_block_time_nanos()
    }

    /// Get the current block time in seconds
    pub fn get_block_time_seconds(&self) -> i64 {
        self.inner.get_block_time_nanos() / 1_000_000_000i64
    }

    /// Set the current block time in nanoseconds
    pub fn set_block_time_nanos(&self, nanoseconds: u64) {
        self.inner.set_block_time_nanos(nanoseconds)
    }

    /// Set the current block time in seconds
    pub fn set_block_time_seconds(&self, seconds: u64) {
        self.inner.set_block_time_nanos(seconds * 1_000_000_000u64)
    }

    /// Set the current chain id
    pub fn set_chain_id(&self, chain_id: &str) {
        self.inner.set_chain_id(chain_id)
    }

    /// Get the current block height
    pub fn get_block_height(&self) -> i64 {
        self.inner.get_block_height()
    }

    pub fn setup_validator(&self, coins: &[Coin]) -> RunnerResult<String> {
        self.inner.setup_validator(coins)
    }

    pub fn setup_validator_with_secret(
        &self,
        coins: &[Coin],
        secret: &str,
    ) -> RunnerResult<String> {
        self.inner.setup_validator_with_secret(coins, secret)
    }

    pub fn get_validator_addresses(&self) -> RunnerResult<Vec<String>> {
        self.inner.get_validator_addresses()
    }

    /// Get the first validator address
    pub fn get_first_validator_address(&self) -> RunnerResult<String> {
        self.inner.get_first_validator_address()
    }

    /// Get the first validator signing account
    pub fn get_first_validator_signing_account(&self) -> RunnerResult<SigningAccount> {
        self.inner.get_first_validator_signing_account()
    }

    /// Increase the time of the blockchain by the given number of seconds.
    pub fn increase_time(&self, seconds: u64) {
        self.inner.increase_time(seconds)
    }

    /// Initialize account with initial balance of any coins.
    /// This function mints new coins and send to newly created account
    pub fn init_account(&self, coins: &[Coin]) -> RunnerResult<SigningAccount> {
        self.inner.init_account(coins)
    }

    pub fn init_account_with_secret(
        &self,
        coins: &[Coin],
        secret: &str,
    ) -> RunnerResult<SigningAccount> {
        self.inner.init_account_with_secret(coins, secret)
    }

    /// Convinience function to create multiple accounts with the same
    /// Initial coins balance
    pub fn init_accounts(&self, coins: &[Coin], count: u64) -> RunnerResult<Vec<SigningAccount>> {
        self.inner.init_accounts(coins, count)
    }

    pub fn init_accounts_with_secrets(
        &self,
        coins: &[Coin],
        secrets: &[&str],
    ) -> RunnerResult<Vec<SigningAccount>> {
        self.inner.init_accounts_with_secrets(coins, secrets)
    }

    pub fn setup_validators(&self, coins: &[Coin], count: u64) -> RunnerResult<Vec<String>> {
        self.inner.setup_validators(coins, count)
    }

    pub fn setup_validators_with_secrets(
        &self,
        coins: &[Coin],
        secrets: &[&str],
    ) -> RunnerResult<Vec<String>> {
        self.inner.setup_validators_with_secrets(coins, secrets)
    }

    /// Simulate transaction execution and return gas info
    pub fn simulate_tx<I>(&self, msgs: I, signer: &SigningAccount) -> RunnerResult<GasInfo>
    where
        I: IntoIterator<Item = Any>,
    {
        self.inner.simulate_tx(msgs, signer)
    }

    /// Set parameter set for a given subspace.
    pub fn set_param_set(&self, subspace: &str, pset: impl Into<Any>) -> RunnerResult<()> {
        self.inner.set_param_set(subspace, pset)
    }

    /// Get parameter set for a given subspace.
    pub fn get_param_set<P: Message + Default>(
        &self,
        subspace: &str,
        type_url: &str,
    ) -> RunnerResult<P> {
        self.inner.get_param_set(subspace, type_url)
    }

    /// Directly trigger sudo entrypoint on a given contract.
    ///
    /// # Caution
    ///
    /// This function bypasses standard state changes and processes within the chain logic that might occur in normal situation,
    /// It is primarily intended for internal system logic where necessary state adjustments are handled.
    /// Use only with full understanding of the function's impact on system state and testing validity.
    /// Improper use may result in misleading test outcomes, including false positives or negatives.
    #[cfg(feature = "wasm-sudo")]
    pub fn wasm_sudo<M: serde::Serialize>(
        &self,
        contract_address: &str,
        sudo_msg: M,
    ) -> RunnerResult<Vec<u8>> {
        self.inner.wasm_sudo(contract_address, sudo_msg)
    }
}

impl<'a> Runner<'a> for OsmosisTestApp {
    fn execute_multiple<M, R>(
        &self,
        msgs: &[(M, &str)],
        signer: &SigningAccount,
    ) -> RunnerExecuteResult<R>
    where
        M: ::prost::Message,
        R: ::prost::Message + Default,
    {
        self.inner.execute_multiple(msgs, signer)
    }

    fn query<Q, R>(&self, path: &str, q: &Q) -> RunnerResult<R>
    where
        Q: ::prost::Message,
        R: ::prost::Message + Default,
    {
        self.inner.query(path, q)
    }

    fn execute_multiple_raw<R>(
        &self,
        msgs: Vec<test_tube::cosmrs::Any>,
        signer: &SigningAccount,
    ) -> RunnerExecuteResult<R>
    where
        R: prost::Message + Default,
    {
        self.inner.execute_multiple_raw(msgs, signer)
    }
}

#[cfg(test)]
mod tests {

    use std::option::Option::None;
    use test_tube::cosmrs::proto::cosmos::bank::v1beta1::QueryAllBalancesRequest;

    use cosmwasm_std::{coins, Coin};

    use crate::module::Wasm;
    use crate::runner::app::OsmosisTestApp;
    use crate::Bank;
    use test_tube::account::{Account, FeeSetting};
    use test_tube::module::Module;

    #[test]
    fn test_init_accounts() {
        let app = OsmosisTestApp::default();
        let accounts = app
            .init_accounts(&coins(100_000_000_000, "orai"), 3)
            .unwrap();

        assert!(accounts.get(0).is_some());
        assert!(accounts.get(1).is_some());
        assert!(accounts.get(2).is_some());
        assert!(accounts.get(3).is_none());
    }

    #[test]
    fn test_get_and_set_block_timestamp() {
        let app = OsmosisTestApp::default();

        let block_time_nanos = app.get_block_time_nanos();
        let block_time_seconds = app.get_block_time_seconds();

        app.increase_time(10u64);

        assert_eq!(
            app.get_block_time_nanos(),
            block_time_nanos + 10_000_000_000
        );
        assert_eq!(app.get_block_time_seconds(), block_time_seconds + 10);
    }

    #[test]
    fn test_get_block_height() {
        let app = OsmosisTestApp::default();

        assert_eq!(app.get_block_height(), 1i64);

        app.increase_time(10u64);

        assert_eq!(app.get_block_height(), 2i64);
    }

    #[test]
    fn test_multiple_as_module() {
        let app = OsmosisTestApp::default();
        let alice = app
            .init_account(&[
                Coin::new(1_000_000_000_000u128, "uatom"),
                Coin::new(1_000_000_000_000u128, "orai"),
            ])
            .unwrap();

        let wasm = Wasm::new(&app);
        let wasm_byte_code = std::fs::read("./test_artifacts/cw1_whitelist.wasm").unwrap();
        let code_id = wasm
            .store_code(&wasm_byte_code, None, &alice)
            .unwrap()
            .data
            .code_id;

        assert_eq!(code_id, 1);
    }

    #[test]
    fn test_wasm_execute_and_query() {
        use cw1_whitelist::msg::*;

        let app = OsmosisTestApp::default();
        let accs = app
            .init_accounts(
                &[
                    Coin::new(1_000_000_000_000u128, "uatom"),
                    Coin::new(1_000_000_000_000u128, "orai"),
                ],
                2,
            )
            .unwrap();
        let admin = &accs[0];
        let new_admin = &accs[1];

        let wasm = Wasm::new(&app);
        let wasm_byte_code = std::fs::read("./test_artifacts/cw1_whitelist.wasm").unwrap();
        let code_id = wasm
            .store_code(&wasm_byte_code, None, admin)
            .unwrap()
            .data
            .code_id;
        assert_eq!(code_id, 1);

        // initialize admins and check if the state is correct
        let init_admins = vec![admin.address()];
        let contract_addr = wasm
            .instantiate(
                code_id,
                &InstantiateMsg {
                    admins: init_admins.clone(),
                    mutable: true,
                },
                Some(&admin.address()),
                None,
                &[],
                admin,
            )
            .unwrap()
            .data
            .address;
        let admin_list = wasm
            .query::<QueryMsg, AdminListResponse>(&contract_addr, &QueryMsg::AdminList {})
            .unwrap();
        assert_eq!(admin_list.admins, init_admins);
        assert!(admin_list.mutable);

        // update admin and check again
        let new_admins = vec![new_admin.address()];
        wasm.execute::<ExecuteMsg>(
            &contract_addr,
            &ExecuteMsg::UpdateAdmins {
                admins: new_admins.clone(),
            },
            &[],
            admin,
        )
        .unwrap();

        let admin_list = wasm
            .query::<QueryMsg, AdminListResponse>(&contract_addr, &QueryMsg::AdminList {})
            .unwrap();

        assert_eq!(admin_list.admins, new_admins);
        assert!(admin_list.mutable);
    }

    #[test]
    fn test_custom_fee() {
        let app = OsmosisTestApp::default();
        let initial_balance = 1_000_000_000_000;
        let alice = app.init_account(&coins(initial_balance, "orai")).unwrap();
        let bob = app.init_account(&coins(initial_balance, "orai")).unwrap();

        let amount = Coin::new(1_000_000u128, "orai");
        let gas_limit = 100_000_000;

        // use FeeSetting::Auto by default, so should not equal newly custom fee setting
        let wasm = Wasm::new(&app);
        let wasm_byte_code = std::fs::read("./test_artifacts/cw1_whitelist.wasm").unwrap();
        let res = wasm.store_code(&wasm_byte_code, None, &alice).unwrap();

        assert_ne!(res.gas_info.gas_wanted, gas_limit);

        //update fee setting
        let bob = bob.with_fee_setting(FeeSetting::Custom {
            amount: amount.clone(),
            gas_limit,
        });
        let res = wasm.store_code(&wasm_byte_code, None, &bob).unwrap();

        let bob_balance = Bank::new(&app)
            .query_all_balances(&QueryAllBalancesRequest {
                address: bob.address(),
                pagination: None,
            })
            .unwrap()
            .balances
            .into_iter()
            .find(|c| c.denom == "orai")
            .unwrap()
            .amount
            .parse::<u128>()
            .unwrap();

        assert_eq!(res.gas_info.gas_wanted, gas_limit);
        assert_eq!(bob_balance, initial_balance - amount.amount.u128());
    }

    #[cfg(feature = "wasm-sudo")]
    #[test]
    fn test_wasm_sudo() {
        mod simple_sudo {

            use cosmwasm_schema::cw_serde;

            #[cw_serde]
            pub struct InstantiateMsg {}

            #[cw_serde]
            pub enum ExecuteMsg {}

            #[cw_serde]
            pub enum QueryMsg {
                GetRandomData { key: String },
            }

            #[cw_serde]
            pub enum SudoMsg {
                SetRandomData { key: String, value: String },
            }

            #[cw_serde]
            pub struct RandomDataResponse {
                pub key: String,
                pub value: String,
            }
        }

        let app = OsmosisTestApp::default();
        let wasm = Wasm::new(&app);

        let wasm_byte_code = std::fs::read("./test_artifacts/simple_sudo.wasm").unwrap();
        let alice = app.init_account(&coins(1_000_000_000_000, "orai")).unwrap();

        let code_id = wasm
            .store_code(&wasm_byte_code, None, &alice)
            .unwrap()
            .data
            .code_id;

        let contract_addr = wasm
            .instantiate(
                code_id,
                &simple_sudo::InstantiateMsg {},
                None,
                Some("simple_sudo"),
                &[],
                &alice,
            )
            .unwrap()
            .data
            .address;

        let res = app
            .wasm_sudo(
                &contract_addr,
                simple_sudo::SudoMsg::SetRandomData {
                    key: "x".to_string(),
                    value: "1".to_string(),
                },
            )
            .unwrap();

        assert_eq!(String::from_utf8(res).unwrap(), "x=1");

        let res: simple_sudo::RandomDataResponse = wasm
            .query(
                &contract_addr,
                &simple_sudo::QueryMsg::GetRandomData {
                    key: "x".to_string(),
                },
            )
            .unwrap();
        assert_eq!(res.value, "1");
    }
}
