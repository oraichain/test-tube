#![doc = include_str!("../README.md")]

mod module;
mod runner;

pub use test_tube::cosmrs;

pub use module::*;
use runner::app::OsmosisTestApp;
pub use test_tube::account::{Account, FeeSetting, NonSigningAccount, SigningAccount};
pub use test_tube::runner::error::{DecodeError, EncodeError, RunnerError};
pub use test_tube::runner::result::{ExecuteResponse, RunnerExecuteResult, RunnerResult};
pub use test_tube::runner::Runner;
pub use test_tube::{fn_execute, fn_query};

// public export as OraichainTestApp to avoid conflicts
pub use runner::app::OsmosisTestApp as OraichainTestApp;
pub use runner::app::{CHAIN_ID, DEFAULT_GAS_ADJUSTMENT, FEE_DENOM, OSMO_ADDRESS_PREFIX};
