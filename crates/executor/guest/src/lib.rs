#![cfg_attr(not(test), warn(unused_crate_dependencies))]

/// Client program input data types.
pub mod io;
#[macro_use]
mod utils;
pub mod custom;
pub mod error;
pub mod executor;
pub mod tracking;

mod into_primitives;
pub use into_primitives::{FromInput, IntoInput, IntoPrimitives, ValidateBlockPostExecution};

use std::sync::Arc;
use alloy_primitives::FixedBytes;
use executor::{EthClientExecutor, DESERIALZE_INPUTS};
use io::EthClientExecutorInput;

pub fn verify_block_hash(input: &Vec<u8>) -> FixedBytes<32> {
    println!("cycle-tracker-report-start: {}", DESERIALZE_INPUTS);
    let input = bincode::deserialize::<EthClientExecutorInput>(input).unwrap();
    println!("cycle-tracker-report-end: {}", DESERIALZE_INPUTS);

    // Execute the block.
    let executor = EthClientExecutor::eth(
        Arc::new((&input.genesis).try_into().unwrap()),
        input.custom_beneficiary,
    );
    let header = executor.execute(input).expect("failed to execute client");
    let block_hash = header.hash_slow();
    block_hash
}
