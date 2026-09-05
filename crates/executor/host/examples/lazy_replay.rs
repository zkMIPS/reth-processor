//! Correctness gate for the lazy witness trie, natively: load a cached
//! (eager-format) guest input, convert it to the lazy witness form exactly as
//! the host now does, run the real guest `ClientExecutor::execute` on both
//! forms, and require identical headers/roots.  Also reports how many witness
//! nodes the lazy run actually resolved vs. the total shipped.
//!
//! Run:
//!   cargo run --release -p host-executor --example lazy_replay -- <input.bin>

use std::{sync::Arc, time::Instant};

use guest_executor::{executor::EthClientExecutor, io::EthClientExecutorInput};
use serde::Deserialize;
use serde_with::serde_as;

/// The pre-lazy input layout (bincode is positional: no `nodes`, no
/// `code_hashes`), so cached inputs from before the change can be replayed.
#[serde_as]
#[derive(Deserialize)]
struct LegacyInput {
    #[serde_as(
        as = "reth_primitives_traits::serde_bincode_compat::Block<'_, reth_ethereum_primitives::TransactionSigned, alloy_consensus::Header>"
    )]
    current_block: alloy_consensus::Block<reth_ethereum_primitives::TransactionSigned>,
    #[serde_as(as = "Vec<alloy_consensus::serde_bincode_compat::Header>")]
    ancestor_headers: Vec<alloy_consensus::Header>,
    parent_state: mpt::LegacyEthereumState,
    bytecodes: Vec<revm_bytecode::Bytecode>,
    genesis: primitives::genesis::Genesis,
    custom_beneficiary: Option<alloy_primitives::Address>,
    opcode_tracking: bool,
}

fn run(label: &str, input: EthClientExecutorInput) -> (alloy_consensus::Header, alloy_primitives::B256) {
    let executor = EthClientExecutor::eth(
        Arc::new((&input.genesis).try_into().unwrap()),
        input.custom_beneficiary,
    );
    let t = Instant::now();
    let out = executor.execute(input).expect("execute");
    println!("{label:<10} {:>8.1} ms  state_root={}", t.elapsed().as_secs_f64() * 1e3, out.0.state_root);
    out
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: lazy_replay <input.bin>");
    let bytes = std::fs::read(&path).expect("read input");
    let legacy: LegacyInput = bincode::deserialize(&bytes).expect("legacy input layout");
    let eager = EthClientExecutorInput {
        current_block: legacy.current_block,
        ancestor_headers: legacy.ancestor_headers,
        parent_state: legacy.parent_state.into(),
        bytecodes: legacy.bytecodes,
        code_hashes: Vec::new(),
        genesis: legacy.genesis,
        custom_beneficiary: legacy.custom_beneficiary,
        opcode_tracking: legacy.opcode_tracking,
    };

    // The lazy form the host now ships.
    let mut lazy = eager.clone();
    lazy.parent_state = eager.parent_state.to_witness();
    lazy.code_hashes = eager.bytecodes.iter().map(|b| b.hash_slow()).collect();
    let lazy_bytes = bincode::serialize(&lazy).unwrap();
    println!(
        "eager input {} bytes; lazy input {} bytes ({} witness nodes, {} bytecodes)",
        bytes.len(),
        lazy_bytes.len(),
        lazy.parent_state.nodes.len(),
        lazy.code_hashes.len()
    );
    let t = Instant::now();
    let lazy_rt: EthClientExecutorInput = bincode::deserialize(&lazy_bytes).unwrap();
    println!("lazy input decode {:.1} ms", t.elapsed().as_secs_f64() * 1e3);

    let (h_eager, r_eager) = run("eager", eager);
    let (h_lazy, r_lazy) = run("lazy", lazy_rt);
    assert_eq!(h_eager, h_lazy, "headers differ");
    assert_eq!(r_eager, r_lazy, "parent roots differ");
    println!("OK: lazy == eager (block hash {})", h_lazy.hash_slow());
}
