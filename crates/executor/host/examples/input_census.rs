//! Native census of a cached guest input: which fields dominate the bytes,
//! the decode work and the hashing work the guest pays before executing a
//! single EVM instruction.  Native timings are a proxy for guest cycles
//! (same code, minus the keccak precompile), good for ranking, not for
//! absolute numbers.
//!
//! Run:
//!   cargo run --release -p host-executor --example input_census -- <input.bin>

use std::time::Instant;

use guest_executor::io::EthClientExecutorInput;
use serde::{de::DeserializeOwned, Serialize};

fn timed<T>(label: &str, f: impl FnOnce() -> T) -> T {
    let t = Instant::now();
    let out = f();
    println!("{label:<52} {:>9.1} ms", t.elapsed().as_secs_f64() * 1e3);
    out
}

fn field<T: Serialize + DeserializeOwned>(label: &str, v: &T) {
    let bytes = bincode::serialize(v).unwrap();
    let t = Instant::now();
    let _: T = bincode::deserialize(&bytes).unwrap();
    println!(
        "{label:<52} {:>9.1} ms decode  {:>10} bytes",
        t.elapsed().as_secs_f64() * 1e3,
        bytes.len()
    );
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: input_census <input.bin>");
    let bytes = std::fs::read(&path).expect("read input");
    println!("input file: {} bytes", bytes.len());

    let input: EthClientExecutorInput =
        timed("bincode::deserialize (whole input)", || bincode::deserialize(&bytes).unwrap());

    println!("\n== per-field decode (re-serialized, then decoded natively) ==");
    // current_block / ancestor_headers use reth's serde_bincode_compat
    // wrappers and cannot be bincode-serialized bare; they are the remainder
    // of the whole-input figure after the fields below.
    field("parent_state.state_trie", &input.parent_state.state_trie);
    field("parent_state.storage_tries", &input.parent_state.storage_tries);
    field("bytecodes", &input.bytecodes);
    field("genesis (json string)", &input.genesis);

    println!("\n== counts ==");
    println!("transactions: {}", input.current_block.body.transactions.len());
    println!("ancestor headers: {}", input.ancestor_headers.len());
    println!("state trie: size()={}", input.parent_state.state_trie.size());
    let storage_nodes: usize = input.parent_state.storage_tries.values().map(|t| t.size()).sum();
    println!(
        "storage tries: {} tries, size() total={}",
        input.parent_state.storage_tries.len(),
        storage_nodes
    );
    let code_bytes: usize = input.bytecodes.iter().map(|b| b.len()).sum();
    println!("bytecodes: {} contracts, {} code bytes", input.bytecodes.len(), code_bytes);

    println!("\n== witness-db work (what the guest hashes) ==");
    timed("state_trie.hash() (keccak every node)", || input.parent_state.state_trie.hash());
    timed("all storage_tries.hash()", || {
        for t in input.parent_state.storage_tries.values() {
            let _ = t.hash();
        }
    });
    timed("bytecodes hash_slow() (keccak all code)", || {
        for b in &input.bytecodes {
            let _ = b.hash_slow();
        }
    });
    timed("ancestor headers hash_slow()", || {
        for h in &input.ancestor_headers {
            let _ = h.hash_slow();
        }
    });
}
