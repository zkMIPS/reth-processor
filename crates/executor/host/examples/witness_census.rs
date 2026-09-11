//! Native census of a cached client input's witness: how many trie nodes of
//! each kind the guest's arena loader walks, how many bytes, and how long the
//! native load takes.  `cargo run --release --example witness_census -- <input.bin>`
use std::time::Instant;

use guest_executor::io::EthClientExecutorInput;
use mpt::ArenaState;

const TAG_DIGEST: u8 = 0;
const TAG_NODE: u8 = 1;

#[derive(Default, Debug)]
struct Census {
    nodes: usize,
    nulls: usize,
    digests: usize,
    leaves: usize,
    extensions: usize,
    branches: usize,
    inline_children: usize,
    node_bytes: usize,
    keccak_blocks: usize,
}

fn varint(buf: &[u8], pos: &mut usize) -> usize {
    let (mut v, mut shift) = (0usize, 0);
    loop {
        let b = buf[*pos];
        *pos += 1;
        v |= ((b & 0x7f) as usize) << shift;
        if b & 0x80 == 0 {
            return v;
        }
        shift += 7;
    }
}

fn items(payload: &[u8]) -> usize {
    let mut rest = payload;
    let mut n = 0;
    while !rest.is_empty() {
        let h = alloy_rlp::Header::decode(&mut rest).unwrap();
        rest = &rest[h.payload_length..];
        n += 1;
    }
    n
}

fn walk(stream: &[u8], c: &mut Census) {
    let mut pos = 0;
    while pos < stream.len() {
        let tag = stream[pos];
        pos += 1;
        match tag {
            TAG_DIGEST => c.digests += 1,
            TAG_NODE => {
                let len = varint(stream, &mut pos);
                let node = &stream[pos..pos + len];
                pos += len;
                c.nodes += 1;
                c.node_bytes += len;
                c.keccak_blocks += len.div_ceil(136);
                let mut b = node;
                let h = alloy_rlp::Header::decode(&mut b).unwrap();
                let payload = &b[..h.payload_length];
                if !h.list {
                    c.nulls += 1;
                    continue;
                }
                match items(payload) {
                    2 => {
                        let mut r = payload;
                        let ph = alloy_rlp::Header::decode(&mut r).unwrap();
                        let path = &r[..ph.payload_length];
                        if path[0] & 0x20 == 0 {
                            c.extensions += 1
                        } else {
                            c.leaves += 1
                        }
                    }
                    17 => {
                        c.branches += 1;
                        let mut r = payload;
                        for _ in 0..16 {
                            let ch = alloy_rlp::Header::decode(&mut r).unwrap();
                            if ch.list {
                                c.inline_children += 1;
                            }
                            r = &r[ch.payload_length..];
                        }
                    }
                    n => panic!("node with {n} items"),
                }
            }
            _ => panic!("bad tag"),
        }
    }
}

fn main() {
    let path = std::env::args().nth(1).expect("input.bin");
    let bytes = std::fs::read(&path).unwrap();
    let t = Instant::now();
    let input: EthClientExecutorInput = bincode::deserialize(&bytes).unwrap();
    println!("input {} B, bincode decode {:?}", bytes.len(), t.elapsed());
    let w = &input.parent_state;
    let mut state = Census::default();
    walk(&w.state_nodes, &mut state);
    println!("state trie: {} B stream, {state:?}", w.state_nodes.len());
    let mut storage = Census::default();
    let mut storage_bytes = 0;
    for (_, _, s) in &w.storage {
        storage_bytes += s.len();
        walk(s, &mut storage);
    }
    println!("storage tries: {} tries, {storage_bytes} B streams, {storage:?}", w.storage.len());
    println!(
        "bytecodes: {} ({} code bytes), txs {}",
        input.bytecodes.len(),
        input.bytecodes.iter().map(|b| b.len()).sum::<usize>(),
        input.current_block.body.transactions.len()
    );
    let t = Instant::now();
    let st = ArenaState::from_witness(w).unwrap();
    println!("native ArenaState::from_witness: {:?}", t.elapsed());
    std::hint::black_box(st);
}
