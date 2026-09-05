#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use alloy_primitives::{keccak256, map::HashMap, Address, Bytes, B256};
use alloy_rpc_types::EIP1186AccountProofResponse;
use reth_trie::{AccountProof, HashedPostState, HashedStorage, TrieAccount, EMPTY_ROOT_HASH};
use serde::{Deserialize, Serialize};

#[cfg(feature = "execution-witness")]
mod execution_witness;

/// Module containing MPT code adapted from `zeth`.
mod mpt;
pub use mpt::Error;
pub use mpt::{report as resolver_report, stats as resolver_stats};
use mpt::{
    extend_trie_from_proof, mpt_from_proof, node_from_digest, parse_proof, proofs_to_tries,
    resolve_nodes, transition_proofs_to_tries, MptNode,
};

/// Ethereum state trie and account storage tries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EthereumState {
    pub state_trie: MptNode,
    pub storage_tries: HashMap<B256, MptNode>,
    /// The lazy witness: every trie node the host knows, keyed by keccak of
    /// its RLP.  When non-empty, `state_trie` starts as a bare root digest and
    /// storage tries are created on demand from each account's `storage_root`;
    /// a node is decoded — and its hash checked — only when a key path reaches
    /// it.  An empty map is the fully materialised (eager) form.
    #[serde(default)]
    /// `Bytes` (not `Vec<u8>`): bincode decodes it with one memcpy per node;
    /// a `Vec<u8>` goes through serde's per-element seq path in the guest.
    pub nodes: HashMap<B256, Bytes>,
}

/// The pre-lazy wire layout of [`EthereumState`] (no `nodes` field).  bincode
/// is positional, so inputs cached before the lazy witness landed can only be
/// read through this mirror; `From` gives the eager state back.
#[derive(Debug, Clone, Deserialize)]
pub struct LegacyEthereumState {
    pub state_trie: MptNode,
    pub storage_tries: HashMap<B256, MptNode>,
}

impl From<LegacyEthereumState> for EthereumState {
    fn from(l: LegacyEthereumState) -> Self {
        Self { state_trie: l.state_trie, storage_tries: l.storage_tries, nodes: HashMap::default() }
    }
}

impl EthereumState {
    /// Builds Ethereum state tries from relevant proofs before and after a state transition.
    pub fn from_transition_proofs(
        state_root: B256,
        parent_proofs: &HashMap<Address, AccountProof>,
        proofs: &HashMap<Address, AccountProof>,
    ) -> Result<Self, FromProofError> {
        transition_proofs_to_tries(state_root, parent_proofs, proofs)
    }

    /// Builds Ethereum state tries from relevant proofs from a given state.
    pub fn from_proofs(
        state_root: B256,
        proofs: &HashMap<Address, AccountProof>,
    ) -> Result<Self, FromProofError> {
        proofs_to_tries(state_root, proofs)
    }

    /// Builds Ethereum state tries from a EIP-1186 proof.
    pub fn from_account_proof(proof: EIP1186AccountProofResponse) -> Result<Self, FromProofError> {
        let mut storage_tries = HashMap::with_hasher(Default::default());
        let mut storage_nodes = HashMap::with_hasher(Default::default());
        let mut storage_root_node = MptNode::default();

        for storage_proof in &proof.storage_proof {
            let proof_nodes = parse_proof(&storage_proof.proof)?;
            mpt_from_proof(&proof_nodes)?;

            // the first node in the proof is the root
            if let Some(node) = proof_nodes.first() {
                storage_root_node = node.clone();
            }

            proof_nodes.into_iter().for_each(|node| {
                storage_nodes.insert(node.reference(), node);
            });
        }

        storage_tries
            .insert(keccak256(proof.address), resolve_nodes(&storage_root_node, &storage_nodes));

        let state = EthereumState {
            state_trie: MptNode::from_account_proof(&proof.account_proof)?,
            storage_tries,
            nodes: HashMap::default(),
        };

        Ok(state)
    }

    /// Resolves missing account trie nodes from an EIP-1186 account proof.
    pub fn extend_from_account_proof(
        &mut self,
        proof: &EIP1186AccountProofResponse,
    ) -> Result<(), FromProofError> {
        self.state_trie = extend_trie_from_proof(&self.state_trie, &proof.account_proof)?;
        let hashed_address = keccak256(proof.address);
        for storage_proof in &proof.storage_proof {
            let storage_trie = self
                .storage_tries
                .entry(hashed_address)
                .or_insert_with(|| node_from_digest(proof.storage_hash));
            if !storage_proof.proof.is_empty() {
                *storage_trie = extend_trie_from_proof(storage_trie, &storage_proof.proof)?;
            }
        }
        Ok(())
    }

    #[cfg(feature = "execution-witness")]
    pub fn from_execution_witness(
        witness: &alloy_rpc_types_debug::ExecutionWitness,
        pre_state_root: B256,
    ) -> Self {
        let (state_trie, storage_tries) =
            execution_witness::build_validated_tries(witness, pre_state_root).unwrap();

        Self { state_trie, storage_tries, nodes: HashMap::default() }
    }

    /// Mutates state based on diffs provided in [`HashedPostState`].
    /// The lazy form: a root digest plus the witness nodes it can resolve.
    pub fn from_witness(state_root: B256, nodes: HashMap<B256, Bytes>) -> Self {
        Self { state_trie: node_from_digest(state_root), storage_tries: HashMap::default(), nodes }
    }

    /// Convert a materialised state into its lazy witness form: the root
    /// digest and every digest-referenced node of the state trie and of the
    /// storage tries, as `(keccak, rlp)`.
    pub fn to_witness(&self) -> Self {
        let mut pairs = Vec::new();
        self.state_trie.collect_witness_nodes(&mut pairs);
        for trie in self.storage_tries.values() {
            trie.collect_witness_nodes(&mut pairs);
        }
        let mut nodes: HashMap<B256, Bytes> = HashMap::default();
        nodes.reserve(pairs.len());
        for (hash, rlp) in pairs {
            nodes.insert(hash, rlp.into());
        }
        Self::from_witness(self.state_trie.hash(), nodes)
    }

    /// Number of witness nodes carried (lazy form); 0 for a materialised state.
    pub fn witness_node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Resolve the state-trie path of `hashed_address` and read the account.
    pub fn account(&mut self, hashed_address: &B256) -> Result<Option<TrieAccount>, Error> {
        mpt::STATS_ACCOUNT_CALLS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let nibs = mpt::to_nibs(hashed_address.as_slice());
        let nodes = &self.nodes;
        mpt::report("mpt.account.resolve_path", || {
            self.state_trie.resolve_path(&nibs, &|d: &B256| nodes.get(d).cloned())
        })?;
        mpt::report("mpt.account.get", || {
            self.state_trie.get_rlp::<TrieAccount>(hashed_address.as_slice())
        })
    }

    /// The storage trie of `hashed_address`, created from the account's
    /// `storage_root` on first use in the lazy form.
    pub fn storage_trie_mut(&mut self, hashed_address: &B256) -> Result<&mut MptNode, Error> {
        if !self.storage_tries.contains_key(hashed_address) {
            let root = self
                .account(hashed_address)?
                .map(|a| a.storage_root)
                .unwrap_or(EMPTY_ROOT_HASH);
            let trie =
                if root == EMPTY_ROOT_HASH { MptNode::default() } else { node_from_digest(root) };
            self.storage_tries.insert(*hashed_address, trie);
        }
        Ok(self.storage_tries.get_mut(hashed_address).unwrap())
    }

    /// Resolve the storage path and read the slot's RLP value.
    pub fn storage<T: alloy_rlp::Decodable>(
        &mut self,
        hashed_address: &B256,
        hashed_slot: &[u8],
    ) -> Result<Option<T>, Error> {
        mpt::STATS_STORAGE_CALLS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        mpt::report("mpt.storage.trie_mut", || self.storage_trie_mut(hashed_address))?;
        let nibs = mpt::to_nibs(hashed_slot);
        let nodes = &self.nodes;
        let trie = self.storage_tries.get_mut(hashed_address).unwrap();
        mpt::report("mpt.storage.resolve_path", || {
            trie.resolve_path(&nibs, &|d: &B256| nodes.get(d).cloned())
        })?;
        mpt::report("mpt.storage.get", || trie.get_rlp::<T>(hashed_slot))
    }

    /// Run a mutating trie operation, resolving whatever digest it trips on
    /// (a delete that collapses a branch needs the surviving sibling, which
    /// is off the key path) until it succeeds.
    fn with_resolution<R>(
        trie: &mut MptNode,
        nodes: &HashMap<B256, Bytes>,
        key: &[u8],
        mut op: impl FnMut(&mut MptNode) -> Result<R, Error>,
    ) -> Result<R, Error> {
        let resolver = |d: &B256| nodes.get(d).cloned();
        trie.resolve_path_for_update(&mpt::to_nibs(key), &resolver)?;
        loop {
            match op(trie) {
                Err(Error::NodeNotResolved(digest)) => {
                    if !trie.resolve_digest(&digest, &resolver)? {
                        return Err(Error::NodeNotResolved(digest));
                    }
                }
                other => return other,
            }
        }
    }

    pub fn update(&mut self, post_state: &HashedPostState) {
        for (hashed_address, account) in post_state.accounts.iter() {
            match account {
                Some(account) => {
                    let state_storage = &post_state
                        .storages
                        .get(hashed_address)
                        .cloned()
                        .unwrap_or_else(|| HashedStorage::new(false));
                    let storage_root =
                        self.storage_root_after_update(*hashed_address, state_storage);

                    if account.is_empty() && storage_root == EMPTY_ROOT_HASH {
                        Self::with_resolution(
                            &mut self.state_trie,
                            &self.nodes,
                            hashed_address.as_slice(),
                            |t| t.delete(hashed_address.as_slice()),
                        )
                        .unwrap();
                        self.storage_tries.remove(hashed_address);
                        continue;
                    }

                    let state_account = TrieAccount {
                        nonce: account.nonce,
                        balance: account.balance,
                        storage_root,
                        code_hash: account.get_bytecode_hash(),
                    };
                    Self::with_resolution(
                        &mut self.state_trie,
                        &self.nodes,
                        hashed_address.as_slice(),
                        |t| t.insert_rlp(hashed_address.as_slice(), state_account.clone()),
                    )
                    .unwrap();
                }
                None => {
                    Self::with_resolution(
                        &mut self.state_trie,
                        &self.nodes,
                        hashed_address.as_slice(),
                        |t| t.delete(hashed_address.as_slice()),
                    )
                    .unwrap();
                    self.storage_tries.remove(hashed_address);
                }
            }
        }
    }

    fn storage_root_after_update(
        &mut self,
        hashed_address: B256,
        state_storage: &HashedStorage,
    ) -> B256 {
        if state_storage.is_empty() {
            if let Some(storage_trie) = self.storage_tries.get(&hashed_address) {
                return storage_trie.hash()
            }

            return self
                .account(&hashed_address)
                .unwrap()
                .map(|account| account.storage_root)
                .unwrap_or(EMPTY_ROOT_HASH)
        }

        // In the lazy form an untouched storage trie may not exist yet: seed
        // it from the account's storage root before applying the writes.
        if !self.storage_tries.contains_key(&hashed_address) {
            let _ = self.storage_trie_mut(&hashed_address).unwrap();
        }
        let nodes = &self.nodes;
        let storage_trie = self.storage_tries.get_mut(&hashed_address).unwrap();

        if state_storage.wiped {
            storage_trie.clear();
        }

        for (key, value) in state_storage.storage.iter() {
            let key = key.as_slice();
            if value.is_zero() {
                Self::with_resolution(storage_trie, nodes, key, |t| t.delete(key)).unwrap();
            } else {
                Self::with_resolution(storage_trie, nodes, key, |t| t.insert_rlp(key, *value))
                    .unwrap();
            }
        }

        storage_trie.hash()
    }

    /// Computes the state root.
    pub fn state_root(&self) -> B256 {
        self.state_trie.hash()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FromProofError {
    #[error("Node {} is not found by hash", .0)]
    NodeNotFoundByHash(usize),
    #[error("Node {} refrences invalid successor", .0)]
    NodeHasInvalidSuccessor(usize),
    #[error("Node {} cannot have children and is invalid", .0)]
    NodeCannotHaveChildren(usize),
    #[error("Found mismatched storage root after reconstruction \n account {}, found {}, expected {}", .0, .1, .2)]
    MismatchedStorageRoot(Address, B256, B256),
    #[error("Found mismatched staet root after reconstruction \n found {}, expected {}", .0, .1)]
    MismatchedStateRoot(B256, B256),
    // todo: Should decode return a decoder error?
    #[error("Error decoding proofs from bytes, {}", .0)]
    DecodingError(#[from] Error),
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{b256, U256};
    use reth_primitives_traits::Account;

    use super::*;

    #[test]
    fn update_removes_empty_account_with_empty_storage_root() {
        let hashed_address = B256::repeat_byte(0x11);
        let post_state =
            HashedPostState::default().with_accounts([(hashed_address, Some(Default::default()))]);
        let mut state =
            EthereumState { state_trie: MptNode::default(), storage_tries: HashMap::default(), nodes: HashMap::default() };

        state.update(&post_state);

        assert!(state.state_trie.get(hashed_address.as_slice()).unwrap().is_none());
        assert_eq!(state.state_root(), EMPTY_ROOT_HASH);
        assert!(!state.storage_tries.contains_key(&hashed_address));
    }

    #[test]
    fn update_preserves_storage_root_when_storage_trie_is_not_revealed() {
        let hashed_address = B256::repeat_byte(0x22);
        let storage_root =
            b256!("3333333333333333333333333333333333333333333333333333333333333333");
        let mut state =
            EthereumState { state_trie: MptNode::default(), storage_tries: HashMap::default(), nodes: HashMap::default() };
        state
            .state_trie
            .insert_rlp(
                hashed_address.as_slice(),
                TrieAccount {
                    nonce: 0,
                    balance: U256::from(1),
                    storage_root,
                    code_hash: TrieAccount::default().code_hash,
                },
            )
            .unwrap();
        let post_state = HashedPostState::default().with_accounts([(
            hashed_address,
            Some(Account { nonce: 0, balance: U256::from(2), bytecode_hash: None }),
        )]);

        state.update(&post_state);

        let account =
            state.state_trie.get_rlp::<TrieAccount>(hashed_address.as_slice()).unwrap().unwrap();
        assert_eq!(account.balance, U256::from(2));
        assert_eq!(account.storage_root, storage_root);
    }
}

#[cfg(test)]
mod lazy_tests {
    use super::*;
    use alloy_primitives::{keccak256, U256};

    fn key(i: u64) -> B256 {
        keccak256(i.to_be_bytes())
    }

    /// Eager trie with `n` accounts; account `i` owns `i % 4` storage slots.
    fn eager_state(n: u64) -> EthereumState {
        let mut st = EthereumState::default();
        for i in 0..n {
            let ha = key(i);
            let mut storage_root = EMPTY_ROOT_HASH;
            if i % 4 != 0 {
                let trie = st.storage_tries.entry(ha).or_default();
                for j in 0..(i % 4) {
                    trie.insert_rlp(key(1_000_000 + i * 16 + j).as_slice(), U256::from(j + 7)).unwrap();
                }
                storage_root = trie.hash();
            }
            let acc = TrieAccount {
                nonce: i,
                balance: U256::from(i * 1000),
                storage_root,
                code_hash: keccak256(i.to_le_bytes()),
            };
            st.state_trie.insert_rlp(ha.as_slice(), acc).unwrap();
        }
        st
    }

    #[test]
    fn decode_fast_matches_legacy_decoder() {
        let state = eager_state(300);
        let witness = state.to_witness();
        assert!(!witness.nodes.is_empty());
        for (hash, rlp) in &witness.nodes {
            let fast = MptNode::decode_fast(rlp).unwrap();
            let legacy = MptNode::decode(rlp).unwrap();
            assert_eq!(fast, legacy, "node {hash}");
            assert_eq!(fast.hash(), *hash);
        }
    }

    #[test]
    fn lazy_reads_match_eager() {
        let eager = eager_state(300);
        let mut lazy = eager.to_witness();
        assert_eq!(lazy.state_root(), eager.state_root());
        for i in 0..300u64 {
            let ha = key(i);
            let e = eager.state_trie.get_rlp::<TrieAccount>(ha.as_slice()).unwrap();
            let l = lazy.account(&ha).unwrap();
            assert_eq!(e, l, "account {i}");
            for j in 0..(i % 4) {
                let slot = key(1_000_000 + i * 16 + j);
                let e = eager.storage_tries[&ha].get_rlp::<U256>(slot.as_slice()).unwrap();
                let l = lazy.storage::<U256>(&ha, slot.as_slice()).unwrap();
                assert_eq!(e, l, "slot {i}/{j}");
            }
        }
        // A key that is not there resolves to None on both.
        assert_eq!(lazy.account(&key(999_999)).unwrap(), None);
    }

    #[test]
    fn lazy_update_matches_eager() {
        use reth_trie::{HashedPostState, HashedStorage};
        use alloy_primitives::map::B256Map;
        use reth_primitives_traits::Account;

        let mut eager = eager_state(300);
        let mut lazy = eager.to_witness();

        let mut post = HashedPostState::default();
        for i in (0..300u64).step_by(3) {
            let ha = key(i);
            // touch: change balance, write two slots (one new, one zeroed)
            post.accounts.insert(
                ha,
                Some(Account { nonce: i + 1, balance: U256::from(i * 7 + 1), bytecode_hash: Some(keccak256(i.to_le_bytes())) }),
            );
            let mut hs = HashedStorage::new(false);
            hs.storage.insert(key(1_000_000 + i * 16), U256::ZERO); // delete first slot if present
            hs.storage.insert(key(2_000_000 + i), U256::from(42u64)); // new slot
            post.storages.insert(ha, hs);
        }
        // delete a few accounts outright
        for i in [5u64, 50, 150] {
            post.accounts.insert(key(i), None);
        }
        // brand-new account
        post.accounts.insert(key(777_777), Some(Account { nonce: 1, balance: U256::from(1u64), bytecode_hash: None }));
        let _unused: B256Map<()> = Default::default();

        eager.update(&post);
        lazy.update(&post);
        assert_eq!(lazy.state_root(), eager.state_root(), "post-state roots differ");
    }
}
