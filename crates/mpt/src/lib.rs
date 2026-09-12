#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use alloy_primitives::{keccak256, map::HashMap, Address, B256};
use alloy_rpc_types::EIP1186AccountProofResponse;
use reth_trie::{AccountProof, HashedPostState, HashedStorage, TrieAccount, EMPTY_ROOT_HASH};
use serde::{Deserialize, Serialize};

#[cfg(feature = "execution-witness")]
mod execution_witness;

/// Module containing MPT code adapted from `zeth`.
mod mpt;
/// Arena-backed trie built from a preorder RLP witness stream (the guest's form).
mod arena;
pub use arena::{witness_stream, ArenaState, ArenaTrie, StorageWitness, WitnessState};
pub use mpt::Error;
use mpt::{
    extend_trie_from_proof, mpt_from_proof, node_from_digest, parse_proof, proofs_to_tries,
    resolve_nodes, transition_proofs_to_tries, MptNode,
};

/// Ethereum state trie and account storage tries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthereumState {
    pub state_trie: MptNode,
    pub storage_tries: HashMap<B256, MptNode>,
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

        Self { state_trie, storage_tries }
    }

    /// Mutates state based on diffs provided in [`HashedPostState`].
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
                        self.state_trie.delete(hashed_address.as_slice()).unwrap();
                        self.storage_tries.remove(hashed_address);
                        continue;
                    }

                    let state_account = TrieAccount {
                        nonce: account.nonce,
                        balance: account.balance,
                        storage_root,
                        code_hash: account.get_bytecode_hash(),
                    };
                    self.state_trie.insert_rlp(hashed_address.as_slice(), state_account).unwrap();
                }
                None => {
                    self.state_trie.delete(hashed_address.as_slice()).unwrap();
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
                .state_trie
                .get_rlp::<TrieAccount>(hashed_address.as_slice())
                .unwrap()
                .map(|account| account.storage_root)
                .unwrap_or(EMPTY_ROOT_HASH)
        }

        let storage_trie = self.storage_tries.entry(hashed_address).or_default();

        if state_storage.wiped {
            storage_trie.clear();
        }

        for (key, value) in state_storage.storage.iter() {
            let key = key.as_slice();
            if value.is_zero() {
                storage_trie.delete(key).unwrap();
            } else {
                storage_trie.insert_rlp(key, *value).unwrap();
            }
        }

        storage_trie.hash()
    }

    /// Computes the state root.
    pub fn state_root(&self) -> B256 {
        self.state_trie.hash()
    }

    /// The witness form the guest consumes: root hashes plus preorder streams
    /// of raw RLP nodes for the state trie and every storage trie (sorted by
    /// hashed address so the bytes are reproducible).
    pub fn to_witness_state(&self) -> WitnessState {
        let mut storage: Vec<StorageWitness> = self
            .storage_tries
            .iter()
            .map(|(addr, trie)| StorageWitness {
                hashed_address: *addr,
                root: trie.hash(),
                nodes: witness_stream(trie),
            })
            .collect();
        storage.sort_by(|a, b| a.hashed_address.cmp(&b.hashed_address));
        WitnessState {
            state_root: self.state_trie.hash(),
            state_nodes: witness_stream(&self.state_trie),
            storage,
        }
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
            EthereumState { state_trie: MptNode::default(), storage_tries: HashMap::default() };

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
            EthereumState { state_trie: MptNode::default(), storage_tries: HashMap::default() };
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
