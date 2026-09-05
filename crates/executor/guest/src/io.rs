use std::{cell::RefCell, collections::HashSet, iter::once};

use alloy_consensus::{Block, BlockHeader, Header};
use alloy_primitives::map::HashMap;
use itertools::Itertools;
use mpt::EthereumState;
use primitives::genesis::Genesis;
use reth_errors::ProviderError;
use reth_ethereum_primitives::EthPrimitives;
use reth_primitives_traits::{NodePrimitives, SealedHeader};
use reth_trie::{TrieAccount, EMPTY_ROOT_HASH};
use revm::{
    state::{AccountInfo, Bytecode},
    DatabaseRef,
};
use revm_primitives::{keccak256, Address, B256, U256};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::error::ClientError;

pub type EthClientExecutorInput = ClientExecutorInput<EthPrimitives>;

#[cfg(feature = "optimism")]
pub type OpClientExecutorInput = ClientExecutorInput<reth_optimism_primitives::OpPrimitives>;

/// The input for the client to execute a block and fully verify the STF (state transition
/// function).
///
/// Instead of passing in the entire state, we only pass in the state roots along with merkle proofs
/// for the storage slots that were modified and accessed.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientExecutorInput<P: NodePrimitives> {
    /// The current block (which will be executed inside the client).
    #[serde_as(
        as = "reth_primitives_traits::serde_bincode_compat::Block<'_, P::SignedTx, Header>"
    )]
    pub current_block: Block<P::SignedTx>,
    /// The previous block headers starting from the most recent. There must be at least one header
    /// to provide the parent state root.
    #[serde_as(as = "Vec<alloy_consensus::serde_bincode_compat::Header>")]
    pub ancestor_headers: Vec<Header>,
    /// Network state as of the parent block.
    pub parent_state: EthereumState,
    /// Account bytecodes.
    pub bytecodes: Vec<Bytecode>,
    /// `keccak256(code)` of each entry of `bytecodes`, so the guest can index
    /// them by hash without hashing every contract up front; a bytecode's hash
    /// is checked the first time the EVM loads it (unexecuted code is never
    /// hashed).  Empty (old inputs) means: hash everything eagerly.
    #[serde(default)]
    pub code_hashes: Vec<B256>,
    /// The genesis block, as a json string.
    pub genesis: Genesis,
    /// The genesis block, as a json string.
    pub custom_beneficiary: Option<Address>,
    /// Whether to track the cycle count of opcodes.
    pub opcode_tracking: bool,
}

impl<P: NodePrimitives> ClientExecutorInput<P> {
    /// Gets the immediate parent block's header.
    #[inline(always)]
    pub fn parent_header(&self) -> &Header {
        self.ancestor_headers.last().unwrap()
    }

    /// Creates a [`TrieDB`] over `state` (the parent state, taken out of the
    /// input so the executor can update it after the block ran).
    pub fn witness_db<'a>(
        &'a self,
        state: &'a RefCell<EthereumState>,
        sealed_headers: &[SealedHeader],
    ) -> Result<TrieDB<'a>, ClientError> {
        <Self as WitnessInput>::witness_db(self, state, sealed_headers)
    }
}

impl<P: NodePrimitives> WitnessInput for ClientExecutorInput<P> {
    #[inline(always)]
    fn state(&self) -> &EthereumState {
        &self.parent_state
    }

    #[inline(always)]
    fn state_anchor(&self) -> B256 {
        self.parent_header().state_root()
    }

    #[inline(always)]
    fn bytecodes(&self) -> impl Iterator<Item = &Bytecode> {
        self.bytecodes.iter()
    }

    #[inline(always)]
    fn code_hashes(&self) -> &[B256] {
        &self.code_hashes
    }

    #[inline(always)]
    fn sealed_headers(&self) -> impl Iterator<Item = SealedHeader> {
        self.ancestor_headers
            .iter()
            .map(|h| SealedHeader::seal_slow(h.clone()))
            .chain(once(SealedHeader::seal_slow(self.current_block.header.clone())))
    }
}

#[derive(Debug)]
pub struct TrieDB<'a> {
    /// The parent state.  Reads resolve witness nodes lazily (decoding and
    /// hash-checking only the paths the block touches), which mutates the
    /// trie behind `DatabaseRef`'s `&self` — hence the cell.
    inner: &'a RefCell<EthereumState>,
    block_hashes: HashMap<u64, B256>,
    /// Bytecodes by their CLAIMED hash; `verified_code` records which claims
    /// have been checked (`hash_slow` on first load).
    bytecode_by_hash: HashMap<B256, &'a Bytecode>,
    verified_code: RefCell<HashSet<B256>>,
}

impl<'a> TrieDB<'a> {
    pub fn new(
        inner: &'a RefCell<EthereumState>,
        block_hashes: HashMap<u64, B256>,
        bytecode_by_hash: HashMap<B256, &'a Bytecode>,
    ) -> Self {
        Self { inner, block_hashes, bytecode_by_hash, verified_code: RefCell::new(HashSet::new()) }
    }
}

/// The system address used for system calls.
const SYSTEM_ADDRESS: Address =
    alloy_primitives::address!("0xfffffffffffffffffffffffffffffffffffffffe");

impl DatabaseRef for TrieDB<'_> {
    /// The database error type.
    type Error = ProviderError;

    /// Get basic account information.
    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if address == SYSTEM_ADDRESS {
            return Ok(Some(AccountInfo::default()))
        }

        let hashed_address = keccak256(address);

        let account_in_trie = self.inner.borrow_mut().account(&hashed_address).unwrap();

        let account = account_in_trie.map(|account_in_trie| AccountInfo {
            balance: account_in_trie.balance,
            nonce: account_in_trie.nonce,
            code_hash: account_in_trie.code_hash,
            code: None,
        });

        Ok(account)
    }

    /// Get account code by its hash.
    fn code_by_hash_ref(&self, hash: B256) -> Result<Bytecode, Self::Error> {
        let code = *self.bytecode_by_hash.get(&hash).expect("bytecode for hash must be provided");
        // The claimed hash is trusted only once it has been checked; a
        // contract that never executes is never hashed.
        if !self.verified_code.borrow().contains(&hash) {
            assert_eq!(code.hash_slow(), hash, "bytecode does not match its claimed hash");
            self.verified_code.borrow_mut().insert(hash);
        }
        Ok(code.clone())
    }

    /// Get storage value of address at index.
    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let hashed_address = keccak256(address);
        let hashed_slot = keccak256(index.to_be_bytes::<32>());

        Ok(self
            .inner
            .borrow_mut()
            .storage::<U256>(&hashed_address, hashed_slot.as_slice())
            .expect("Can get from MPT")
            .unwrap_or_default())
    }

    /// Get block hash by block number.
    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        Ok(*self
            .block_hashes
            .get(&number)
            .expect("A block hash must be provided for each block number"))
    }
}

/// A trait for constructing [`WitnessDb`].
pub trait WitnessInput {
    /// Gets a reference to the state from which account info and storage slots are loaded.
    fn state(&self) -> &EthereumState;

    /// Gets the state trie root hash that the state referenced by
    /// [state()](trait.WitnessInput#tymethod.state) must conform to.
    fn state_anchor(&self) -> B256;

    /// Gets an iterator over account bytecodes.
    fn bytecodes(&self) -> impl Iterator<Item = &Bytecode>;

    /// The claimed `keccak256` of each bytecode (empty: hash eagerly).
    fn code_hashes(&self) -> &[B256];

    /// Gets an iterator over references to a consecutive, reverse-chronological block headers
    /// starting from the current block header.
    fn sealed_headers(&self) -> impl Iterator<Item = SealedHeader>;

    /// Creates a [`WitnessDb`] from a [`WitnessInput`] implementation. To do so, it verifies the
    /// state root, ancestor headers and account bytecodes, and constructs the account and
    /// storage values by reading against state tries.
    ///
    /// NOTE: For some unknown reasons, calling this trait method directly from outside of the type
    /// implementing this trait causes a zkVM run to cost over 5M cycles more. To avoid this, define
    /// a method inside the type that calls this trait method instead.
    #[inline(always)]
    fn witness_db<'a>(
        &'a self,
        state: &'a RefCell<EthereumState>,
        sealed_headers: &[SealedHeader],
    ) -> Result<TrieDB<'a>, ClientError> {
        // The parent state root anchors everything: in the lazy form the root
        // is a bare digest and every node is hash-checked when it is reached,
        // so the per-storage-trie root check of the eager form is subsumed.
        // Eager (fully materialised) states are still checked as before.
        {
            let st = state.borrow();
            if self.state_anchor() != st.state_root() {
                return Err(ClientError::MismatchedStateRoot);
            }
            if st.nodes.is_empty() {
                for (hashed_address, storage_trie) in st.storage_tries.iter() {
                    let account =
                        st.state_trie.get_rlp::<TrieAccount>(hashed_address.as_slice()).unwrap();
                    let storage_root = account.map_or(EMPTY_ROOT_HASH, |a| a.storage_root);
                    if storage_root != storage_trie.hash() {
                        return Err(ClientError::MismatchedStorageRoot);
                    }
                }
            }
        }

        let claimed = self.code_hashes();
        let bytecodes_by_hash = if claimed.is_empty() {
            self.bytecodes().map(|code| (code.hash_slow(), code)).collect::<HashMap<_, _>>()
        } else {
            claimed.iter().copied().zip(self.bytecodes()).collect::<HashMap<_, _>>()
        };

        // Verify and build block hashes
        let mut block_hashes: HashMap<u64, B256> = HashMap::with_hasher(Default::default());
        for (parent_header, child_header) in sealed_headers.iter().tuple_windows() {
            if parent_header.number() != child_header.number() - 1 {
                return Err(ClientError::InvalidHeaderBlockNumber(
                    parent_header.number() + 1,
                    child_header.number(),
                ));
            }

            let parent_header_hash = parent_header.hash_slow();
            if parent_header_hash != child_header.parent_hash() {
                return Err(ClientError::InvalidHeaderParentHash(
                    parent_header_hash,
                    child_header.parent_hash(),
                ));
            }

            block_hashes.insert(parent_header.number(), child_header.parent_hash());
        }

        Ok(TrieDB::new(state, block_hashes, bytecodes_by_hash))
    }
}
