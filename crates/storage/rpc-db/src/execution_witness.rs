use std::{
    collections::BTreeMap,
    marker::PhantomData,
    sync::{Arc, RwLock},
};

use alloy_consensus::Header;
use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{map::HashMap, Address, B256};
use alloy_provider::{Network, Provider};
use alloy_rlp::{Decodable, Encodable};
use alloy_rpc_types::Header as RpcHeader;
use alloy_rpc_types_debug::ExecutionWitness;
use alloy_trie::{TrieAccount, EMPTY_ROOT_HASH};
use async_trait::async_trait;
use mpt::EthereumState;
use reth_storage_errors::{db::DatabaseError, ProviderError};
use revm_database::{BundleState, DatabaseRef};
use revm_primitives::{keccak256, ruint::aliases::U256, StorageKey, StorageValue, KECCAK_EMPTY};
use revm_state::{AccountInfo, Bytecode};
use serde::Deserialize;

use crate::{RpcDb, RpcDbError};

#[derive(Debug)]
pub struct ExecutionWitnessRpcDb<P, N> {
    /// The provider which fetches data.
    pub provider: P,
    /// The block to fetch missing pre-state proofs from.
    pub state_block_number: u64,
    /// The cached state.
    pub state: Arc<RwLock<EthereumState>>,
    /// The cached bytecodes.
    pub codes: Arc<RwLock<HashMap<B256, Bytecode>>>,

    pub ancestor_headers: BTreeMap<u64, Header>,

    phantom: PhantomData<N>,
}

impl<P: Provider<N> + Clone, N: Network> ExecutionWitnessRpcDb<P, N> {
    /// Create a new [`ExecutionWitnessRpcDb`].
    pub async fn new(provider: P, block_number: u64, state_root: B256) -> Result<Self, RpcDbError> {
        let execution_witness = Self::fetch_witness(&provider, block_number).await?;
        Ok(Self::from_witness(provider, block_number, state_root, execution_witness))
    }

    /// Fetch the execution witness on its own.  It depends only on the block
    /// number, so the host can run it concurrently with the block fetches
    /// and pass the result to [`Self::from_witness`] once the parent's state
    /// root is known — the three RPC round trips were strictly serial before.
    pub async fn fetch_witness(
        provider: &P,
        block_number: u64,
    ) -> Result<ExecutionWitness, RpcDbError> {
        tracing::info!("Fetching execution witness for block {}", block_number);
        let execution_witness = fetch_execution_witness(provider, block_number).await?;
        tracing::info!("Fetched execution witness for block done {}", block_number);
        Ok(execution_witness)
    }

    /// Build the database from an already-fetched witness.
    pub fn from_witness(
        provider: P,
        block_number: u64,
        state_root: B256,
        execution_witness: ExecutionWitness,
    ) -> Self {
        let state = EthereumState::from_execution_witness(&execution_witness, state_root);

        let codes = execution_witness
            .codes
            .iter()
            .map(|encoded| (keccak256(encoded), Bytecode::new_raw(encoded.clone())))
            .collect();

        let ancestor_headers = execution_witness
            .headers
            .iter()
            .map(|encoded| Header::decode(&mut encoded.as_ref()).unwrap())
            .map(|h| (h.number, h))
            .collect();

        let db = Self {
            provider,
            state_block_number: block_number.saturating_sub(1),
            state: Arc::new(RwLock::new(state)),
            codes: Arc::new(RwLock::new(codes)),
            ancestor_headers,
            phantom: PhantomData,
        };

        db
    }

    /// Fetches and merges a missing account proof into the cached pre-state trie.
    async fn fetch_missing_account_proof(&self, address: Address) -> Result<(), RpcDbError> {
        tracing::warn!(
            "Fetching missing account proof for address {} at block {}",
            address,
            self.state_block_number
        );
        let proof = self
            .provider
            .get_proof(address, vec![])
            .number(self.state_block_number)
            .await
            .map_err(|err| RpcDbError::GetProofError(address, err.to_string()))?;

        self.state.write().map_err(|_| RpcDbError::Poisoned)?.extend_from_account_proof(&proof)?;

        Ok(())
    }

    /// Fetches and merges a missing storage proof into the cached pre-state trie.
    async fn fetch_missing_storage_proof(
        &self,
        address: Address,
        index: StorageKey,
    ) -> Result<(), RpcDbError> {
        tracing::warn!(
            "Fetching missing storage proof for address {} slot {} at block {}",
            address,
            B256::from(index),
            self.state_block_number
        );
        let proof = self
            .provider
            .get_proof(address, vec![B256::from(index)])
            .number(self.state_block_number)
            .await
            .map_err(|err| RpcDbError::GetProofError(address, err.to_string()))?;

        self.state.write().map_err(|_| RpcDbError::Poisoned)?.extend_from_account_proof(&proof)?;

        Ok(())
    }

    fn fetch_missing_account_proof_blocking(&self, address: Address) -> Result<(), ProviderError> {
        let handle = tokio::runtime::Handle::try_current().map_err(|_| {
            ProviderError::Database(DatabaseError::Other("no tokio runtime found".to_string()))
        })?;
        tokio::task::block_in_place(|| handle.block_on(self.fetch_missing_account_proof(address)))
            .map_err(|err| ProviderError::Database(DatabaseError::Other(err.to_string())))
    }

    fn fetch_missing_storage_proof_blocking(
        &self,
        address: Address,
        index: StorageKey,
    ) -> Result<(), ProviderError> {
        let handle = tokio::runtime::Handle::try_current().map_err(|_| {
            ProviderError::Database(DatabaseError::Other("no tokio runtime found".to_string()))
        })?;
        tokio::task::block_in_place(|| {
            handle.block_on(self.fetch_missing_storage_proof(address, index))
        })
        .map_err(|err| ProviderError::Database(DatabaseError::Other(err.to_string())))
    }

    async fn fetch_account_code(&self, address: Address) -> Result<Bytecode, RpcDbError> {
        let code = self
            .provider
            .get_code_at(address)
            .number(self.state_block_number)
            .await
            .map_err(|err| RpcDbError::GetCodeError(address, err.to_string()))?;

        Ok(Bytecode::new_raw(code))
    }

    fn fetch_account_code_blocking(
        &self,
        address: Address,
        expected_hash: B256,
    ) -> Result<Bytecode, ProviderError> {
        let handle = tokio::runtime::Handle::try_current().map_err(|_| {
            ProviderError::Database(DatabaseError::Other("no tokio runtime found".to_string()))
        })?;
        let bytecode =
            tokio::task::block_in_place(|| handle.block_on(self.fetch_account_code(address)))
                .map_err(|err| ProviderError::Database(DatabaseError::Other(err.to_string())))?;

        cache_verified_code(&self.codes, address, expected_hash, bytecode)
    }

    fn complete_account_code(
        &self,
        address: Address,
        account: Option<AccountInfo>,
    ) -> Result<Option<AccountInfo>, ProviderError> {
        let Some(mut account) = account else { return Ok(None) };

        if account.code.is_none() && should_fetch_code(account.code_hash) {
            if let Some(code) = cached_code(&self.codes, account.code_hash)? {
                account.code = Some(code);
            } else {
                tracing::warn!(
                    "Code {} not found in execution witness for address {}; fetching fallback code",
                    account.code_hash,
                    address
                );
                account.code = Some(self.fetch_account_code_blocking(address, account.code_hash)?);
            }
        }

        Ok(Some(account))
    }

    fn ensure_empty_storage_trie(&self, hashed_address: B256) -> Result<(), ProviderError> {
        self.state
            .write()
            .map_err(|_| poisoned_provider_error())?
            .storage_tries
            .entry(hashed_address)
            .or_default();
        Ok(())
    }
}

async fn fetch_execution_witness<P, N>(
    provider: &P,
    block_number: u64,
) -> Result<ExecutionWitness, RpcDbError>
where
    P: Provider<N>,
    N: Network,
{
    let witness = provider
        .client()
        .request("debug_executionWitness", (BlockNumberOrTag::Number(block_number),))
        .await?;

    Ok(FlexibleExecutionWitness::into_execution_witness(witness))
}

#[derive(Debug, Deserialize)]
struct FlexibleExecutionWitness {
    state: Vec<alloy_primitives::Bytes>,
    codes: Vec<alloy_primitives::Bytes>,
    #[serde(default)]
    keys: Option<Vec<alloy_primitives::Bytes>>,
    headers: Vec<FlexibleExecutionWitnessHeader>,
}

impl FlexibleExecutionWitness {
    fn into_execution_witness(self) -> ExecutionWitness {
        ExecutionWitness {
            state: self.state,
            codes: self.codes,
            keys: self.keys.unwrap_or_default(),
            headers: self
                .headers
                .into_iter()
                .map(FlexibleExecutionWitnessHeader::into_rlp_bytes)
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum FlexibleExecutionWitnessHeader {
    Rlp(alloy_primitives::Bytes),
    Rpc(RpcHeader<Header>),
}

impl FlexibleExecutionWitnessHeader {
    fn into_rlp_bytes(self) -> alloy_primitives::Bytes {
        match self {
            Self::Rlp(bytes) => bytes,
            Self::Rpc(header) => {
                let mut out = Vec::new();
                header.into_consensus().encode(&mut out);
                out.into()
            }
        }
    }
}

const SYSTEM_ADDRESS: Address =
    alloy_primitives::address!("0xfffffffffffffffffffffffffffffffffffffffe");

#[derive(Debug)]
enum AccountReadError {
    Trie(mpt::Error),
    Provider(ProviderError),
}

impl AccountReadError {
    fn unresolved_node(&self) -> Option<B256> {
        match self {
            Self::Trie(mpt::Error::NodeNotResolved(digest)) => Some(*digest),
            Self::Trie(_) | Self::Provider(_) => None,
        }
    }

    fn into_provider_error(self) -> ProviderError {
        match self {
            Self::Trie(err) => ProviderError::TrieWitnessError(err.to_string()),
            Self::Provider(err) => err,
        }
    }
}

fn read_account_info_from_state(
    state: &EthereumState,
    address_hash: B256,
    codes: &HashMap<B256, Bytecode>,
) -> Result<Option<AccountInfo>, AccountReadError> {
    if let Some(mut bytes) =
        state.state_trie.get(address_hash.as_ref()).map_err(AccountReadError::Trie)?
    {
        let account = TrieAccount::decode(&mut bytes)
            .map_err(ProviderError::from)
            .map_err(AccountReadError::Provider)?;
        let account_info =
            account_info_from_trie_account(codes, account).map_err(AccountReadError::Provider)?;

        Ok(Some(account_info))
    } else {
        Ok(None)
    }
}

fn account_info_from_trie_account(
    codes: &HashMap<B256, Bytecode>,
    account: TrieAccount,
) -> Result<AccountInfo, ProviderError> {
    Ok(AccountInfo {
        balance: account.balance,
        nonce: account.nonce,
        code_hash: account.code_hash,
        code: codes.get(&account.code_hash).cloned(),
    })
}

fn cached_code(
    codes: &RwLock<HashMap<B256, Bytecode>>,
    code_hash: B256,
) -> Result<Option<Bytecode>, ProviderError> {
    Ok(codes.read().map_err(|_| poisoned_provider_error())?.get(&code_hash).cloned())
}

fn cache_verified_code(
    codes: &RwLock<HashMap<B256, Bytecode>>,
    address: Address,
    expected_hash: B256,
    bytecode: Bytecode,
) -> Result<Bytecode, ProviderError> {
    let actual_hash = bytecode.hash_slow();
    if actual_hash != expected_hash {
        return Err(ProviderError::TrieWitnessError(format!(
            "Fetched code hash mismatch for {address}: expected {expected_hash}, got {actual_hash}"
        )))
    }
    codes.write().map_err(|_| poisoned_provider_error())?.insert(expected_hash, bytecode.clone());

    Ok(bytecode)
}

fn should_fetch_code(code_hash: B256) -> bool {
    code_hash != KECCAK_EMPTY && code_hash != B256::ZERO
}

#[derive(Debug)]
enum StorageRead {
    Value(StorageValue),
    MissingEmptyTrie,
}

#[derive(Debug)]
enum StorageReadError {
    Trie(mpt::Error),
    Provider(ProviderError),
    MissingTrie { storage_root: B256 },
}

impl StorageReadError {
    fn unresolved_node(&self) -> Option<B256> {
        match self {
            Self::Trie(mpt::Error::NodeNotResolved(digest)) => Some(*digest),
            Self::Trie(_) | Self::Provider(_) | Self::MissingTrie { .. } => None,
        }
    }

    fn into_provider_error(self) -> ProviderError {
        match self {
            Self::Trie(err) => ProviderError::TrieWitnessError(err.to_string()),
            Self::Provider(err) => err,
            Self::MissingTrie { storage_root } => ProviderError::TrieWitnessError(format!(
                "storage trie not found for root {storage_root}"
            )),
        }
    }
}

fn read_storage_from_state(
    state: &EthereumState,
    hashed_address: B256,
    hashed_slot: B256,
) -> Result<StorageRead, StorageReadError> {
    if let Some(storage_trie) = state.storage_tries.get(&hashed_address) {
        if let Some(mut value) =
            storage_trie.get(hashed_slot.as_slice()).map_err(StorageReadError::Trie)?
        {
            return U256::decode(&mut value)
                .map(StorageRead::Value)
                .map_err(ProviderError::from)
                .map_err(StorageReadError::Provider)
        }

        return Ok(StorageRead::Value(U256::ZERO))
    }

    let storage_root = state
        .state_trie
        .get_rlp::<TrieAccount>(hashed_address.as_slice())
        .map_err(StorageReadError::Trie)?
        .map_or(EMPTY_ROOT_HASH, |account| account.storage_root);

    if storage_root == EMPTY_ROOT_HASH || storage_root == B256::ZERO {
        Ok(StorageRead::MissingEmptyTrie)
    } else {
        Err(StorageReadError::MissingTrie { storage_root })
    }
}

fn poisoned_provider_error() -> ProviderError {
    ProviderError::Database(DatabaseError::Other("poisoned lock".to_string()))
}

impl<P: Provider<N> + Clone, N: Network> DatabaseRef for ExecutionWitnessRpcDb<P, N> {
    type Error = ProviderError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if address == SYSTEM_ADDRESS {
            return Ok(Some(AccountInfo::default()))
        }

        let hash = keccak256(address);
        let account = {
            let state = self.state.read().map_err(|_| poisoned_provider_error())?;
            let codes = self.codes.read().map_err(|_| poisoned_provider_error())?;
            read_account_info_from_state(&state, hash, &codes)
        };

        match account {
            Ok(account) => self.complete_account_code(address, account),
            Err(err) => {
                let Some(digest) = err.unresolved_node() else {
                    return Err(err.into_provider_error())
                };

                tracing::warn!(
                    "Account trie reached unresolved node {} for address {}; fetching fallback proof",
                    digest,
                    address
                );
                self.fetch_missing_account_proof_blocking(address)?;

                let account = {
                    let state = self.state.read().map_err(|_| poisoned_provider_error())?;
                    let codes = self.codes.read().map_err(|_| poisoned_provider_error())?;
                    read_account_info_from_state(&state, hash, &codes)
                        .map_err(AccountReadError::into_provider_error)?
                };
                self.complete_account_code(address, account)
            }
        }
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.codes
            .read()
            .map_err(|_| poisoned_provider_error())?
            .get(&code_hash)
            .ok_or_else(|| {
                ProviderError::TrieWitnessError(format!("Code not found for {code_hash}"))
            })
            .cloned()
    }

    fn storage_ref(
        &self,
        address: Address,
        index: StorageKey,
    ) -> Result<StorageValue, Self::Error> {
        let slot = B256::from(index);
        let hashed_address = keccak256(address);
        let hashed_slot = keccak256(slot);

        let storage = {
            let state = self.state.read().map_err(|_| poisoned_provider_error())?;
            read_storage_from_state(&state, hashed_address, hashed_slot)
        };

        match storage {
            Ok(StorageRead::Value(value)) => Ok(value),
            Ok(StorageRead::MissingEmptyTrie) => {
                self.ensure_empty_storage_trie(hashed_address)?;
                Ok(U256::ZERO)
            }
            Err(err) => {
                if let Some(digest) = err.unresolved_node() {
                    tracing::warn!(
                        "Storage trie reached unresolved node {} for address {} slot {}; fetching fallback proof",
                        digest,
                        address,
                        slot
                    );
                } else if let StorageReadError::MissingTrie { storage_root } = err {
                    tracing::warn!(
                        "Storage trie with root {} is missing for address {} slot {}; fetching fallback proof",
                        storage_root,
                        address,
                        slot
                    );
                } else {
                    return Err(err.into_provider_error())
                }

                self.fetch_missing_storage_proof_blocking(address, index)?;

                let state = self.state.read().map_err(|_| poisoned_provider_error())?;
                match read_storage_from_state(&state, hashed_address, hashed_slot)
                    .map_err(StorageReadError::into_provider_error)?
                {
                    StorageRead::Value(value) => Ok(value),
                    StorageRead::MissingEmptyTrie => {
                        drop(state);
                        self.ensure_empty_storage_trie(hashed_address)?;
                        Ok(U256::ZERO)
                    }
                }
            }
        }
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        let header = self.ancestor_headers.get(&number).ok_or_else(|| {
            ProviderError::TrieWitnessError(format!("Header {number} not found in the ancestors"))
        })?;

        Ok(header.hash_slow())
    }
}

#[async_trait]
impl<P, N> RpcDb<N> for ExecutionWitnessRpcDb<P, N>
where
    P: Provider<N> + Clone,
    N: Network,
{
    async fn state(&self, _bundle_state: &BundleState) -> Result<EthereumState, RpcDbError> {
        Ok(self.state.read().map_err(|_| RpcDbError::Poisoned)?.clone())
    }

    fn bytecodes(&self) -> Vec<Bytecode> {
        self.codes.read().expect("codes lock poisoned").values().cloned().collect()
    }

    async fn ancestor_headers(&self) -> Result<Vec<Header>, RpcDbError> {
        Ok(self.ancestor_headers.values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use alloy_consensus::Header;
    use alloy_primitives::hex::FromHex;
    use alloy_rlp::Decodable;

    use super::*;

    #[test]
    fn execution_witness_accepts_rpc_header_objects_and_null_keys() {
        let json = r#"{
            "headers": [{
                "parentHash": "0xddcb9640c370c7914ccf303924421b257f05a676fc8d3c9c33ef8476194d98bd",
                "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                "miner": "0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97",
                "stateRoot": "0x043ef1fafb089e28e171f777d22845c2bdbf89e6b767857b02dcf9308de92b5c",
                "transactionsRoot": "0x751ee8f2d2893940e2b8287a72fb451ca382e5e515e8de266686e057f8cb41a7",
                "receiptsRoot": "0xc0bf6c67ff3ab702758b903204bf3f054ce68ca48dc55f8fd40e5e912b34f782",
                "logsBloom": "0xdc7d77b6e8cfcb93b6be74bdc368dba1dfecc4fdef2447324c1d84facd5cdeb2fd5e0196e6fdd5bdff93e3f9ea46adcf76bf89f8bf0e6141b5de26c0bbbf14f7cdbeb0abfedaebf95b7e7a48a5e877fd5c7ef11fb8cc9baa83445c55b8e5ffc8dee2fb19ab7e61dbcc1b9357fe0aecee5e1f7769d396fed9fef5c455bf2fff4de072397a939a5768bd69a73b3587832ab8b3c7ef653dc1de147b3973fbbb8fbfcf157d67a4d5ee5c7df5cd87dcc017a8ffd58b4d9f4c71d85dee3b2e6a1f69ffdfa75f0ef9e83edbbfe32ab7d274eedbd8cc71ff8f7e689bede5331bb0626bd6f4dde9cac72714b43eefb36df28baee2ffe36e2967fd02e2573ef7995503e7cf",
                "difficulty": "0x0",
                "number": "0x17e8a77",
                "gasLimit": "0x3938700",
                "gasUsed": "0x19aacd0",
                "timestamp": "0x6a017d13",
                "extraData": "0x546974616e2028746974616e6275696c6465722e78797a29",
                "mixHash": "0xd0d37c7118b2221b8ec1c4940be1689108309c9837a0359d41be16acdc7e546e",
                "nonce": "0x0000000000000000",
                "baseFeePerGas": "0x115394a1",
                "withdrawalsRoot": "0x978b9471e9087c6f967aaa08f757abd7280dbb7aa3310320cdd4d3fb4ecb9e5e",
                "blobGasUsed": "0x0",
                "excessBlobGas": "0xb503bd8",
                "parentBeaconBlockRoot": "0xc2b892804ed1f1f3cfeefbbc0fffd0e298bab43a7773409154a0e6ea306b794a",
                "requestsHash": "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "slotNumber": null,
                "hash": "0x190299f2eee1493723cc749ff9148663c5202f9b3479ed0da8d99ba62f882c23"
            }],
            "codes": ["0x6000"],
            "state": ["0x80"],
            "keys": null
        }"#;

        let witness = serde_json::from_str::<FlexibleExecutionWitness>(json)
            .unwrap()
            .into_execution_witness();
        let header = Header::decode(&mut witness.headers[0].as_ref()).unwrap();

        assert_eq!(header.number, 25_070_199);
        assert_eq!(witness.codes.len(), 1);
        assert_eq!(witness.state.len(), 1);
        assert!(witness.keys.is_empty());
    }

    #[test]
    fn execution_witness_preserves_rlp_header_bytes_and_keys() {
        let json = r#"{
            "headers": ["0x010203"],
            "codes": [],
            "state": [],
            "keys": ["0x04"]
        }"#;

        let witness = serde_json::from_str::<FlexibleExecutionWitness>(json)
            .unwrap()
            .into_execution_witness();

        assert_eq!(witness.headers[0].as_ref(), Vec::<u8>::from_hex("010203").unwrap());
        assert_eq!(witness.keys[0].as_ref(), Vec::<u8>::from_hex("04").unwrap());
    }
}
