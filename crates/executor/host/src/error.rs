use alloy_rpc_types::ConversionError;
use alloy_transport::{RpcError, TransportError, TransportErrorKind};
use mpt::FromProofError;
use reth_errors::BlockExecutionError;
use revm_primitives::B256;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to parse blocks into executor friendly format {}", .0)]
    ParseError(#[from] ConversionError),
    #[error("Transport Error: {}", .0)]
    Transport(#[from] TransportError),
    #[error("Failed to recover senders from RPC block data")]
    FailedToRecoverSenders,
    #[error("Failed to validate post execution state")]
    PostExecutionCheck(#[from] reth_errors::ConsensusError),
    #[error("Local Execution Failed {}", .0)]
    ExecutionFailed(#[from] BlockExecutionError),
    #[error("Failed to construct a valid state trie from RPC data {}", .0)]
    FromProof(#[from] FromProofError),
    #[error("RPC didnt have expected block height {}", .0)]
    ExpectedBlock(u64),
    #[error("Header Mismatch \n found {} expected {}", .0, .1)]
    HeaderMismatch(B256, B256),
    #[error("State root mismatch after local execution \n found {} expected {}", .0, .1)]
    StateRootMismatch(B256, B256),
    #[error("Failed to read the genesis file: {}", .0)]
    FailedToReadGenesisFile(#[from] std::io::Error),
    #[error("custom error: {0}")]
    Custom(String),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SpawnedTaskError {
    #[error("rpc error: {0}")]
    Rpc(#[from] RpcError<TransportErrorKind>),

    #[error("proof conversion error: {0}")]
    Proof(#[from] FromProofError),
}
