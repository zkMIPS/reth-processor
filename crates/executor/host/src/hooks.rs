use std::{future::Future, time::Duration};

use alloy_consensus::Block;
use reth_primitives_traits::NodePrimitives;
use zkm_sdk::{ExecutionReport, ZKMVerifyingKey};

pub trait ExecutionHooks: Send {
    fn on_execution_start(
        &self,
        _block_number: u64,
    ) -> impl Future<Output = eyre::Result<()>> + Send {
        async { Ok(()) }
    }

    fn on_execution_end<P: NodePrimitives>(
        &self,
        _executed_block: &Block<P::SignedTx>,
        _execution_report: &ExecutionReport,
    ) -> impl Future<Output = eyre::Result<()>> {
        async { Ok(()) }
    }

    fn on_proving_start(&self, _block_number: u64) -> impl Future<Output = eyre::Result<()>> {
        async { Ok(()) }
    }

    fn on_proving_end(
        &self,
        _block_number: u64,
        _proof_bytes: &[u8],
        _public_values_bytes: &[u8],
        _zkm_version: &str,
        _vk: &ZKMVerifyingKey,
        _execution_report: &ExecutionReport,
        _proving_duration: Duration,
    ) -> impl Future<Output = eyre::Result<()>> {
        async { Ok(()) }
    }
}

impl ExecutionHooks for () {}
