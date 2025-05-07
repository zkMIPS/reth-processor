use std::marker::PhantomData;

use alloy_evm::EthEvmFactory;
use alloy_network::Ethereum;
use alloy_provider::Network;
use guest_executor::{
    custom::CustomEvmFactory, IntoInput, IntoPrimitives, ValidateBlockPostExecution,
};
use op_alloy_network::Optimism;
use reth_ethereum_primitives::EthPrimitives;
use reth_evm::ConfigureEvm;
use reth_evm_ethereum::EthEvmConfig;
use reth_optimism_evm::OpEvmConfig;
use reth_optimism_primitives::OpPrimitives;
use reth_primitives_traits::NodePrimitives;
use serde::de::DeserializeOwned;
use zkm_prover::components::DefaultProverComponents;
use zkm_sdk::{Prover, ProverClient};

use crate::ExecutionHooks;

pub trait ExecutorComponents {
    type Prover: Prover<DefaultProverComponents> + 'static;

    type Network: Network;

    type Primitives: NodePrimitives
        + DeserializeOwned
        + IntoPrimitives<Self::Network>
        + IntoInput
        + ValidateBlockPostExecution;

    type EvmConfig: ConfigureEvm<Primitives = Self::Primitives>;

    type Hooks: ExecutionHooks;
}

#[derive(Debug, Default)]
pub struct EthExecutorComponents<H, P = ProverClient> {
    phantom: PhantomData<(H, P)>,
}

impl<H, P> ExecutorComponents for EthExecutorComponents<H, P>
where
    H: ExecutionHooks,
    P: Prover<DefaultProverComponents> + 'static,
{
    type Prover = P;

    type Network = Ethereum;

    type Primitives = EthPrimitives;

    type EvmConfig = EthEvmConfig<CustomEvmFactory<EthEvmFactory>>;

    type Hooks = H;
}

#[derive(Debug, Default)]
pub struct OpExecutorComponents<H, P = ProverClient> {
    phantom: PhantomData<(H, P)>,
}

impl<H, P> ExecutorComponents for OpExecutorComponents<H, P>
where
    H: ExecutionHooks,
    P: Prover<DefaultProverComponents> + 'static,
{
    type Prover = P;

    type Network = Optimism;

    type Primitives = OpPrimitives;

    type EvmConfig = OpEvmConfig;

    type Hooks = H;
}
