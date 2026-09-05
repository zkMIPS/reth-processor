use std::{
    fmt::{Debug, Formatter},
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use crate::{Config, ExecutionHooks, ExecutorComponents, HostExecutor};
use alloy_provider::Provider;
use either::Either;
use eyre::bail;
use guest_executor::io::ClientExecutorInput;
use reth_primitives_traits::NodePrimitives;
use revm_primitives::B256;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use tokio::{task, time::sleep};
use tracing::{info, info_span, warn};
use zkm_prover::components::DefaultProverComponents;
use zkm_sdk::{
    ExecutionReport, Prover, ZKMProofKind, ZKMProvingKey, ZKMPublicValues, ZKMStdin,
    ZKMVerifyingKey,
};

pub type EitherExecutor<C, P> = Either<FullExecutor<C, P>, CachedExecutor<C>>;

static ELF_ID: OnceLock<String> = OnceLock::new();

pub async fn build_executor<C, P>(
    elf: Vec<u8>,
    provider: Option<P>,
    debug_provider: Option<P>,
    evm_config: C::EvmConfig,
    client: Arc<C::Prover>,
    hooks: C::Hooks,
    config: Config,
) -> eyre::Result<EitherExecutor<C, P>>
where
    C: ExecutorComponents,
    P: Provider<C::Network> + Clone + std::fmt::Debug,
{
    if let Some(provider) = provider {
        let debug_provider = debug_provider.unwrap_or(provider.clone());
        return Ok(Either::Left(
            FullExecutor::try_new(provider, debug_provider, elf, evm_config, client, hooks, config)
                .await?,
        ));
    }

    if let Some(cache_dir) = config.cache_dir {
        return Ok(Either::Right(
            CachedExecutor::try_new(
                elf,
                client,
                hooks,
                cache_dir,
                config.chain.id(),
                config.prove_mode,
            )
            .await?,
        ));
    }

    bail!("Either a RPC URL or a cache dir must be provided")
}

pub trait BlockExecutor<C: ExecutorComponents> {
    #[allow(async_fn_in_trait)]
    async fn execute(&self, block_number: u64) -> eyre::Result<()>;

    fn client(&self) -> Arc<C::Prover>;

    fn pk(&self) -> Arc<ZKMProvingKey>;

    fn vk(&self) -> Arc<ZKMVerifyingKey>;

    #[allow(async_fn_in_trait)]
    async fn process_client(
        &self,
        client_input: ClientExecutorInput<C::Primitives>,
        hooks: &C::Hooks,
        prove_mode: Option<ZKMProofKind>,
    ) -> eyre::Result<()> {
        let mut stdin = ZKMStdin::new();
        let buffer = bincode::serialize(&client_input).unwrap();

        stdin.write_vec(buffer);

        // Generate the proof.
        if let Some(prove_mode) = prove_mode {
            info!("Starting proof generation");

            let proving_start = Instant::now();
            hooks.on_proving_start(client_input.current_block.number).await?;
            let client = self.client();
            let pk = self.pk();

            let elf_id = if ELF_ID.get().is_none() {
                ELF_ID.set(hex::encode(Sha256::digest(&pk.elf))).unwrap();
                None
            } else {
                Some(ELF_ID.get().unwrap().clone())
            };
            info!("elf id: {:?}", elf_id);

            let proof_with_cycles = task::spawn_blocking(move || {
                client
                    .prove_with_cycles(&pk, &stdin, prove_mode, elf_id)
                    .map_err(|err| eyre::eyre!("{err}"))
            })
            .await
            .map_err(|err| eyre::eyre!("{err}"))??;

            info!("cycles: {:?}", proof_with_cycles.1);

            let proving_duration = proving_start.elapsed();
            let proof_bytes = bincode::serialize(&proof_with_cycles.0.proof).unwrap();
            let public_values_bytes =
                bincode::serialize(&proof_with_cycles.0.public_values).unwrap();
            // Size census: dump the exact bytes that get submitted so the
            // proof's composition can be measured offline.
            if let Ok(path) = std::env::var("ZIREN_COMPRESS_PROOF_OUT") {
                std::fs::write(&path, &proof_bytes)?;
                info!("wrote {} proof bytes to {path}", proof_bytes.len());
            }

            hooks
                .on_proving_end(
                    client_input.current_block.number,
                    &proof_bytes,
                    &public_values_bytes,
                    &proof_with_cycles.0.zkm_version,
                    self.vk().as_ref(),
                    proof_with_cycles.1,
                    proving_duration,
                )
                .await?;

            info!(
                "Proof for block {} successfully generated! Proving took {:?}",
                client_input.current_block.number, proving_duration
            );
        } else {
            // Execute the block inside the zkVM.
            crate::utils::zkm_dump(&self.pk().elf, &stdin, client_input.current_block.number);

            // Only execute the program.
            let (_, execute_result) =
                execute_client(client_input.current_block.number, self.client(), self.pk(), stdin)
                    .await?;
            let (mut public_values, execution_report) = execute_result?;

            let cycles: u64 = execution_report.cycle_tracker.values().sum();
            info!("total cycles: {:?}", cycles);
            // Every tracked span, including the aggregated
            // `cycle-tracker-report-*` names, which the report's Display omits.
            let mut spans: Vec<_> = execution_report.cycle_tracker.iter().collect();
            spans.sort_by(|a, b| b.1.cmp(a.1));
            for (name, cycles) in spans {
                info!("cycle-tracker {name}: {cycles}");
            }

            // Read the block hash.
            let block_hash = public_values.read::<B256>();
            info!(?block_hash, "Execution successful");

            hooks
                .on_execution_end::<C::Primitives>(&client_input.current_block, &execution_report)
                .await?;
        }

        Ok(())
    }
}

impl<C, P> BlockExecutor<C> for EitherExecutor<C, P>
where
    C: ExecutorComponents,
    P: Provider<C::Network> + Clone + std::fmt::Debug,
{
    async fn execute(&self, block_number: u64) -> eyre::Result<()> {
        match self {
            Either::Left(ref executor) => executor.execute(block_number).await,
            Either::Right(ref executor) => executor.execute(block_number).await,
        }
    }

    fn client(&self) -> Arc<C::Prover> {
        match self {
            Either::Left(ref executor) => executor.client.clone(),
            Either::Right(ref executor) => executor.client.clone(),
        }
    }

    fn pk(&self) -> Arc<ZKMProvingKey> {
        match self {
            Either::Left(ref executor) => executor.pk.clone(),
            Either::Right(ref executor) => executor.pk.clone(),
        }
    }

    fn vk(&self) -> Arc<ZKMVerifyingKey> {
        match self {
            Either::Left(ref executor) => executor.vk.clone(),
            Either::Right(ref executor) => executor.vk.clone(),
        }
    }
}

pub struct FullExecutor<C, P>
where
    C: ExecutorComponents,
    P: Provider<C::Network> + Clone,
{
    provider: P,
    debug_provider: P,
    host_executor: HostExecutor<C::EvmConfig, C::ChainSpec>,
    client: Arc<C::Prover>,
    pk: Arc<ZKMProvingKey>,
    vk: Arc<ZKMVerifyingKey>,
    hooks: C::Hooks,
    config: Config,
}

impl<C, P> FullExecutor<C, P>
where
    C: ExecutorComponents,
    P: Provider<C::Network> + Clone + std::fmt::Debug,
{
    pub async fn try_new(
        provider: P,
        debug_provider: P,
        elf: Vec<u8>,
        evm_config: C::EvmConfig,
        client: Arc<C::Prover>,
        hooks: C::Hooks,
        config: Config,
    ) -> eyre::Result<Self> {
        let cloned_client = client.clone();

        // Setup the proving key and verification key.
        let (pk, vk) = task::spawn_blocking(move || {
            let (pk, vk) = cloned_client.setup(&elf);
            (pk, vk)
        })
        .await?;

        // store vk in the file
        let vk_bytes = bincode::serialize(&vk)?;
        let path = "vk.bin";

        if let Ok(old_bytes) = std::fs::read(path) {
            if old_bytes != vk_bytes {
                std::fs::write(path, &vk_bytes)?;
                info!("{path} updated");
            } else {
                info!("{path} unchanged");
            }
        } else {
            std::fs::write(path, &vk_bytes)?;
            info!("{path} created");
        }

        Ok(Self {
            provider,
            debug_provider,
            host_executor: HostExecutor::new(
                evm_config,
                Arc::new(C::try_into_chain_spec(&config.genesis)?),
            ),
            client,
            pk: Arc::new(pk),
            vk: Arc::new(vk),
            hooks,
            config,
        })
    }

    pub async fn wait_for_block(&self, block_number: u64) -> eyre::Result<()> {
        let block_number = block_number.into();

        while self.provider.get_block_by_number(block_number).await?.is_none() {
            sleep(Duration::from_millis(100)).await;
        }
        Ok(())
    }
}

impl<C, P> BlockExecutor<C> for FullExecutor<C, P>
where
    C: ExecutorComponents,
    P: Provider<C::Network> + Clone + std::fmt::Debug,
{
    async fn execute(&self, block_number: u64) -> eyre::Result<()> {
        self.hooks.on_execution_start(block_number).await?;

        let client_input_from_cache = self.config.cache_dir.as_ref().and_then(|cache_dir| {
            match try_load_input_from_cache::<C::Primitives>(
                cache_dir,
                self.config.chain.id(),
                block_number,
            ) {
                Ok(client_input) => client_input,
                Err(e) => {
                    warn!("Failed to load input from cache: {}", e);
                    None
                }
            }
        });

        let now = Instant::now();
        let client_input = match client_input_from_cache {
            Some(mut client_input_from_cache) => {
                // Override opcode tracking from cache by the setting provided by the user
                client_input_from_cache.opcode_tracking = self.config.opcode_tracking;
                client_input_from_cache
            }
            None => {
                // Execute the host.
                let client_input = self
                    .host_executor
                    .execute(
                        block_number,
                        &self.provider,
                        &self.debug_provider,
                        self.config.genesis.clone(),
                        self.config.custom_beneficiary,
                        self.config.opcode_tracking,
                    )
                    .await?;

                if let Some(ref cache_dir) = self.config.cache_dir {
                    let input_folder = cache_dir.join(format!("input/{}", self.config.chain.id()));
                    if !input_folder.exists() {
                        std::fs::create_dir_all(&input_folder)?;
                    }

                    let input_path = input_folder.join(format!("{block_number}.bin"));
                    let mut cache_file = std::fs::File::create(input_path)?;

                    bincode::serialize_into(&mut cache_file, &client_input)?;
                }

                client_input
            }
        };
        info!("Block {} executed in {:?}", block_number, now.elapsed());

        self.process_client(client_input, &self.hooks, self.config.prove_mode).await?;

        Ok(())
    }

    fn client(&self) -> Arc<C::Prover> {
        self.client.clone()
    }

    fn pk(&self) -> Arc<ZKMProvingKey> {
        self.pk.clone()
    }

    fn vk(&self) -> Arc<ZKMVerifyingKey> {
        self.vk.clone()
    }
}

impl<C, P> Debug for FullExecutor<C, P>
where
    C: ExecutorComponents,
    P: Provider<C::Network> + Clone,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FullExecutor").field("config", &self.config).finish()
    }
}

pub struct CachedExecutor<C>
where
    C: ExecutorComponents,
{
    cache_dir: PathBuf,
    chain_id: u64,
    client: Arc<C::Prover>,
    pk: Arc<ZKMProvingKey>,
    vk: Arc<ZKMVerifyingKey>,
    hooks: C::Hooks,
    prove_mode: Option<ZKMProofKind>,
}

impl<C> CachedExecutor<C>
where
    C: ExecutorComponents,
{
    pub async fn try_new(
        elf: Vec<u8>,
        client: Arc<C::Prover>,
        hooks: C::Hooks,
        cache_dir: PathBuf,
        chain_id: u64,
        prove_mode: Option<ZKMProofKind>,
    ) -> eyre::Result<Self> {
        let cloned_client = client.clone();

        // Setup the proving key and verification key.
        let (pk, vk) = task::spawn_blocking(move || {
            let (pk, vk) = cloned_client.setup(&elf);
            (pk, vk)
        })
        .await?;

        Ok(Self {
            cache_dir,
            chain_id,
            client,
            pk: Arc::new(pk),
            vk: Arc::new(vk),
            hooks,
            prove_mode,
        })
    }
}

impl<C> BlockExecutor<C> for CachedExecutor<C>
where
    C: ExecutorComponents,
{
    async fn execute(&self, block_number: u64) -> eyre::Result<()> {
        let client_input = try_load_input_from_cache::<C::Primitives>(
            &self.cache_dir,
            self.chain_id,
            block_number,
        )?
        .ok_or(eyre::eyre!("No cached input found"))?;

        self.process_client(client_input, &self.hooks, self.prove_mode).await
    }

    fn client(&self) -> Arc<C::Prover> {
        self.client.clone()
    }

    fn pk(&self) -> Arc<ZKMProvingKey> {
        self.pk.clone()
    }

    fn vk(&self) -> Arc<ZKMVerifyingKey> {
        self.vk.clone()
    }
}

impl<C> Debug for CachedExecutor<C>
where
    C: ExecutorComponents,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedExecutor").field("cache_dir", &self.cache_dir).finish()
    }
}

// Block execution in Ziren is a long-running, blocking task, so run it in a separate thread.
async fn execute_client<P: Prover<DefaultProverComponents> + 'static>(
    number: u64,
    client: Arc<P>,
    pk: Arc<ZKMProvingKey>,
    stdin: ZKMStdin,
) -> eyre::Result<(ZKMStdin, eyre::Result<(ZKMPublicValues, ExecutionReport)>)> {
    task::spawn_blocking(move || {
        info_span!("execute_client", number).in_scope(|| {
            let result = client.execute(&pk.elf, &stdin);
            (stdin, result.map_err(|err| eyre::eyre!("{err}")))
        })
    })
    .await
    .map_err(|err| eyre::eyre!("{err}"))
}

fn try_load_input_from_cache<P: NodePrimitives + DeserializeOwned>(
    cache_dir: &Path,
    chain_id: u64,
    block_number: u64,
) -> eyre::Result<Option<ClientExecutorInput<P>>> {
    let cache_path = cache_dir.join(format!("input/{chain_id}/{block_number}.bin"));

    if cache_path.exists() {
        // TODO: prune the cache if invalid instead
        let mut cache_file = std::fs::File::open(cache_path)?;
        let client_input = bincode::deserialize_from(&mut cache_file)?;

        Ok(Some(client_input))
    } else {
        Ok(None)
    }
}
