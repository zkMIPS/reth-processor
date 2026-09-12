use std::{env, sync::Arc};

use alloy_provider::{Provider, ProviderBuilder, WsConnect};
use clap::Parser;
use cli::Args;
use eth_proofs::EthProofsClient;
use futures::{channel::mpsc, future::ready, FutureExt, SinkExt, StreamExt};
use host_executor::{
    alerting::AlertingClient, create_eth_block_execution_strategy_factory, EthExecutorComponents,
    FullExecutor,
};
use provider::create_provider;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use zkm_sdk::{include_elf, ProverClient};

mod cli;

mod eth_proofs;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    // Initialize the environment variables.
    dotenv::dotenv().ok();

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    // Initialize the logger.
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::from_default_env()
                .add_directive("zkm_core_machine=warn".parse().unwrap())
                .add_directive("zkm_core_executor=warn".parse().unwrap())
                .add_directive("zkm_prover=warn".parse().unwrap())
                .add_directive("zkm_sdk=info".parse().unwrap()),
        )
        .init();

    // Parse the command line arguments.
    let args = Args::parse();
    let config = args.as_config().await?;

    let elf = include_elf!("reth").to_vec();
    let block_execution_strategy_factory =
        create_eth_block_execution_strategy_factory(&config.genesis, None);

    let eth_proofs_client = EthProofsClient::new(
        args.eth_proofs_cluster_id,
        args.eth_proofs_endpoint,
        args.eth_proofs_api_token,
    );
    let alerting_client = args.pager_duty_integration_key.map(AlertingClient::new);

    let ws = WsConnect::new(args.ws_rpc_url);
    #[allow(deprecated)]
    let ws_provider = ProviderBuilder::new().on_ws(ws).await?;
    let http_provider = create_provider(args.http_rpc_url);
    let debug_http_provider = create_provider(args.debug_http_rpc_url);

    // Subscribe to block headers.
    let subscription = ws_provider.subscribe_blocks().await?;
    let block_interval = args.block_interval;
    let block_residue = args.block_residue % block_interval.max(1);
    let mut stream = subscription
        .into_stream()
        .filter(move |h| ready(h.number % block_interval == block_residue));

    // let mut builder = ProverClient::builder().cuda();
    if let Some(_endpoint) = &args.moongate_endpoint {
        //     builder = builder.with_moongate_endpoint(endpoint)
    }

    let client = Arc::new(ProverClient::new());

    let executor = FullExecutor::<EthExecutorComponents<_, _>, _>::try_new(
        http_provider.clone(),
        debug_http_provider.clone(),
        elf,
        block_execution_strategy_factory,
        client,
        eth_proofs_client,
        config,
    )
    .await?;

    info!("Latest block number: {}", http_provider.get_block_number().await?);

    // Two-stage pipeline.  The fetcher pulls headers off the subscription,
    // fetches the block + witness and runs the native execution; the prover
    // loop below consumes the prepared inputs one at a time.  Block N+1's
    // fetch therefore overlaps block N's proof instead of leaving the cards
    // idle for the RPC round trips.
    let executor = Arc::new(executor);
    let alerting_client = Arc::new(alerting_client);
    let (mut tx, mut rx) = mpsc::channel(args.prefetch_depth.max(1));
    let fetcher = {
        let executor = executor.clone();
        let alerting_client = alerting_client.clone();
        let max_lag = args.max_lag;
        tokio::spawn(async move {
            // The subscription is only a wake-up: it says how far the chain
            // is.  Which block to prepare next is a cursor that advances by
            // `block_interval`, so falling behind never skips a block — the
            // backlog is worked through in order (unless `max_lag` says to
            // drop it).  A header stream that lags drops headers; the cursor
            // does not.
            let mut head = 0u64;
            let mut next = 0u64;
            loop {
                if next == 0 || next > head {
                    match stream.next().await {
                        Some(header) => {
                            head = head.max(header.number);
                            if next == 0 {
                                // The stream only delivers this instance's
                                // residue class, so the cursor starts aligned.
                                next = header.number;
                            }
                            continue;
                        }
                        None => break,
                    }
                }
                // Absorb whatever headers are already queued so `head` is fresh.
                while let Some(Some(header)) = stream.next().now_or_never() {
                    head = head.max(header.number);
                }

                let number = next;
                next += block_interval;
                if max_lag > 0 && head - number > max_lag {
                    warn!("skipping block {number}: {} behind the newest header", head - number);
                    continue;
                }

                // Wait for the block to be avaliable in the HTTP provider
                let prepared = match executor.wait_for_block(number).await {
                    Ok(()) => executor.prepare(number).await,
                    Err(err) => Err(err),
                };
                match prepared {
                    Ok(client_input) => {
                        if tx.send((number, client_input)).await.is_err() {
                            break;
                        }
                    }
                    Err(err) => {
                        report_error(&alerting_client, number, err).await;
                    }
                }
            }
        })
    };

    // Prove one block ahead of the one being awaited.  The prover serialises
    // the work itself (one job at a time, on its own mutex), so the second
    // request only overlaps what happens BEFORE proving: shipping a 13 MB
    // client input over the wire and deserialising it, ~0.35 s per block that
    // the cards would otherwise spend idle between blocks.
    let mut inflight: Option<(u64, tokio::task::JoinHandle<eyre::Result<()>>)> = None;
    while let Some((number, client_input)) = rx.next().await {
        let executor = executor.clone();
        let next = tokio::spawn(async move { executor.prove_prepared(client_input).await });
        if let Some((prev_number, prev)) = inflight.replace((number, next)) {
            match prev.await {
                Ok(Err(err)) => report_error(&alerting_client, prev_number, err).await,
                Err(err) => {
                    report_error(&alerting_client, prev_number, eyre::eyre!("prove task: {err}"))
                        .await
                }
                Ok(Ok(())) => {}
            }
        }
    }
    if let Some((number, last)) = inflight {
        match last.await {
            Ok(Err(err)) => report_error(&alerting_client, number, err).await,
            Err(err) => report_error(&alerting_client, number, eyre::eyre!("prove task: {err}")).await,
            Ok(Ok(())) => {}
        }
    }
    fetcher.await?;

    Ok(())
}

async fn report_error(alerting_client: &Option<AlertingClient>, number: u64, err: eyre::Report) {
    let error_message = format!("Error handling block {number}: {err}");
    error!(error_message);

    if let Some(alerting_client) = alerting_client {
        alerting_client.send_alert(error_message).await;
    }
}
