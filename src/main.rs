mod alert;
mod config;
mod flow;
mod mitigation;
mod processor;
mod prometheus;
mod ring_buffer;
mod utils;

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use fxhash::FxHashMap;
use tokio::sync::{Mutex, RwLock, mpsc};
use tracing::{error, info, warn};

use crate::alert::AlertManager;
use crate::config::Config;
use crate::flow::FlowRecord;
use crate::processor::{SharedProcessor, new_shared_processor};
use crate::prometheus::SharedSnapshots;
use crate::utils::current_timestamp;

#[derive(Parser, Debug)]
#[command(name = "netalert")]
#[command(about = "NetFlow/sFlow traffic alerting daemon")]
struct Args {
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,

    #[arg(long, default_value = "2055")]
    netflow_port: u16,

    #[arg(long, default_value = "6343")]
    sflow_port: u16,

    #[arg(long, default_value = "0.0.0.0")]
    bind_addr: String,

    #[arg(long, default_value = "info")]
    log_level: String,

    #[arg(long, default_value = "0.0.0.0:9090")]
    metrics_addr: String,
}

type SharedAlertManager = Arc<Mutex<AlertManager>>;
type ExporterRates = Arc<RwLock<FxHashMap<IpAddr, u32>>>;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log_level));

    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    info!("Starting NetAlert daemon");
    info!("Config file: {:?}", args.config);

    let config = Config::load(&args.config)
        .with_context(|| format!("Failed to load config from {:?}", args.config))?;

    info!("Loaded {} rules", config.rules.len());
    for (idx, rule) in config.rules.iter().enumerate() {
        info!(
            "  Rule {}: prefix={}, thresholds={}",
            idx,
            rule.prefix,
            rule.thresholds.len()
        );
    }

    let evaluation_interval = config.global.evaluation_interval;
    let window_secs = config.global.window.as_secs() as usize;

    // Build exporter sampling rates map
    let exporter_rates: ExporterRates = Arc::new(RwLock::new(config.exporter_sampling_rates()));

    // Build alert manager
    let alert_manager: SharedAlertManager = Arc::new(Mutex::new(AlertManager::new(
        config.global.alert_script.as_ref().map(PathBuf::from),
    )));

    let shared_processor = new_shared_processor(window_secs);
    let shared_snapshots: SharedSnapshots = prometheus::new_shared_snapshots();

    // Start Prometheus metrics endpoint
    prometheus::spawn(args.metrics_addr.clone(), shared_snapshots.clone());

    // Initialize processor and alert manager from config
    shared_processor.write().await.reload_config(&config)?;
    alert_manager.lock().await.reload_config(&config);

    let (flow_tx, flow_rx) = mpsc::channel::<FlowRecord>(10000);

    let netflow_addr = format!("{}:{}", args.bind_addr, args.netflow_port);
    let sflow_addr = format!("{}:{}", args.bind_addr, args.sflow_port);

    let flow_tx_netflow = flow_tx.clone();
    let rates_netflow = exporter_rates.clone();
    let _netflow_handle = tokio::spawn(async move {
        if let Err(e) = run_netflow_receiver(&netflow_addr, flow_tx_netflow, rates_netflow).await {
            error!("NetFlow receiver error: {}", e);
        }
    });

    let flow_tx_sflow = flow_tx.clone();
    let rates_sflow = exporter_rates.clone();
    let _sflow_handle = tokio::spawn(async move {
        if let Err(e) = run_sflow_receiver(&sflow_addr, flow_tx_sflow, rates_sflow).await {
            error!("sFlow receiver error: {}", e);
        }
    });

    let processor_clone = shared_processor.clone();
    let _processor_handle = tokio::spawn(async move {
        run_flow_processor(flow_rx, processor_clone).await;
    });

    let processor_for_ticker = shared_processor.clone();
    let alert_for_ticker = alert_manager.clone();
    let snapshots_for_ticker = shared_snapshots.clone();
    let _ticker_handle = tokio::spawn(async move {
        run_ticker(
            processor_for_ticker,
            alert_for_ticker,
            snapshots_for_ticker,
            evaluation_interval,
        )
        .await;
    });

    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sighup = signal(SignalKind::hangup())?;
        let mut sigterm = signal(SignalKind::terminate())?;
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                _ = sigterm.recv() => break,
                _ = sighup.recv() => {
                    info!("SIGHUP received, reloading config...");
                    reload_config(
                        &args.config,
                        &shared_processor,
                        &alert_manager,
                        &exporter_rates,
                    ).await;
                }
            }
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;

    info!("Shutting down...");

    Ok(())
}

async fn reload_config(
    config_path: &PathBuf,
    shared_processor: &SharedProcessor,
    shared_alert_manager: &SharedAlertManager,
    exporter_rates: &ExporterRates,
) {
    match Config::load(config_path) {
        Ok(new_config) => {
            {
                let mut rates = exporter_rates.write().await;
                *rates = new_config.exporter_sampling_rates();
            }
            {
                let mut processor = shared_processor.write().await;
                if let Err(e) = processor.reload_config(&new_config) {
                    error!("Failed to reload processor config: {}", e);
                    return;
                }
            }
            {
                let mut am = shared_alert_manager.lock().await;
                am.reload_config(&new_config);
            }
            info!("Config reloaded successfully");
        }
        Err(e) => {
            error!("Failed to parse updated config: {}", e);
        }
    }
}

enum AnyFlowReader {
    Netflow(rustflow::tokio::NetflowReader),
    Sflow(rustflow::tokio::SflowReader),
}

impl AnyFlowReader {
    async fn read(&mut self) -> anyhow::Result<rustflow::CommonFlow> {
        match self {
            Self::Netflow(r) => Ok(r.read().await?),
            Self::Sflow(r) => Ok(r.read().await?),
        }
    }
}

async fn run_netflow_receiver(
    bind_addr: &str,
    tx: mpsc::Sender<FlowRecord>,
    exporter_rates: ExporterRates,
) -> Result<()> {
    info!("Starting NetFlow/IPFIX listener on {}", bind_addr);
    let reader = rustflow::tokio::NetflowReader::bind(bind_addr).await?;
    run_receiver_loop(
        "NetFlow",
        AnyFlowReader::Netflow(reader),
        tx,
        exporter_rates,
    )
    .await
}

async fn run_sflow_receiver(
    bind_addr: &str,
    tx: mpsc::Sender<FlowRecord>,
    exporter_rates: ExporterRates,
) -> Result<()> {
    info!("Starting sFlow listener on {}", bind_addr);
    let reader = rustflow::tokio::SflowReader::bind(bind_addr).await?;
    run_receiver_loop("sFlow", AnyFlowReader::Sflow(reader), tx, exporter_rates).await
}

async fn run_receiver_loop(
    name: &str,
    mut reader: AnyFlowReader,
    tx: mpsc::Sender<FlowRecord>,
    exporter_rates: ExporterRates,
) -> Result<()> {
    loop {
        match reader.read().await {
            Ok(common_flow) => {
                let mut flow = FlowRecord::from_common_flow(&common_flow);

                // Override sampling rate from exporter config if available
                if let Some(src_addr) = common_flow.sampler_address {
                    let rates = exporter_rates.read().await;
                    if let Some(&rate) = rates.get(&src_addr) {
                        flow.sampling_rate = rate;
                    }
                }

                if tx.send(flow).await.is_err() {
                    warn!("Flow channel closed");
                    return Ok(());
                }
            }
            Err(e) => {
                warn!("{} receive error: {}", name, e);
            }
        }
    }
}

async fn run_flow_processor(mut rx: mpsc::Receiver<FlowRecord>, processor: SharedProcessor) {
    info!("Flow processor started");

    while let Some(flow) = rx.recv().await {
        let mut proc = processor.write().await;
        proc.process_flow(&flow);
    }

    info!("Flow processor stopped");
}

async fn run_ticker(
    processor: SharedProcessor,
    alert_manager: SharedAlertManager,
    shared_snapshots: SharedSnapshots,
    evaluation_interval: std::time::Duration,
) {
    info!(
        "Ticker started ({}s interval)",
        evaluation_interval.as_secs()
    );

    let mut interval = tokio::time::interval(evaluation_interval);

    loop {
        interval.tick().await;

        let current_time = current_timestamp();
        let eval_start = std::time::Instant::now();

        // Compute rates and evaluate alerts together under write lock
        // (alert evaluation needs mutable access to drain capture buffers)
        let snapshots = {
            let mut proc = processor.write().await;
            let snapshots = proc.compute_all_rates(current_time);
            {
                let mut am = alert_manager.lock().await;
                am.evaluate(&snapshots, &mut proc).await;
            }
            snapshots
        };

        let elapsed = eval_start.elapsed();
        if elapsed.as_secs() >= 1 {
            warn!("Evaluation took {}ms", elapsed.as_millis());
        }

        // Publish snapshots for Prometheus endpoint
        *shared_snapshots.write().unwrap() = snapshots;
    }
}
