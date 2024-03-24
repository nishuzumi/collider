extern crate lazy_static;

use std::sync::atomic::Ordering;
use std::time::Instant;

use bitcoin::consensus::encode;
use bitcoin::key::Secp256k1;
use bitcoin::Network;
use colored::*;
use ocl::{Device, Platform};
use prettytable::{Cell, Row, Table};
use tracing::{info, subscriber};
use tracing_subscriber::fmt::format::Format;

use atomicals_electrumx::{Api, ElectrumXBuilder};
use atomicals_packer::AtomicalsPacker;

use crate::atomicals_worker::AtomicalsWorker;
use crate::miner::{create_miner, Miner};
use crate::miner::cpu::CpuMiner;
use crate::miner::gpu::GpuMiner;
use crate::util::{format_speed, get_cpu_desc, GLOBAL_OPTS};
use crate::utils::bitworkc::BitWork;

pub mod atomicals_packer;
pub mod atomicals_worker;
mod miner;
mod util;
mod utils;

#[cfg(not(target_pointer_width = "64"))]
compile_error!("This program requires a 64-bit architecture.");

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let opts = GLOBAL_OPTS.clone();

    if GLOBAL_OPTS.verbose {
        let format = Format::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .event_format(format)
            .finish();
        subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
    } else {
        let format = Format::default()
            .without_time()
            .with_target(false)
            .with_level(true);
        let subscriber = tracing_subscriber::fmt()
            .event_format(format)
            .with_max_level(tracing::Level::INFO)
            .finish();

        subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
    };

    println!(
        "{}",
        "

             ██████╗ ██████╗ ██╗     ██╗     ⚛️╗███████╗██████╗ 
            ██╔════╝██╔═══██╗██║     ██║     ██║██╔════╝██╔══██╗
            ██║     ██║   ██║██║     ██║     ██║█████╗  ██████╔╝
            ██║     ██║   ██║██║     ██║     ██║██╔══╝  ██╔══██╗
            ╚██████╗╚██████╔╝███████╗███████╗██║███████╗██║  ██║
             ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝╚══════╝╚═╝  ╚═╝"
            .bright_red()
    );
    let twitter = "Author: @BoxMrChen https://x.com/BoxMrChen".blue();
    let boxchen = "@BoxMrChen".yellow();
    println!(
        r#"
            Made with ❤️ by {boxchen}, @atomicalsir, @atomicals               
                {twitter}
               Github: https://github.com/nishuzumi/collider

"#
    );

    if opts.verbose {
        tracing::debug!("Verbose mode is enabled");
    }

    if opts.benchmark {
        info!("Running collider benchmark...");
        collider_benchmark();
    } else {
        info!("Starting collier...");
        mint().await;
    }
}

fn collider_benchmark() {
    info!("{}", "Benchmarking, will take a few minutes...".yellow());
    
    let commit_tx = "01000000012a912f654cc1bd88da5b8a54c52b6dd60b6e831bfba52b32c1314cd17c5634120100000000feffffff024c05000000000000225120e3d5a4789dc4982cfda563c8c23f988f505e481bf9602f7ba5b1045e44e0392000b09a3b0000000022512032447fe28750a7e2b18af49d89a359a81c69bbf6f3db05feb7e8e1688f37e4c200000000";
    let commit_tx = hex::decode(commit_tx).unwrap();

    let reveal_tx = "01000000017b7afa047d43cb34409d453e11fc048314dd2ee58a5b20c1b0f6a8077b5634120000000000fdffffff02e803000000000000225120adb58bdbccaa9fdd6594859354b502214e3405a74d772a60e255e233468c4c7900000000000000000a6a08000000000000000100000000";
    let reveal_tx = hex::decode(reveal_tx).unwrap();

    let miners: Vec<Box<dyn Miner>> = vec![Box::new(CpuMiner::new()), Box::new(GpuMiner::new())];

    let bitwork = BitWork::new("1234567.14".to_string()).unwrap();
    let bitwork_r = BitWork::new("1234567.11".to_string()).unwrap();

    let mut table = Table::new();
    table.add_row(Row::new(vec![
        Cell::new("Device"),
        Cell::new("Commit Hash Rate (M/s)"),
        Cell::new("Reveal Hash Rate (M/s)"),
    ]));
    for miner in miners {
        // commit
        let now = Instant::now();
        let _ = miner
            .mine_commit(&commit_tx, bitwork.clone(), 0, None)
            .unwrap();
        let elapsed = now.elapsed();
        let hash_rate =
            miner.mine_commit_counter().load(Ordering::SeqCst) as f64 / elapsed.as_secs_f64();

        let now = Instant::now();
        let _ = miner
            .mine_reveal(&reveal_tx, bitwork_r.clone(), 0, None)
            .unwrap();
        let elapsed = now.elapsed();
        let reveal_hash_rate =
            miner.mine_reveal_counter().load(Ordering::SeqCst) as f64 / elapsed.as_secs_f64();

        let commit_str = format!("{}/s", format_speed(hash_rate));
        let reveal_str = format!("{}/s", format_speed(reveal_hash_rate).as_str());

        table.add_row(Row::new(vec![
            Cell::new(miner.name()),
            Cell::new(commit_str.as_str()),
            Cell::new(reveal_str.as_str()),
        ]));
    }

    println!();
    println!("{}", "Benchmark results:".blue());
    println!("CPU Name: {}", get_cpu_desc());
    let platform = Platform::default();
    let devices = Device::list_all(platform).unwrap();
    
    for device in devices.iter() {
        println!(
            "GPU Name: {} (OpenCL Version: {})",
            device.name().unwrap(),
            device.version().unwrap()
        );
    }
    table.printstd();
}

async fn mint() {
    let opts = GLOBAL_OPTS.clone();

    let (electrumx, network) = if opts.testnet {
        info!("Using testnet");
        (
            ElectrumXBuilder::testnet().build().unwrap(),
            Network::Testnet,
        )
    } else {
        info!("Using mainnet");
        let mut client = ElectrumXBuilder::default();
        if let Some(api_url) = opts.api_url {
            client = client.base_uri(api_url);
        }

        (client.build().unwrap(), Network::Bitcoin)
    };

    // print primary wallet address
    let secp = Secp256k1::new();
    info!(
        "Primary wallet address: {}",
        opts.primary_wallet.clone().unwrap()
    );
    info!(
        "Funding wallet address: {}",
        opts.funding_wallet.as_ref().unwrap().p2tr_address(&secp)
    );

    let packer = AtomicalsPacker::new(electrumx.clone(), network, false);

    let ft = packer
        .get_bitwork_info(opts.ticker.unwrap().clone())
        .await
        .expect("get bitwork info error");

    info!("Bitwork info: {}", ft);
    let worker_data = packer
        .generate_worker(&ft, opts.primary_wallet.clone().unwrap())
        .await
        .expect("generate worker error");

    let funding_wallet = opts.funding_wallet.as_ref().unwrap().p2tr_address(&secp);
    let utxo = electrumx
        .wait_until_utxo(funding_wallet.to_string(), worker_data.satsbyte)
        .await
        .expect("wait until utxo error");

    let miner = create_miner();

    let worker = AtomicalsWorker::new(
        GLOBAL_OPTS.funding_wallet.as_ref().unwrap().keypair(&secp),
        miner,
    );

    let commit_result = worker
        .build_commit_tx(&worker_data, utxo)
        .expect("build commit tx error");

    let commit_hex = encode::serialize_hex(&commit_result.commit_tx);
    // print the commit hex content
    info!("🔍 Commit hex: {}", commit_hex);
    electrumx
        .broadcast(commit_hex)
        .await
        .expect("broadcast commit tx error");
    let testnet = if opts.testnet { "testnet/" } else { "" };
    info!(
        "🔍🎺 Commit tx broadcasted successfully! 🚀 {}",
        format!(
            "https://mempool.space/{}tx/{}",
            testnet,
            commit_result.commit_tx.txid()
        )
        .blue()
    );

    let reveal_result = worker
        .build_reveal_tx(commit_result, &worker_data)
        .expect("build reveal tx error");

    let reveal_hex = encode::serialize_hex(&reveal_result);
    // print the reveal hex content
    info!("🔓 Reveal hex: {}", reveal_hex);
    electrumx
        .broadcast(reveal_hex)
        .await
        .expect("broadcast reveal tx error");
    info!(
        "🔓🎺 Reveal tx broadcasted successfully! 🚀 {}",
        format!(
            "https://mempool.space/{}tx/{}",
            testnet,
            reveal_result.txid()
        )
        .blue()
    );

    info!("🎉 Eureka! 💥 The Collider has successfully smashed the problem and computed the result! 🧪✨")
}
