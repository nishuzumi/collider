extern crate lazy_static;

use bitcoin::consensus::encode;
use bitcoin::key::Secp256k1;
use bitcoin::Network;
use colored::*;
use tracing::{event, info, info_span, Level, subscriber};
use tracing::span::Record;
use tracing_subscriber::fmt::format::Format;
use tracing_subscriber::FmtSubscriber;

use atomicals_electrumx::{Api, ElectrumXBuilder};
use atomicals_packer::AtomicalsPacker;

use crate::atomicals_worker::AtomicalsWorker;
use crate::miner::create_miner;
use crate::util::GLOBAL_OPTS;

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

    info!("Starting collier...");
    if opts.verbose {
        tracing::debug!("Verbose mode is enabled");
    }

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
    info!("Primary wallet address: {}", opts.primary_wallet);
    info!(
        "Funding wallet address: {}",
        opts.funding_wallet.p2tr_address(&secp)
    );

    let packer = AtomicalsPacker::new(electrumx.clone(), network, false);

    let ft = packer
        .get_bitwork_info(opts.ticker.clone())
        .await
        .expect("get bitwork info error");

    info!("Bitwork info: {}", ft);
    let worker_data = packer
        .generate_worker(&ft, opts.primary_wallet.clone())
        .await
        .expect("generate worker error");

    let funding_wallet = &opts.funding_wallet.p2tr_address(&secp);
    let utxo = electrumx
        .wait_until_utxo(funding_wallet.to_string(), worker_data.satsbyte)
        .await
        .expect("wait until utxo error");

    let miner = create_miner();

    let worker = AtomicalsWorker::new(GLOBAL_OPTS.funding_wallet.clone().keypair(&secp), miner);

    let commit_result = worker.build_commit_tx(&worker_data, utxo).expect("build commit tx error");

    let commit_hex = encode::serialize_hex(&commit_result.commit_tx);
    // print the commit hex content
    info!("🔍 Commit hex: {}", commit_hex);
    electrumx.broadcast(commit_hex).await.expect("broadcast commit tx error");
    let testnet = if opts.testnet { "testnet/" } else { "" };
    info!("🔍🎺 Commit tx broadcasted successfully! 🚀 {}",format!("https://mempool.space/{}tx/{}",testnet,commit_result.commit_tx.txid()).blue());
    
    let reveal_result = worker.build_reveal_tx(commit_result,&worker_data ).expect("build reveal tx error");
    
    let reveal_hex = encode::serialize_hex(&reveal_result);
    // print the reveal hex content
    info!("🔓 Reveal hex: {}", reveal_hex);
    electrumx.broadcast(reveal_hex).await.expect("broadcast reveal tx error");
    info!("🔓🎺 Reveal tx broadcasted successfully! 🚀 {}",format!("https://mempool.space/{}tx/{}",testnet,reveal_result.txid()).blue());
    
    info!("🎉 Eureka! 💥 The Collider has successfully smashed the problem and computed the result! 🧪✨")
}
