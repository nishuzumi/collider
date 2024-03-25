use std::env;
use std::process::Command;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::{Address, key, Network, PrivateKey, Script, ScriptBuf, TapNodeHash, XOnlyPublicKey};
use bitcoin::consensus::Encodable;
use bitcoin::key::{Keypair, Secp256k1, TapTweak, TweakedKeypair};
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF, OP_RETURN};
use bitcoin::opcodes::OP_0;
use bitcoin::script::PushBytes;
use bitcoin::secp256k1::All;
use eyre::Result;
use lazy_static::lazy_static;
use rand::Rng;
use serde::Serialize;
use structopt::StructOpt;

#[derive(Clone, Debug, StructOpt)]
#[structopt(name = "Collider", about = "A collider for atomicals.")]
pub struct Opt {
    #[structopt(long)]
    pub benchmark: bool,
    /// Sets the level of verbosity
    #[structopt(short, long)]
    pub verbose: bool,

    #[structopt(short, long, env = "API_URL")]
    pub api_url: Option<String>,

    #[structopt(long, env = "TESTNET")]
    pub testnet: bool,

    #[structopt(short, long, default_value = "50", env = "BASE_FEE")]
    pub base_fee: u64,

    #[structopt(short, long, env = "PRIMARY_WALLET", required_unless("benchmark"))]
    pub primary_wallet: Option<String>,

    #[structopt(short, long, env = "FUNDING_WALLET", parse(try_from_str = WifPrivateKey::from_str),required_unless("benchmark"))]
    pub funding_wallet: Option<WifPrivateKey>,

    #[structopt(short, long, env = "TICKER")]
    pub ticker: Option<String>,

    #[structopt(short, long, env = "MINER", default_value = "cpu",required_unless("benchmark"), possible_values = &["cpu", "gpu"])]
    pub miner: String,
}

lazy_static! {
    pub static ref GLOBAL_OPTS: Opt = {
        if cfg!(test) {
            Opt {
                benchmark: false,
                verbose: false,
                api_url: None,
                testnet: true,
                base_fee: 50,
                ticker: Option::from("atom".to_string()),
                primary_wallet: Option::from(env::var("PRIMARY_WALLET").expect("PRIMARY_WALLET is not set")),
                funding_wallet: Option::from(WifPrivateKey::from_str(
                    env::var("FUNDING_WALLET")
                        .expect("FUNDING_WALLET is not set")
                        .as_str(),
                )
                .unwrap()),
                miner: "gpu".to_string(),
            }
        } else {
            Opt::from_args()
        }
    };
}

pub fn current_network() -> Network {
    if GLOBAL_OPTS.testnet {
        Network::Testnet
    } else {
        Network::Bitcoin
    }
}

#[cfg(test)]
pub fn log() {
    dotenvy::dotenv().ok();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO) // 设置日志级别
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
}

pub fn tx2bytes(tx: &bitcoin::Transaction) -> Vec<u8> {
    let mut buf = Vec::new();
    tx.consensus_encode(&mut buf).unwrap();
    buf
}
#[allow(dead_code)]
pub fn tx2hex(tx: &bitcoin::Transaction) -> String {
    hex::encode(tx2bytes(tx))
}

#[derive(Clone, Debug)]
pub struct WifPrivateKey(PrivateKey);

impl FromStr for WifPrivateKey {
    type Err = key::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PrivateKey::from_wif(s).map(WifPrivateKey)
    }
}

impl WifPrivateKey {
    pub(crate) fn keypair(&self, secp: &Secp256k1<All>) -> Keypair {
        self.0.inner.keypair(&secp)
    }
    pub(crate) fn x_only_public_key(&self, secp: &Secp256k1<All>) -> XOnlyPublicKey {
        let (x, _) = self.0.inner.x_only_public_key(secp);
        x
    }

    pub fn p2tr_address(&self, secp: &Secp256k1<All>) -> Address {
        Address::p2tr(secp, self.x_only_public_key(secp), None, current_network())
    }

    pub fn tap_tweak(
        &self,
        secp: &Secp256k1<All>,
        merkle_tree: Option<TapNodeHash>,
    ) -> TweakedKeypair {
        let pair = Keypair::from_secret_key(secp, &self.0.inner);
        pair.tap_tweak(secp, merkle_tree)
    }
}
pub fn time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
pub fn time_nonce() -> (u64, u64) {
    (time(), rand::thread_rng().gen_range(1..10_000_000))
}
pub fn time_nonce_script(nonce: u64) -> ScriptBuf {
    Script::builder()
        .push_opcode(OP_RETURN)
        // .push_slice(<&PushBytes>::try_from(format!("{:016X}", nonce).as_bytes()).unwrap())
        .push_slice(nonce.to_le_bytes())
        .into_script()
}

pub fn cbor<T>(v: &T) -> Result<Vec<u8>>
where
    T: Serialize,
{
    let mut cbor = Vec::new();

    ciborium::into_writer(v, &mut cbor)?;

    Ok(cbor)
}

pub fn build_reveal_script(
    x_only_public_key: &XOnlyPublicKey,
    op_type: &str,
    payload: &[u8],
) -> ScriptBuf {
    // format!(
    // 	"{} OP_CHECKSIG OP_0 OP_IF {} {} {} OP_ENDIF",
    // 	&private_key.public_key(&Default::default()).to_string()[2..],
    // 	array_bytes::bytes2hex("", "atom"),
    // 	array_bytes::bytes2hex("", op_type),
    // 	payload.chunks(520).map(|c| array_bytes::bytes2hex("", c)).collect::<Vec<_>>().join(" ")
    // )
    let b = Script::builder()
        .push_x_only_key(x_only_public_key)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_0)
        .push_opcode(OP_IF)
        .push_slice(<&PushBytes>::try_from("atom".as_bytes()).unwrap())
        .push_slice(<&PushBytes>::try_from(op_type.as_bytes()).unwrap());

    payload
        .chunks(520)
        .fold(b, |b, c| b.push_slice(<&PushBytes>::try_from(c).unwrap()))
        .push_opcode(OP_ENDIF)
        .into_script()
}

pub fn format_speed(speed: f64) -> String {
    const UNITS: [&str; 4] = ["", "K", "M", "B"];
    let mut speed = speed;
    let mut unit_index = 0;

    while speed >= 1000.0 && unit_index < UNITS.len() - 1 {
        speed /= 1000.0;
        unit_index += 1;
    }

    format!("{:.2}{}", speed, UNITS[unit_index])
}

#[cfg(target_os = "macos")]
pub fn get_cpu_desc() -> String {
    let output = Command::new("sysctl")
        .arg("-n")
        .arg("machdep.cpu.brand_string")
        .output()
        .expect("failed to execute process");

    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[cfg(target_os = "linux")]
pub fn get_cpu_desc() -> String {
    use std::io::{BufRead, BufReader};
    let file = std::fs::File::open("/proc/cpuinfo").expect("Could not open /proc/cpuinfo");
    let reader = std::io::BufReader::new(file);

    for line in reader.lines() {
        if let Ok(line) = line {
            if line.starts_with("model name") {
                let cpu_desc = line.split(':').nth(1).expect("Could not split line").trim();
                return cpu_desc.to_string();
            }
        }
    }

    "Unknown".to_string()
}

#[cfg(target_os = "windows")]
pub fn get_cpu_desc() -> String {
    let output = Command::new("wmic")
        .args(["cpu", "get", "name"])
        .output()
        .expect("failed to execute process");

    let output = String::from_utf8_lossy(&output.stdout);
    output.trim().split('\n').nth(1).unwrap_or("Unknown").trim().to_string()
}