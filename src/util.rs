use std::env;
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
#[structopt(name = "Collier", about = "A collier for atomicals.")]
pub struct Opt {
    /// Sets the level of verbosity
    #[structopt(short, long)]
    pub verbose: bool,

    #[structopt(short, long, env = "API_URL")]
    pub api_url: Option<String>,

    #[structopt(long, env = "TESTNET")]
    pub testnet: bool,

    #[structopt(short, long, default_value = "50", env = "BASE_FEE")]
    pub base_fee: u64,

    #[structopt(short, long, env = "PRIMARY_WALLET")]
    pub primary_wallet: String,

    #[structopt(short, long, env = "FUNDING_WALLET", parse(try_from_str = WifPrivateKey::from_str))]
    pub funding_wallet: WifPrivateKey,
    
    #[structopt(short, long, env = "TICKER")]
    pub ticker:String,
    
    #[structopt(short, long, env = "MINER",default_value = "cpu")]
    pub miner: String,
}

lazy_static! {
    pub static ref GLOBAL_OPTS: Opt = {
        if cfg!(test) {
            Opt {
                verbose: false,
                api_url: None,
                testnet: true,
                base_fee: 50,
                ticker: "atom".to_string(),
                primary_wallet: env::var("PRIMARY_WALLET").expect("PRIMARY_WALLET is not set"),
                funding_wallet: WifPrivateKey::from_str(
                    env::var("FUNDING_WALLET")
                        .expect("FUNDING_WALLET is not set")
                        .as_str(),
                )
                .unwrap(),
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
