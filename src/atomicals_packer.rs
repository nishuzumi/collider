use std::str::FromStr;

use bitcoin::{Address, Amount, Network, TxOut};
use bitcoin::secp256k1::{All, Secp256k1};
use eyre::{eyre, Result};
use serde::Serialize;

use atomicals_electrumx::{Api, ElectrumX};
/// Thanks for atomicalsir awesome work
use atomicals_electrumx::r#type::Ft;

use crate::util;
use crate::util::{current_network, GLOBAL_OPTS};
use crate::utils::bitworkc::BitWork;

#[derive(Debug)]
pub struct AtomicalsPacker {
    pub api: ElectrumX,
    pub network: Network,
    master_mode: bool,
}

#[derive(Clone, Debug)]
pub struct TickerData {
    pub secp: Secp256k1<All>,
    pub satsbyte: u64,
    pub bitworkc: BitWork,
    pub bitworkr: Option<BitWork>,
    pub additional_outputs: Vec<TxOut>,
    pub payload: PayloadWrapper,
}

#[derive(Clone, Debug)]
pub struct Fees {
    pub commit: u64,
    // commit_and_reveal: u64,
    pub commit_and_reveal_and_outputs: u64,
    // reveal: u64,
    pub reveal_and_outputs: u64,
}
#[derive(Debug, Serialize, Clone)]
pub struct PayloadWrapper {
    pub args: Payload,
}
#[derive(Debug, Serialize, Clone)]
pub struct Payload {
    pub bitworkc: String,
    pub mint_ticker: String,
    pub nonce: u64,
    pub time: u64,
}
impl AtomicalsPacker {
    pub fn new(electrumx: ElectrumX, network: Network, master_mode: bool) -> Self {
        AtomicalsPacker {
            api: electrumx,
            network,
            master_mode,
        }
    }

    pub async fn get_bitwork_info(&self, ticker: String) -> Result<Ft> {
        let id = self.api.get_by_ticker(ticker.clone()).await?.atomical_id;
        let response = self.api.get_ft_info(id).await?;
        let global = response.global.unwrap();
        let ft = response.result;

        if ft.ticker != ticker {
            Err(eyre!("ticker mismatch"))?;
        }
        if ft.subtype != "decentralized" {
            Err(eyre!("not decentralized"))?;
        }
        if ft.mint_height > global.height + 1 {
            Err(eyre!("mint height mismatch"))?;
        }
        if ft.mint_amount == 0 || ft.mint_amount >= 100_000_000 {
            Err(eyre!("mint amount mismatch"))?;
        }
        if ft.dft_info.mint_count >= ft.max_mints  && ft.mint_mode.clone().is_some_and(|mode| mode != "perpetual") && !self.master_mode {
            Err(eyre!("max mints reached"))?;
        }

        Ok(ft)
    }
    pub async fn generate_worker(&self, ft: &Ft, primary_address: String) -> Result<TickerData> {
        let secp = Secp256k1::new();
        let satsbyte = if self.network == Network::Bitcoin {
            GLOBAL_OPTS.base_fee
        } else {
            2
        };
        let wallet = Address::from_str(&primary_address)?
            .require_network(current_network())
            .expect("network mismatch");
        let additional_outputs = vec![TxOut {
            value: Amount::from_sat(ft.mint_amount),
            script_pubkey: wallet.script_pubkey(),
        }];
        let bitworkc = BitWork::new(
            ft.mint_bitworkc
                .clone()
                .unwrap_or_else(|| ft.dft_info.mint_bitworkc_current.clone().unwrap()),
        )
        .expect("bitworkc parse error");
        let payload = PayloadWrapper {
            args: {
                let (time, nonce) = util::time_nonce();

                Payload {
                    bitworkc: bitworkc.raw.clone(),
                    mint_ticker: ft.ticker.clone(),
                    nonce,
                    time,
                }
            },
        };
        Ok(TickerData {
            secp,
            satsbyte,
            bitworkc,
            bitworkr: ft
                .mint_bitworkr
                .clone()
                .map(|bitwork| BitWork::new(bitwork).unwrap()),
            additional_outputs,
            payload,
        })
    }
}

#[cfg(test)]
mod test {
    use bitcoin::Network;
    use tracing::info;

    use atomicals_electrumx::{Api, ElectrumXBuilder};

    use crate::atomicals_packer::AtomicalsPacker;
    use crate::util::{GLOBAL_OPTS, log};

    #[tokio::test]
    async fn test_get_bitwork_info() {
        log();
        let electrumx = ElectrumXBuilder::testnet().build().unwrap();
        let packer = AtomicalsPacker::new(electrumx.clone(), Network::Testnet, true);
        let ft = packer
            .get_bitwork_info("rollover3".to_string())
            .await
            .unwrap();
        info!("{:?}", ft);
        assert_eq!(ft.ticker, "rollover3");
        let worker_data = packer
            .generate_worker(&ft, GLOBAL_OPTS.primary_wallet.as_ref().unwrap().clone())
            .await
            .unwrap();
        info!("{:?}", worker_data);

        let funding_wallet = &GLOBAL_OPTS.funding_wallet.as_ref().unwrap().p2tr_address(&worker_data.secp);
        let utxo = electrumx
            .wait_until_utxo(funding_wallet.to_string(), worker_data.satsbyte)
            .await;
        info!("{:?}", utxo);
    }
}
