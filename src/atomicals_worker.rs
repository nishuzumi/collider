use std::cell::RefCell;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use bitcoin::{
    Amount, OutPoint, Psbt, ScriptBuf, Sequence, TapLeafHash, TapSighashType, Transaction, TxIn,
    TxOut, Witness,
};
use bitcoin::absolute::LockTime;
use bitcoin::consensus::{deserialize, Encodable};
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::psbt::Input;
use bitcoin::secp256k1::{All, Message};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{LeafVersion, Signature, TaprootBuilder, TaprootSpendInfo};
use bitcoin::transaction::Version;
use eyre::Result;
use indicatif::{ProgressBar, ProgressStyle};
use tokio::sync::oneshot;

use atomicals_electrumx::r#type::Utxo;

use crate::atomicals_packer::{Fees, Payload, PayloadWrapper, TickerData};
use crate::miner::Miner;
use crate::util;
use crate::util::{format_speed, GLOBAL_OPTS, tx2bytes};

#[derive(Debug, Clone)]
pub struct PayloadScript {
    pub payload: PayloadWrapper,
    pub payload_encoded: Vec<u8>,
    funding_spk: ScriptBuf,
    reveal_script: ScriptBuf,
    reveal_spend_info: TaprootSpendInfo,
    pub fees: Fees,
    reveal_spk: ScriptBuf,
}

#[derive(Debug)]
pub struct CommitInfo {
    pub commit_tx: Transaction,
    commit_output: Vec<TxOut>,
    payload_script: PayloadScript,
}

struct PsbtData {
    psbt: Psbt,
    payload_script: PayloadScript,
    commit_output: Vec<TxOut>,
    commit_prev_outs: [TxOut; 1],
}

/// AtomicalsBuilder is a builder for build available atomicals mining transactions
/// As we all know, the commit tx and reveal tx are the pair transaction in ordinals
/// So we only need know the tx in, and we can build the commit tx and reveal tx without any other information
pub struct AtomicalsWorker {
    funding_wallet: Keypair,
    miner: RefCell<Box<dyn Miner>>,
}

impl AtomicalsWorker {
    const BASE_BYTES: f64 = 10.5;
    const INPUT_BYTES_BASE: f64 = 67.5;
    // Estimated 8-byte value, with a script size of one byte.
    // The actual size of the value is determined by the final nonce.
    const OP_RETURN_BYTES: f64 = 21. + 8. + 1.;
    const OUTPUT_BYTES_BASE: f64 = 31.;
    const REVEAL_INPUT_BYTES_BASE: f64 = 41.;

    const VERSION: Version = Version::ONE;
    const LOCK_TIME: LockTime = LockTime::ZERO;
    pub fn new(funding_wallet: Keypair, miner: Box<dyn Miner>) -> Self {
        AtomicalsWorker {
            funding_wallet,
            miner: RefCell::new(miner),
        }
    }
    /// Generate the payload script
    /// The payload script is the script that will be used in the reveal tx
    pub fn generate_payload_script(&self, ticker_data: &TickerData) -> Result<PayloadScript> {
        let TickerData {
            secp,
            satsbyte,
            additional_outputs,
            ticker,
            ..
        } = ticker_data;

        let payload = PayloadWrapper {
            args: {
                Payload {
                    mint_ticker: ticker.to_string(),
                }
            },
        };

        let payload_encoded = util::cbor(&payload)?;

        let funding_wallet = GLOBAL_OPTS.funding_wallet.as_ref().unwrap();
        let funding_wallet_x_only_public_key = funding_wallet.x_only_public_key(secp);

        let reveal_script =
            util::build_reveal_script(&funding_wallet_x_only_public_key, "dmt", &payload_encoded);

        let reveal_spend_info = TaprootBuilder::new()
            .add_leaf(0, reveal_script.clone())?
            .finalize(secp, funding_wallet_x_only_public_key)
            .unwrap();
        let fees = Self::fees_of(
            satsbyte.to_owned(),
            reveal_script.as_bytes().len(),
            additional_outputs,
            true,
        );

        let reveal_spk = ScriptBuf::new_p2tr(
            secp,
            reveal_spend_info.internal_key(),
            reveal_spend_info.merkle_root(),
        );
        let funding_spk = funding_wallet.p2tr_address(secp).script_pubkey();
        Ok(PayloadScript {
            payload,
            payload_encoded,
            funding_spk,
            reveal_script,
            reveal_spend_info,
            reveal_spk,
            fees,
        })
    }

    fn build_common_outputs(
        &self,
        satsbyte: u64,
        funding_utxo: &Utxo,
        payload_script: &PayloadScript,
    ) -> Vec<TxOut> {
        let PayloadScript {
            fees,
            reveal_spk,
            funding_spk,
            ..
        } = payload_script;

        {
            let spend = TxOut {
                value: Amount::from_sat(fees.reveal_and_outputs),
                script_pubkey: reveal_spk.clone(),
            };
            let refund = {
                let r = funding_utxo
                    .value
                    .saturating_sub(fees.reveal_and_outputs)
                    .saturating_sub(
                        fees.commit + (Self::OUTPUT_BYTES_BASE * satsbyte as f64).floor() as u64,
                    );

                if r > 0 {
                    Some(TxOut {
                        value: Amount::from_sat(r),
                        script_pubkey: funding_spk.clone(),
                    })
                } else {
                    None
                }
            };

            if let Some(r) = refund {
                vec![spend, r]
            } else {
                vec![spend]
            }
        }
    }

    fn build_psbt_data(
        &self,
        data: &TickerData,
        satsbyte: u64,
        funding_utxo: Utxo,
        sequence: u32,
        commit_input: Vec<TxIn>,
    ) -> Result<PsbtData> {
        let payload_script = self.generate_payload_script(data)?;
        let PayloadScript { funding_spk, .. } = payload_script.clone();

        let commit_output = self.build_common_outputs(satsbyte, &funding_utxo, &payload_script);
        let commit_prev_outs = [TxOut {
            value: Amount::from_sat(funding_utxo.value),
            script_pubkey: funding_spk.clone(),
        }];

        let psbt = Psbt::from_unsigned_tx(Transaction {
            version: Self::VERSION,
            lock_time: Self::LOCK_TIME,
            input: {
                let mut i = commit_input.to_owned();
                i[0].sequence = Sequence(sequence);
                i
            },
            output: commit_output.clone(),
        })?;

        Ok(PsbtData {
            psbt,
            payload_script,
            commit_output,
            commit_prev_outs,
        })
    }

    pub fn build_commit_tx(&self, data: &TickerData, funding_utxo: Utxo) -> Result<CommitInfo> {
        let TickerData {
            secp,
            satsbyte,
            bitworkc,
            ..
        } = data.clone();

        let funding_wallet = GLOBAL_OPTS.funding_wallet.as_ref().unwrap();

        let commit_input = vec![TxIn {
            previous_output: OutPoint::new(funding_utxo.txid.parse()?, funding_utxo.vout),
            ..Default::default()
        }];

        let (compute_done_sender, compute_done_receiver) = oneshot::channel();

        let counter = self.miner.borrow_mut().mine_commit_counter();
        let handle = thread::spawn(move || {
            create_hash_rate_bar(
                "Commit mining: ".to_string(),
                move || counter.load(Ordering::Relaxed),
                compute_done_receiver,
            );
        });

        let mut psbt_data = self.build_psbt_data(
            data,
            satsbyte,
            funding_utxo.clone(),
            0,
            commit_input.clone(),
        )?;

        // If there have not found the target sequence, we will return the None
        let mut psbt = psbt_data.psbt.clone();

        let mut serialize_tx = vec![];
        psbt.unsigned_tx
            .consensus_encode(&mut serialize_tx)
            .unwrap();

        let mut miner = self.miner.borrow_mut();
        let commit_tx = miner.mine_commit(&serialize_tx, bitworkc.clone(), 0, None);

        psbt.unsigned_tx = deserialize(commit_tx.as_slice()).expect("Cant not deserialize the commit tx");

        // set it done
        compute_done_sender
            .send(())
            .expect("send done signal failed");

        // sign it

        let tap_key_sig = {
            let commit_hty = TapSighashType::Default;
            let h = SighashCache::new(&psbt_data.psbt.unsigned_tx)
                .taproot_key_spend_signature_hash(
                    0,
                    &Prevouts::All(&psbt_data.commit_prev_outs),
                    commit_hty,
                )?;
            let m = Message::from_digest(h.to_byte_array());

            Signature {
                sig: secp.sign_schnorr(&m, &funding_wallet.tap_tweak(&secp, None).to_inner()),
                hash_ty: commit_hty,
            }
        };

        psbt_data.psbt.inputs[0] = Input {
            witness_utxo: Some(psbt_data.commit_prev_outs[0].clone()),
            final_script_witness: Some(Witness::from_slice(&[tap_key_sig.to_vec()])),
            tap_internal_key: Some(funding_wallet.x_only_public_key(&secp)),
            ..Default::default()
        };

        let final_tx = psbt_data.psbt.extract_tx_unchecked_fee_rate();
        handle.join().expect("join thread failed");

        Ok(CommitInfo {
            commit_tx: final_tx,
            commit_output: psbt_data.commit_output,
            payload_script: psbt_data.payload_script,
        })
    }

    pub fn build_reveal_tx(
        &self,
        commit_info: CommitInfo,
        data: &TickerData,
    ) -> Result<Transaction> {
        let TickerData {
            secp,
            additional_outputs,
            bitworkr,
            ..
        } = data.clone();
        let CommitInfo {
            commit_tx,
            commit_output,
            payload_script,
        } = commit_info;

        let PayloadScript {
            reveal_script,
            reveal_spend_info,
            ..
        } = payload_script.clone();
        // build reveal tx
        let reveal_lh = reveal_script.tapscript_leaf_hash();
        let build_psbt = |nonce: Option<u64>| -> Result<Psbt> {
            let mut psbt = Psbt::from_unsigned_tx(Transaction {
                version: Self::VERSION,
                lock_time: Self::LOCK_TIME,
                input: vec![TxIn {
                    previous_output: OutPoint::new(commit_tx.txid(), 0),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    ..Default::default()
                }],
                output: additional_outputs.clone(),
            })?;
            if let Some(nonce) = nonce {
                psbt.unsigned_tx.output.push(TxOut {
                    value: Amount::ZERO,
                    script_pubkey: util::time_nonce_script(nonce),
                });
                psbt.outputs.push(Default::default());
            }
            Ok(psbt)
        };

        let reveal_tx = if let Some(bitworkr) = bitworkr {
            let (compute_done_sender, compute_done_receiver) = oneshot::channel();
            let counter = self.miner.borrow_mut().mine_reveal_counter();
            let handle = thread::spawn(move || {
                create_hash_rate_bar(
                    "Reveal mining: ".to_string(),
                    move || counter.load(Ordering::Relaxed),
                    compute_done_receiver,
                );
            });

            let mut reveal_psbt = build_psbt(Some(0))?;
            let tx_byte = tx2bytes(&reveal_psbt.unsigned_tx);

            let mut miner = self.miner.borrow_mut();
            let reveal_tx = miner.mine_reveal(&tx_byte, bitworkr.clone(), 0, None);

            compute_done_sender
                .send(())
                .expect("send done signal failed");

            reveal_psbt.unsigned_tx =
                deserialize(reveal_tx.as_slice()).expect("Can not deserialize reveal tx");

            let mut serialize_tx = vec![];
            reveal_psbt
                .unsigned_tx
                .consensus_encode(&mut serialize_tx)
                .unwrap();

            self.sign_reveal_psbt(
                &secp,
                &mut reveal_psbt,
                &commit_output[0],
                &reveal_lh,
                &reveal_spend_info,
                &reveal_script,
            )?;

            handle.join().expect("join thread failed");
            reveal_psbt.extract_tx_unchecked_fee_rate()
        } else {
            let mut reveal_psbt = build_psbt(None)?;
            self.sign_reveal_psbt(
                &secp,
                &mut reveal_psbt,
                &commit_output[0],
                &reveal_lh,
                &reveal_spend_info,
                &reveal_script,
            )?;

            // Remove this clone if not needed in the future.
            reveal_psbt.extract_tx_unchecked_fee_rate()
        };

        Ok(reveal_tx)
    }

    fn sign_reveal_psbt(
        &self,
        secp: &Secp256k1<All>,
        psbt: &mut Psbt,
        commit_output: &TxOut,
        reveal_left_hash: &TapLeafHash,
        reveal_spend_info: &TaprootSpendInfo,
        reveal_script: &ScriptBuf,
    ) -> Result<()> {
        let signer = &self.funding_wallet;
        let reveal_hty = TapSighashType::SinglePlusAnyoneCanPay;
        let tap_key_sig = {
            let h = SighashCache::new(&psbt.unsigned_tx).taproot_script_spend_signature_hash(
                0,
                &Prevouts::One(0, commit_output.to_owned()),
                *reveal_left_hash,
                reveal_hty,
            )?;
            let m = Message::from_digest(h.to_byte_array());

            Signature {
                sig: secp.sign_schnorr(&m, signer),
                hash_ty: reveal_hty,
            }
        };

        psbt.inputs[0] = Input {
            witness_utxo: Some(commit_output.to_owned()),
            tap_internal_key: Some(reveal_spend_info.internal_key()),
            tap_merkle_root: reveal_spend_info.merkle_root(),
            final_script_witness: {
                let mut w = Witness::new();

                w.push(tap_key_sig.to_vec());
                w.push(reveal_script.as_bytes());
                w.push(
                    reveal_spend_info
                        .control_block(&(reveal_script.to_owned(), LeafVersion::TapScript))
                        .unwrap()
                        .serialize(),
                );

                Some(w)
            },
            ..Default::default()
        };

        Ok(())
    }

    fn fees_of(
        satsbyte: u64,
        reveal_script_len: usize,
        additional_outputs: &[TxOut],
        has_bitworkr: bool,
    ) -> Fees {
        let satsbyte = satsbyte as f64;
        let commit = {
            (satsbyte * (Self::BASE_BYTES + Self::INPUT_BYTES_BASE + Self::OUTPUT_BYTES_BASE + 1.))
                .ceil() as u64
        };
        let reveal = {
            let compact_input_bytes = if reveal_script_len <= 252 {
                1.
            } else if reveal_script_len <= 0xFFFF {
                3.
            } else if reveal_script_len <= 0xFFFFFFFF {
                5.
            } else {
                9.
            };
            let op_return_bytes = if has_bitworkr {
                Self::OP_RETURN_BYTES
            } else {
                0.
            };

            (satsbyte
                * (Self::BASE_BYTES
                    + Self::REVEAL_INPUT_BYTES_BASE
                    + compact_input_bytes
                    + reveal_script_len as f64 / 4.
                    + additional_outputs.len() as f64 * (Self::OUTPUT_BYTES_BASE + 1.)
                    + op_return_bytes))
                .ceil() as u64
        };
        let outputs = additional_outputs
            .iter()
            .map(|o| o.value.to_sat())
            .sum::<u64>();
        let commit_and_reveal = commit + reveal;
        let commit_and_reveal_and_outputs = commit_and_reveal + outputs;

        Fees {
            commit,
            // commit_and_reveal,
            commit_and_reveal_and_outputs,
            // reveal,
            reveal_and_outputs: reveal + outputs,
        }
    }
}
fn create_hash_rate_bar<F>(prefix: String, count_fn: F, mut done: oneshot::Receiver<()>)
where
    F: Fn() -> u64 + Send + 'static,
{
    let style = ProgressStyle::default_spinner()
        .template("{prefix} {spinner:.green} [{elapsed_precise}] {msg}")
        .unwrap();
    let start_time = Instant::now();
    let bar = ProgressBar::new(0);
    bar.set_prefix(prefix);
    bar.set_style(style);

    while done.try_recv().is_err() {
        let hashes_per_second = count_fn();

        bar.set_message(format!(
            "Hash rate: {}/s",
            format_speed(hashes_per_second as f64 / start_time.elapsed().as_secs_f64())
        ));
        bar.tick();

        // sample every 100 ms
        thread::sleep(Duration::from_millis(100));
    }
    bar.finish();
}
#[cfg(test)]
mod test {
    use std::sync::atomic::Ordering;
    use std::sync::atomic::Ordering::SeqCst;

    use bitcoin::consensus::{deserialize, encode};
    use bitcoin::Network;
    use tokio::time::Instant;
    use tracing::info;

    use atomicals_electrumx::{Api, ElectrumXBuilder};

    use crate::atomicals_packer::AtomicalsPacker;
    use crate::atomicals_worker::AtomicalsWorker;
    use crate::miner::cpu::CpuMiner;
    use crate::miner::Miner;
    use crate::util::{GLOBAL_OPTS, log, time};
    use crate::utils::bitworkc::BitWork;

    #[tokio::test]
    async fn test_mint_work() {
        log();
        let electrumx = ElectrumXBuilder::testnet().build().unwrap();
        let packer = AtomicalsPacker::new(electrumx.clone(), Network::Testnet, true);
        let ft = packer.get_bitwork_info("b911".to_string()).await.unwrap();
        info!("{:?}", ft);
        let worker_data = packer
            .generate_worker(&ft, GLOBAL_OPTS.primary_wallet.as_ref().unwrap().clone())
            .await
            .unwrap();
        info!("{:?}", worker_data);

        let funding_wallet = &GLOBAL_OPTS
            .funding_wallet
            .as_ref()
            .unwrap()
            .p2tr_address(&worker_data.secp);
        let utxo = electrumx
            .wait_until_utxo(funding_wallet.to_string(), worker_data.satsbyte)
            .await
            .unwrap();
        info!("{:?}", utxo);

        let miner = CpuMiner::new();

        let workder = AtomicalsWorker::new(
            GLOBAL_OPTS
                .funding_wallet
                .as_ref()
                .unwrap()
                .keypair(&worker_data.secp),
            Box::new(miner),
        );

        let result = workder.build_commit_tx(&worker_data, utxo).unwrap();
        info!("{:?}", result);
        let commit_hex = encode::serialize_hex(&result.commit_tx);
        electrumx.broadcast(commit_hex).await.unwrap();
        //
        let txid = result.commit_tx.txid();
        assert!(txid.to_string().starts_with("1234567"));

        let reveal = workder.build_reveal_tx(result, &worker_data).unwrap();

        info!("{:?}", reveal);
        let reveal_hex = encode::serialize_hex(&reveal);
        electrumx.broadcast(reveal_hex).await.unwrap();
    }
    // commit 01000000012a912f654cc1bd88da5b8a54c52b6dd60b6e831bfba52b32c1314cd17c5634120100000000feffffff024c05000000000000225120e3d5a4789dc4982cfda563c8c23f988f505e481bf9602f7ba5b1045e44e0392000b09a3b0000000022512032447fe28750a7e2b18af49d89a359a81c69bbf6f3db05feb7e8e1688f37e4c200000000

    #[tokio::test]
    async fn test_commit_work() {
        log();
        let tx = "01000000012a912f654cc1bd88da5b8a54c52b6dd60b6e831bfba52b32c1314cd17c5634120100000000feffffff024c05000000000000225120e3d5a4789dc4982cfda563c8c23f988f505e481bf9602f7ba5b1045e44e0392000b09a3b0000000022512032447fe28750a7e2b18af49d89a359a81c69bbf6f3db05feb7e8e1688f37e4c200000000";
        let tx = hex::decode(tx).unwrap();
        let mut miner = CpuMiner::new();
        let bitwork = BitWork::new("8888888.14".to_string()).unwrap();

        let now = Instant::now();
        let commit_count = miner.mine_commit_counter().clone();
        let nonce = miner.mine_commit(&tx, bitwork, 0, Some(time() as u32));
        let commit_count = commit_count.load(SeqCst);
        info!(
            "duration:{:?}, count:{:?}",
            now.elapsed(),
            commit_count
        );
        
        let tx:bitcoin::Transaction = deserialize(nonce.as_slice()).unwrap();
        println!("{}",tx.txid());
    }
    #[tokio::test]
    async fn test_reveal_work() {
        log();
        let tx = "01000000017b7afa047d43cb34409d453e11fc048314dd2ee58a5b20c1b0f6a8077b5634120000000000fdffffff02e803000000000000225120adb58bdbccaa9fdd6594859354b502214e3405a74d772a60e255e233468c4c7900000000000000000a6a08000000000000000100000000";
        let tx = hex::decode(tx).unwrap();
        let mut miner = CpuMiner::new();
        let bitwork = BitWork::new("1234567.11".to_string()).unwrap();

        let now = Instant::now();
        let commit_count = miner.mine_reveal_counter().load(Ordering::Relaxed);
        let reveal_tx = miner.mine_reveal(&tx, bitwork, 0, None);

        info!("duration:{:?}, count:{:?}", now.elapsed(), commit_count);

        let tx: bitcoin::Transaction = deserialize(reveal_tx.as_slice()).unwrap();
        println!("{}", tx.txid())
    }
}
