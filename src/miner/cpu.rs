use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bitcoin::Sequence;
use rayon::prelude::*;
use ring::digest::{Context, SHA256};

use crate::miner::{
    find_first_sequence_position, find_time_nonce_script_position, Miner,
};
use crate::utils::bitworkc::BitWork;

pub struct CpuMiner {
    commit_counter: Arc<AtomicU64>,
    reveal_counter: Arc<AtomicU64>,
}

impl CpuMiner {
    pub fn new() -> CpuMiner {
        CpuMiner {
            commit_counter: Arc::new(AtomicU64::new(0)),
            reveal_counter: Arc::new(AtomicU64::new(0)),
        }
    }
}
impl Miner for CpuMiner {
    fn mine_commit(
        &self,
        tx: &[u8],
        bitworkc: BitWork,
        start: u32,
        max: Option<u32>,
    ) -> Option<u32> {
        find_seq_by_range_co(tx, bitworkc, start, max, Some(&self.commit_counter))
    }

    fn mine_commit_counter(&self) -> Arc<AtomicU64> {
        self.commit_counter.clone()
    }

    fn mine_reveal(
        &self,
        tx: &[u8],
        bitworkr: BitWork,
        start: u64,
        max: Option<u64>,
    ) -> Option<u64> {
        find_return_nonce_by_range_co(tx, bitworkr, start, max, Some(&self.reveal_counter))
    }

    fn mine_reveal_counter(&self) -> Arc<AtomicU64> {
        self.reveal_counter.clone()
    }
}
pub fn find_seq_by_range_co(
    data: &[u8],
    target: BitWork,
    start: u32,
    max: Option<u32>,
    counter: Option<&AtomicU64>,
) -> Option<u32> {
    let max = max.unwrap_or(Sequence::ENABLE_LOCKTIME_NO_RBF.0);
    let range = 100000u32;
    let pos = find_first_sequence_position(data);
    let mut init_hash = Context::new(&SHA256);
    init_hash.update(&data[..pos]);

    (start..max)
        .into_par_iter()
        .step_by(range as usize)
        .find_map_any(|block_start| {
            for i in block_start..=(block_start + range).min(max) {
                let mut hash_eng = init_hash.clone();
                hash_eng.update(i.to_le_bytes().as_slice());
                hash_eng.update(&data[pos + 4..]);
                let hash2 = hash_eng.finish();

                let mut context: Context = Context::new(&SHA256);
                context.update(hash2.as_ref());
                let second_hash = context.finish();
                let result: &[u8] = second_hash.as_ref();

                if target.matches(result) {
                    counter.map(|c| c.fetch_add((i - block_start) as u64, Ordering::Relaxed));
                    return Some(i);
                }
            }

            counter.map(|c| c.fetch_add(range as u64, Ordering::Relaxed));
            None
        })
}

pub fn find_return_nonce_by_range_co(
    data: &[u8],
    target: BitWork,
    start: u64,
    max: Option<u64>,
    counter: Option<&AtomicU64>,
) -> Option<u64> {
    let max = max.unwrap_or(u64::MAX);
    let range = 100000u32;
    let pos = find_time_nonce_script_position(data);
    let mut init_hash = Context::new(&SHA256);
    init_hash.update(&data[..pos]);

    // change it to carry mode
     (start..=max).step_by(u32::MAX as usize).find_map(|start| {
        let end = (start + u32::MAX as u64).min(max);
        let offset = (end - start) as u32;
        (0..offset)
            .into_par_iter()
            .step_by(range as usize)
            .find_map_any(|offset| {
                for ii in offset..=(range + offset).min(u32::MAX) {
                    let i = ii as u64 + start;
                    let mut hash_eng = init_hash.clone();
                    hash_eng.update(i.to_le_bytes().as_slice());
                    hash_eng.update(&data[pos + 8..]);
                    let hash2 = hash_eng.finish();

                    let mut context: Context = Context::new(&SHA256);
                    context.update(hash2.as_ref());
                    let second_hash = context.finish();
                    let result: &[u8] = second_hash.as_ref();

                    if target.matches(result) {
                        counter.map(|counter| {
                            counter.fetch_add((ii - offset) as u64, Ordering::Relaxed)
                        });

                        return Some(i);
                    }
                }

                if let Some(counter) = counter { counter.fetch_add(range as u64, Ordering::Relaxed); }
                None
            })
    })

}
