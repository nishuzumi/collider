use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rayon::prelude::*;
use ring::digest::{Context, SHA256};

use crate::miner::{find_first_sequence_position, find_time_nonce_script_position, Miner};
use crate::util::time;
use crate::utils::bitworkc::BitWork;

pub struct CpuMiner {
    commit_counter: Arc<AtomicU64>,
    sequence_count: u32,
    reveal_counter: Arc<AtomicU64>,
}

impl CpuMiner {
    pub fn new() -> CpuMiner {
        CpuMiner {
            sequence_count: 0x80000000, // enable abs time lock
            commit_counter: Arc::new(AtomicU64::new(0)),
            reveal_counter: Arc::new(AtomicU64::new(0)),
        }
    }
    pub fn find_seq_by_range_co(
        &mut self,
        data: &[u8],
        target: BitWork,
        start: u32,
        max: Option<u32>,
        counter: Option<&AtomicU64>,
    ) -> Vec<u8> {
        self.sequence_count = 0x80000000;
        let max = max.unwrap_or_else(|| time() as u32);
        let range = 100000u32;
        let pos = find_first_sequence_position(data);
        loop {
            let mut init_hash = Context::new(&SHA256);
            init_hash.update(&data[..pos]);
            init_hash.update(self.sequence_count.to_le_bytes().as_slice());
            init_hash.update(&data[pos + 4..data.len() - 4]);

            // work forever....
            let result = (start..max)
                .into_par_iter()
                .step_by(range as usize)
                .find_map_any(|block_start| {
                    for i in block_start..=(block_start + range).min(max) {
                        let mut hash_eng = init_hash.clone();
                        // let us find the lock time
                        hash_eng.update(&i.to_le_bytes());
                        let hash2 = hash_eng.finish();

                        let mut context: Context = Context::new(&SHA256);
                        context.update(hash2.as_ref());
                        let second_hash = context.finish();
                        let result: &[u8] = second_hash.as_ref();

                        if target.matches(result) {
                            counter
                                .map(|c| c.fetch_add((i - block_start) as u64, Ordering::Relaxed));
                            
                            let mut result = Vec::new();

                            result.extend_from_slice(&data[..pos]);
                            result.extend_from_slice(&self.sequence_count.to_le_bytes());
                            result.extend_from_slice(&data[pos + 4..data.len() - 4]);
                            result.extend_from_slice(&i.to_le_bytes());
                            
                            return Some(result);
                        }
                    }

                    counter.map(|c| c.fetch_add(range as u64, Ordering::Relaxed));
                    None
                });

            if let Some(tx) = result {
                return tx;
            }

            // I do not think it will overflow
            self.sequence_count += 1;
        }
    }
}
impl Miner for CpuMiner {
    fn name(&self) -> &'static str {
        "CPU"
    }

    fn mine_commit(&mut self, tx: &[u8], bitworkc: BitWork, start: u32, max: Option<u32>) -> Vec<u8> {
        let counter = self.commit_counter.clone();
        self.find_seq_by_range_co(tx, bitworkc, start, max, Some(&counter))
    }

    fn mine_commit_counter(&self) -> Arc<AtomicU64> {
        self.commit_counter.clone()
    }

    fn mine_reveal(&mut self, tx: &[u8], bitworkr: BitWork, start: u64, max: Option<u64>) -> Vec<u8> {
        find_return_nonce_by_range_co(tx, bitworkr, start, max, Some(&self.reveal_counter))
    }

    fn mine_reveal_counter(&self) -> Arc<AtomicU64> {
        self.reveal_counter.clone()
    }
}

pub fn find_return_nonce_by_range_co(
    data: &[u8],
    target: BitWork,
    start: u64,
    max: Option<u64>,
    counter: Option<&AtomicU64>,
) -> Vec<u8> {
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
                        
                        let mut result = vec![];

                        result.extend_from_slice(&data[..pos]);
                        result.extend_from_slice(&i.to_le_bytes());
                        result.extend_from_slice(&data[pos + 8..]);
                        return Some(result); 
                    }
                }

                if let Some(counter) = counter {
                    counter.fetch_add(range as u64, Ordering::Relaxed);
                }
                None
            })
    }).expect("failed to find nonce in u64, crazy")
}

#[cfg(test)]
mod test{
    use crate::miner::cpu::CpuMiner;
    use crate::miner::tests::{mint_commit_by, mint_reveal_by};
    use crate::util::log;

    #[test]
    fn test_commit(){
        log();
        let mut miner = CpuMiner::new();
        mint_commit_by(&mut miner);
    }
    
    #[test]
    fn test_reveal(){
        log();
        let mut miner = CpuMiner::new();
        mint_reveal_by(&mut miner);
    }
    
}