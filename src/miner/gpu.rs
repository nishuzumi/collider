use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bitcoin::Sequence;
use ocl::{Buffer, MemFlags, OclPrm, ProQue};
use rayon::prelude::*;

use crate::miner::{find_first_sequence_position, find_time_nonce_script_position, Miner};
use crate::utils::bitworkc::BitWork;

pub struct GpuMiner {
    commit_counter: Arc<AtomicU64>,
    reveal_counter: Arc<AtomicU64>,
}

const KERNEL_CODE: &str = include_str!("ext/sha256d.cl");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, packed)]
struct HashResult64 {
    found: i32,
    results: [u64; 255],
}

impl Default for HashResult64 {
    fn default() -> Self {
        HashResult64 {
            found: 0,
            results: [0; 255],
        }
    }
}
unsafe impl OclPrm for HashResult64 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, packed)]
struct HashResult {
    found: i32,
    results: [u32; 255],
}

impl Default for HashResult {
    fn default() -> Self {
        HashResult {
            found: 0,
            results: [0; 255],
        }
    }
}
unsafe impl OclPrm for HashResult {}

#[derive(Default, Clone, Debug, Copy, PartialEq, Eq)]
#[repr(C, packed)]
pub struct BitWorkForGPU {
    pub mask: [u8; 32],
    pub pattern: [u8; 32],
    pub ext: bool,
    pub ext_pos: u8,
    pub ext_value: u8,
}
unsafe impl OclPrm for BitWorkForGPU {}

#[derive(Default, Clone, Debug, Copy, PartialEq, Eq)]
#[repr(C, packed)]
pub struct Params {
    pub data_len: u32,
    pub pos: u32,
}
unsafe impl OclPrm for Params {}

impl GpuMiner {
    pub fn new() -> GpuMiner {
        GpuMiner {
            commit_counter: Arc::new(AtomicU64::new(0)),
            reveal_counter: Arc::new(AtomicU64::new(0)),
        }
    }
}
impl Miner for GpuMiner {
    fn mine_commit(
        &self,
        tx: &[u8],
        bitworkc: BitWork,
        start: u32,
        max: Option<u32>,
    ) -> Option<u32> {
        find_seq_by_gpu(tx, bitworkc, start, max, Some(&self.commit_counter))
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
        find_return_nonce_by_gpu(tx, bitworkr, start, max, Some(&self.reveal_counter))
    }

    fn mine_reveal_counter(&self) -> Arc<AtomicU64> {
        self.reveal_counter.clone()
    }
}
pub fn find_seq_by_gpu(
    data: &[u8],
    target: BitWork,
    start: u32,
    max: Option<u32>,
    counter: Option<&AtomicU64>,
) -> Option<u32> {
    let max = max.unwrap_or(Sequence::ENABLE_LOCKTIME_NO_RBF.0);
    let pos = find_first_sequence_position(data) as u32;

    let (pro_que, data_buffer, params_buffer, bit_work_buffer) =
      generate_pro_que_params("sha256d".to_string(), data, target, pos);

    let mut output = vec![HashResult::default()];
    let output_buf = Buffer::<HashResult>::builder()
        .queue(pro_que.queue().clone())
        .flags(MemFlags::READ_WRITE)
        .len(output.len())
        .copy_host_slice(&output)
        .build()
        .unwrap();

    let range = 10000000u32;
    let mut offset = start;
    while offset < max {
        let result = offset.checked_add(range);
        let size = if result.is_none() || result.unwrap() > max {
            max - offset
        } else {
            range
        };
        // let size = 1;
        let kernel = pro_que
            .kernel_builder("sha256d")
            .arg(&data_buffer)
            .arg(&params_buffer)
            .arg(&bit_work_buffer)
            .arg(&output_buf)
            .global_work_offset(offset)
            .global_work_size(size)
            .build()
            .unwrap();

        unsafe {
            kernel.enq().unwrap();
        }

        output_buf.read(&mut output).enq().unwrap();

        counter.map(|c| c.fetch_add(size as u64, Ordering::Relaxed));

        let output = output[0];
        if output.found > 0 {
            return Some(output.results[0]);
        };
        offset += size;
    }
    None
}

pub fn find_return_nonce_by_gpu(
    data: &[u8],
    target: BitWork,
    start: u64,
    max: Option<u64>,
    counter: Option<&AtomicU64>,
) -> Option<u64> {
    let max = max.unwrap_or(u64::MAX);
    let pos = find_time_nonce_script_position(data) as u32;

    let range = 10000000;
    let mut offset = start;

    let (pro_que, data_buffer, params_buffer, bit_work_buffer) =
        generate_pro_que_params("sha256d_64".to_string(), data, target, pos);

    let mut output = vec![HashResult64::default()];
    let output_buf = Buffer::<HashResult64>::builder()
        .queue(pro_que.queue().clone())
        .flags(MemFlags::READ_WRITE)
        .len(output.len())
        .copy_host_slice(&output)
        .build()
        .unwrap();

    while offset < max {
        let result = offset.checked_add(range);
        let size = if result.is_none() || result.unwrap() > max {
            max - offset
        } else {
            range
        };
        // let size = 1;
        let kernel = pro_que
            .kernel_builder("sha256d_64")
            .arg(&data_buffer)
            .arg(&params_buffer)
            .arg(&bit_work_buffer)
            .arg(&output_buf)
            .global_work_offset(offset as usize)
            .global_work_size(size as usize)
            .build()
            .unwrap();

        unsafe {
            kernel.enq().unwrap();
        }

        output_buf.read(&mut output).enq().unwrap();

        counter.map(|c| c.fetch_add(size, Ordering::Relaxed));

        let output = output[0];
        if output.found > 0 {
            return Some(output.results[0]);
        };
        offset += size;
    }
    None
}

pub fn generate_pro_que_params(
    func: String,
    data: &[u8],
    target: BitWork,
    pos: u32,
) -> (ProQue, Buffer<u8>, Buffer<Params>, Buffer<BitWorkForGPU>) {
    let pro_que = ProQue::builder().src(KERNEL_CODE).build().unwrap();

    let data_buffer = Buffer::builder()
        .queue(pro_que.queue().clone())
        .flags(MemFlags::READ_ONLY)
        .len(data.len())
        .copy_host_slice(data)
        .build()
        .unwrap();
    // 创建 Params buffer
    let params_buffer = Buffer::builder()
        .queue(pro_que.queue().clone())
        .flags(MemFlags::READ_ONLY)
        .len(1)
        .copy_host_slice(&[Params {
            data_len: data.len() as u32,
            pos,
        }])
        .build()
        .unwrap();

    // 创建 BitWorkForGPU buffer
    let bit_work_buffer = Buffer::builder()
        .queue(pro_que.queue().clone())
        .flags(MemFlags::READ_ONLY)
        .len(1)
        .copy_host_slice(&[BitWorkForGPU {
            mask: target.mask,
            pattern: target.pattern,
            ext: target.ext.is_some(),
            ext_pos: target.ext.clone().map(|e| e.pos).unwrap_or(0),
            ext_value: target.ext.map(|e| e.value).unwrap_or(0),
        }])
        .build()
        .unwrap();

    return (pro_que, data_buffer, params_buffer, bit_work_buffer);
}

#[cfg(test)]
mod tests {
    use std::hash::Hash;
    use std::sync::atomic::Ordering;
    use std::time::Instant;

    use bitcoin::consensus::{deserialize, Encodable};
    use bitcoin::secp256k1;
    use tracing::info;

    use crate::miner::cpu::CpuMiner;
    use crate::util::{log, time_nonce_script};
    use crate::utils::bitworkc::BitWork;

    use super::*;

    #[test]
    fn test_find_seq_by_gpu() {
        log();
        let tx = "01000000012a912f654cc1bd88da5b8a54c52b6dd60b6e831bfba52b32c1314cd17c5634120100000000feffffff024c05000000000000225120e3d5a4789dc4982cfda563c8c23f988f505e481bf9602f7ba5b1045e44e0392000b09a3b0000000022512032447fe28750a7e2b18af49d89a359a81c69bbf6f3db05feb7e8e1688f37e4c200000000";
        let tx = hex::decode(tx).unwrap();
        let miner = GpuMiner::new();
        let bitwork = BitWork::new("1234567.11".to_string()).unwrap();

        let now = Instant::now();
        let nonce = miner.mine_commit(&tx, bitwork, 0, None);

        let mut tx: bitcoin::Transaction = deserialize(&tx).unwrap();
        tx.input[0].sequence = Sequence(nonce.unwrap());

        let mut serialize = vec![];
        tx.consensus_encode(&mut serialize).unwrap();

        info!("reveal: {:?}", tx.txid());

        info!(
            "nonce:{:?}, duration:{:?}, count:{:?}",
            nonce,
            now.elapsed(),
            miner.mine_commit_counter().load(Ordering::Relaxed)
        );
    }

    #[tokio::test]
    async fn test_reveal_work() {
        log();
        let tx = "01000000017b7afa047d43cb34409d453e11fc048314dd2ee58a5b20c1b0f6a8077b5634120000000000fdffffff02e803000000000000225120adb58bdbccaa9fdd6594859354b502214e3405a74d772a60e255e233468c4c7900000000000000000a6a08000000000000000100000000";
        let tx = hex::decode(tx).unwrap();
        let miner = GpuMiner::new();
        let bitwork = BitWork::new("1234567.11".to_string()).unwrap();
        let secp = bitcoin::secp256k1::Secp256k1::new();

        let now = tokio::time::Instant::now();
        let nonce = miner.mine_reveal(&tx, bitwork, 0, None);

        info!(
            "nonce:{:?}, duration:{:?}, count:{:?}",
            nonce,
            now.elapsed(),
            miner.mine_reveal_counter().load(Ordering::Relaxed)
        );
        let mut tx: bitcoin::Transaction = deserialize(&tx).unwrap();
        tx.output[1].script_pubkey = time_nonce_script(nonce.unwrap());
        info!("tx:{:?}", tx);

        let mut serialize = vec![];
        tx.consensus_encode(&mut serialize).unwrap();
        info!("reveal: {:?}", hex::encode(serialize));
        info!("txid:{}", tx.txid());
    }
}
