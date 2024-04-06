use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ocl::{Buffer, MemFlags, OclPrm, ProQue};

use crate::miner::{find_first_sequence_position, find_time_nonce_script_position, Miner};
use crate::util::time;
use crate::utils::bitworkc::BitWork;

pub struct GpuMiner {
    commit_counter: Arc<AtomicU64>,
    reveal_counter: Arc<AtomicU64>,
    sequence: u32,
}

const KERNEL_CODE: &str = include_str!("ext/sha256d.cl");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, packed)]
struct HashResult64 {
    found: i32,
    results: [u32; 255],
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
            sequence: 0x80000000,
            commit_counter: Arc::new(AtomicU64::new(0)),
            reveal_counter: Arc::new(AtomicU64::new(0)),
        }
    }
    pub fn find_seq_by_gpu(
        &mut self,
        data: &[u8],
        target: BitWork,
        start: u32,
        max: Option<u32>,
        counter: Option<&AtomicU64>,
    ) -> Vec<u8> {
        self.sequence = 0x80000000;
        let max = max.unwrap_or(time() as u32);
        let pos = find_first_sequence_position(data);
        // change data
        loop {
            let mut new_data = Vec::new();
            new_data.extend_from_slice(&data[..pos]);
            new_data.extend_from_slice(&self.sequence.to_le_bytes());
            new_data.extend_from_slice(&data[pos + 4..]);

            let data = new_data.as_slice();

            let (pro_que, data_buffer, params_buffer, bit_work_buffer) =
                generate_pro_que_params(data, target.clone(), pos as u32);

            let mut output = vec![HashResult::default()];
            let output_buf = Buffer::<HashResult>::builder()
                .queue(pro_que.queue().clone())
                .flags(MemFlags::READ_WRITE)
                .len(output.len())
                .copy_host_slice(&output)
                .build()
                .unwrap();

            let range = 1 << 24;
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
                    .kernel_builder("sha256d_append")
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
                    let time_lock = output.results[0];
                    let mut result = vec![];
                    result.extend_from_slice(&data[..data.len() - 4]);
                    result.extend_from_slice(&time_lock.to_le_bytes());

                    return result;
                };
                offset += size;
            }

            self.sequence += 1;
        }
    }
}
impl Miner for GpuMiner {
    fn name(&self) -> &'static str {
        "GPU"
    }

    fn mine_commit(
        &mut self,
        tx: &[u8],
        bitworkc: BitWork,
        start: u32,
        max: Option<u32>,
    ) -> Vec<u8> {
        let counter = self.commit_counter.clone();
        self.find_seq_by_gpu(tx, bitworkc, start, max, Some(&counter))
    }

    fn mine_commit_counter(&self) -> Arc<AtomicU64> {
        self.commit_counter.clone()
    }

    fn mine_reveal(
        &mut self,
        tx: &[u8],
        bitworkr: BitWork,
        start: u64,
        max: Option<u64>,
    ) -> Vec<u8> {
        find_return_nonce_by_gpu(tx, bitworkr, start, max, Some(&self.reveal_counter))
    }

    fn mine_reveal_counter(&self) -> Arc<AtomicU64> {
        self.reveal_counter.clone()
    }
}

pub fn find_return_nonce_by_gpu(
    data: &[u8],
    target: BitWork,
    start: u64,
    max: Option<u64>,
    counter: Option<&AtomicU64>,
) -> Vec<u8> {
    let max = max.unwrap_or(u64::MAX);
    let pos = find_time_nonce_script_position(data) as u32;

    let range = 10000000;
    let mut offset = start;

    let (pro_que, data_buffer, params_buffer, bit_work_buffer) =
        generate_pro_que_params(data, target, pos);

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
        
        let kernel = pro_que
            .kernel_builder("sha256d_64")
            .arg(&data_buffer)
            .arg(&params_buffer)
            .arg(&bit_work_buffer)
            .arg(offset)
            .arg(&output_buf)
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
            let output_data = output.results[0] as u64 + offset;
            let mut result = vec![];
            result.extend_from_slice(&data[..pos as usize]);
            result.extend_from_slice(&output_data.to_le_bytes());
            result.extend_from_slice(&data[pos as usize + 8..]);

            return result;
        };
        offset += size;
    }

    panic!("not found in u64, crazy");
}

pub fn generate_pro_que_params(
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

    (pro_que, data_buffer, params_buffer, bit_work_buffer)
}

#[cfg(test)]
mod tests {
    use tracing::info;

    use crate::miner::tests::{mint_commit_by, mint_reveal_by};
    use crate::util::log;

    use super::*;

    #[test]
    fn test_commit() {
        log();
        let mut miner = GpuMiner::new();
        mint_commit_by(&mut miner);
    }

    #[test]
    fn test_reveal() {
        log();
        info!("start");
        let mut miner = GpuMiner::new();
        mint_reveal_by(&mut miner);
    }
}
