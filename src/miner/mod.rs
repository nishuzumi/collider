use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use bitcoin::opcodes::all::OP_RETURN;
use log::info;

use crate::util::GLOBAL_OPTS;
use crate::utils::bitworkc::BitWork;

pub mod cpu;
pub mod gpu;
#[cfg(feature = "op_sha256")]
pub mod op_sha256_gpu; 

pub trait Miner {
    fn name(&self) -> &'static str;
    fn mine_commit(
        &mut self,
        tx: &[u8],
        bitworkc: BitWork,
        start: u32,
        max: Option<u32>,
    ) -> Vec<u8>;

    fn mine_commit_counter(&self) -> Arc<AtomicU64>;

    fn mine_reveal(
        &mut self,
        tx: &[u8],
        bitworkr: BitWork,
        start: u64,
        max: Option<u64>,
    ) -> Vec<u8>;

    fn mine_reveal_counter(&self) -> Arc<AtomicU64>;
}
pub fn create_miner() -> Box<dyn Miner> {
    match GLOBAL_OPTS.miner.as_str() {
        "cpu" => Box::new(cpu::CpuMiner::new()),
        "gpu" => Box::new(gpu::GpuMiner::new()),
        _ => {
            panic!("Invalid miner type: {}", GLOBAL_OPTS.miner);
        }
    }
}
pub fn find_first_sequence_position(serialized_tx: &[u8]) -> usize {
    let mut offset = 0;
    // skip the version number (4 bytes)
    offset += 4;
    // get the number of inputs (assume it's a small varint, i.e. 1 byte)
    let input_count = serialized_tx[offset] as usize;
    offset += 1;
    if input_count == 0 {
        panic!("Cannot find sequence number in a transaction with no inputs.");
    }
    // foreach input
    // skip the previous transaction hash (32 bytes) and output index (4 bytes)
    offset += 32 + 4;
    // parse the script length (assume it's a small varint, i.e. 1 byte)
    let script_length = serialized_tx[offset] as usize;
    offset += 1;
    // skip the script and the sequence number
    offset += script_length;
    // offset is now at the beginning of the sequence number
    offset
}
pub fn find_time_nonce_script_position(serialized_tx: &[u8]) -> usize {
    info!(
        "find_time_nonce_script_position, serialized_tx: {:?}",
        hex::encode(serialized_tx)
    );
    let mut offset = 0;
    // skip the version number (4 bytes)
    offset += 4;
    // parse the number of inputs (variable length)
    let (input_count, input_count_len) = parse_varint(&serialized_tx[offset..]);
    offset += input_count_len;
    // foreach input
    for _ in 0..input_count {
        // skip the previous output hash (32 bytes)
        offset += 32;
        // skip the previous output index (4 bytes)
        offset += 4;
        // parse the script length (variable length)
        let (script_length, script_length_len) = parse_varint(&serialized_tx[offset..]);
        offset += script_length_len;
        // skip the script
        offset += script_length as usize;
        // skip the sequence number (4 bytes)
        offset += 4;
    }
    // parse the number of outputs (variable length)
    let (output_count, output_count_len) = parse_varint(&serialized_tx[offset..]);
    offset += output_count_len;
    // foreach output
    for _ in 0..output_count {
        // skip the value (8 bytes)
        offset += 8;
        // parse the script length (variable length)
        let (script_length, script_length_len) = parse_varint(&serialized_tx[offset..]);
        offset += script_length_len;
        // check if the script matches the time_nonce_script pattern
        if serialized_tx[offset] == OP_RETURN.to_u8() {
            offset += 1;
            if serialized_tx[offset] == 8 {
                // found the time_nonce_script
                return offset + 1;
            }
        }
        // skip the script
        offset += script_length as usize;
    }
    offset
}
fn parse_varint(data: &[u8]) -> (u64, usize) {
    let first_byte = data[0];
    if first_byte < 0xfd {
        (first_byte as u64, 1)
    } else if first_byte == 0xfd {
        (u16::from_le_bytes([data[1], data[2]]) as u64, 3)
    } else if first_byte == 0xfe {
        (
            u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as u64,
            5,
        )
    } else {
        (
            u64::from_le_bytes([
                data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
            ]),
            9,
        )
    }
}
struct StepByIterator {
    start: u64,
    end: u64,
    step: u64,
}

impl Iterator for StepByIterator {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        if self.start < self.end {
            let current = self.start;
            self.start += self.step;
            Some(current)
        } else {
            None
        }
    }
}
#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering::SeqCst;
    use std::time::Instant;

    use bitcoin::consensus::deserialize;
    use tracing::info;

    use crate::miner::Miner;
    use crate::utils::bitworkc::BitWork;

    pub fn mint_commit_by(miner:&mut impl Miner){
        let tx = "01000000012a912f654cc1bd88da5b8a54c52b6dd60b6e831bfba52b32c1314cd17c5634120100000000feffffff024c05000000000000225120e3d5a4789dc4982cfda563c8c23f988f505e481bf9602f7ba5b1045e44e0392000b09a3b0000000022512032447fe28750a7e2b18af49d89a359a81c69bbf6f3db05feb7e8e1688f37e4c200000000";
        let tx = hex::decode(tx).unwrap();
        let bitwork = BitWork::new("88888888.11".to_string()).unwrap();

        let now = Instant::now();
        let commit_count = miner.mine_commit_counter().clone();
        let tx_raw = miner.mine_commit(&tx, bitwork, 0, None);

        let commit_count = commit_count.load(SeqCst);
        info!("duration:{:?}, count:{:?}", now.elapsed(), commit_count);

        let tx: bitcoin::Transaction = deserialize(tx_raw.as_slice()).unwrap();
        println!("{}", tx.txid());
    }
    
    pub fn mint_reveal_by(miner:&mut impl Miner){
        let tx = "01000000017b7afa047d43cb34409d453e11fc048314dd2ee58a5b20c1b0f6a8077b5634120000000000fdffffff02e803000000000000225120adb58bdbccaa9fdd6594859354b502214e3405a74d772a60e255e233468c4c7900000000000000000a6a08000000000000000100000000";
        let tx = hex::decode(tx).unwrap();
        let bitwork = BitWork::new("12345688".to_string()).unwrap();

        let now = Instant::now();
        let reveal_count = miner.mine_reveal_counter().clone();
        let reveal_tx = miner.mine_reveal(&tx, bitwork, 0, None);

        let reveal_count = reveal_count.load(SeqCst);
        info!("duration:{:?}, count:{:?}", now.elapsed(), reveal_count);

        let tx: bitcoin::Transaction = deserialize(reveal_tx.as_slice()).unwrap();
        println!("{}", tx.txid())
    }
    
}
