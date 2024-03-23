use eyre::{eyre, Result};

#[derive(Clone, Debug)]
pub struct Ext {
    pub value: u8,
    pub pos: u8,
}
#[derive(Clone, Debug)]
pub struct BitWork {
    pub raw: String,
    pub mask: [u8; 32],
    pub pattern: [u8; 32],
    pub ext: Option<Ext>,
}

impl BitWork {
    pub fn new(raw_hex_str: String) -> Result<Self> {
        let mut ext = None;
        let mut hex_str = raw_hex_str.clone();
        if raw_hex_str.contains('.') {
            let parts: Vec<&str> = raw_hex_str.split('.').collect();
            hex_str = parts[0].to_string();
            let hex_str_len = hex_str.len();

            let mut ext_num = parts[1].parse().expect("Bitworkc ext parse error");
            // offset the pos
            if hex_str_len % 2 == 0 {
                // hex_str_len -= 1;
                ext_num <<= 4;
            } else {
                ext_num += hex_str[hex_str_len - 1..].parse::<u8>().unwrap() << 4;
            }

            ext = Some(Ext {
                value: ext_num,
                pos: (hex_str_len / 2) as u8,
            });
        }

        if hex_str.len() > 64 {
            return Err(eyre!("Hex string too long"));
        }

        let mut pattern = [0u8; 32];
        let mut mask = [0u8; 32];

        for (i, c) in hex_str.chars().enumerate() {
            let digit = c.to_digit(16).ok_or(eyre!("Invalid hex character"))?;
            let byte_index = 31 - i / 2;
            if i % 2 == 0 {
                pattern[byte_index] |= (digit as u8) << 4;
                mask[byte_index] |= 0xF0;
            } else {
                pattern[byte_index] |= digit as u8;
                mask[byte_index] |= 0x0F;
            }
        }

        Ok(BitWork {
            raw: raw_hex_str,
            mask,
            pattern,
            ext,
        })
    }

    pub fn matches(&self, data: &[u8]) -> bool {
        if data.len() < 32 {
            return false;
        }

        for (index, word) in data.iter().enumerate() {
            let mask = self.mask[index];
            let pattern = self.pattern[index];
            if (word & mask) != pattern {
                return false;
            }
        }
        // if is inf
        if let Some(Ext { value, pos }) = self.ext.clone() {
            return data[31 - pos as usize] >= value;
        }

        true
    }
}

#[cfg(test)]
mod test {
    use crate::util::log;

    use super::*;

    #[test]
    fn test_bitworkc() {
        let bitworkc = BitWork::new("aabbccd".to_string()).unwrap();
        println!("{:?}", bitworkc);
    }

    #[test]
    fn test_mask() {
        let matcher = BitWork::new("aabbccd".to_string()).unwrap();
        let patten = [0xd4, 0xcc, 0xbb, 0xaa];
        let mut data = vec![0; 32];
        let len = 32;
        data[len - 4] = patten[0];
        data[len - 3] = patten[1];
        data[len - 2] = patten[2];
        data[len - 1] = patten[3];

        assert!(matcher.matches(&data));
    }

    #[test]
    fn test_inf_mask() {
        let matcher = BitWork::new("9999.12".to_string()).unwrap();
        {
            let mut data = vec![0; 32];
            let len = 32;
            data[len - 3] = 0x11;
            data[len - 2] = 0x99;
            data[len - 1] = 0x99;

            assert!(!matcher.matches(&data))
        }
        {
            let mut data = vec![0; 32];
            let len = 32;
            data[len - 3] = 0xc0;
            data[len - 2] = 0x99;
            data[len - 1] = 0x99;

            assert!(matcher.matches(&data))
        }
    }

    #[test]
    fn test_inf_mask_2() {
        let matcher = BitWork::new("99999.12".to_string()).unwrap();
        {
            let mut data = vec![0; 32];
            let len = 32;
            data[len - 3] = 0x11;
            data[len - 2] = 0x99;
            data[len - 1] = 0x99;

            assert!(!matcher.matches(&data))
        }
        {
            let mut data = vec![0; 32];
            let len = 32;
            data[len - 3] = 0x9c;
            data[len - 2] = 0x99;
            data[len - 1] = 0x99;

            assert!(matcher.matches(&data))
        }
    }

    #[test]
    fn test_inf_mask_3() {
        log();
        // 1234567.11
        let matcher = BitWork::new("1234567.11".to_string()).unwrap();
        {
            let mut data = vec![0; 32];
            let len = 32;

            data[len - 4] = 0x79;
            data[len - 3] = 0x56;
            data[len - 2] = 0x34;
            data[len - 1] = 0x12;

            assert!(!matcher.matches(&data))
        }
    }
}
