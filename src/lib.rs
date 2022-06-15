const P: u32 = 0xb7e15163;
const Q: u32 = 0x9e3779b9;

fn gen_key_table(key: Vec<u8>) -> [u32; 26] {
    let mut s = [0u32; 26];
    let mut l = [0u32; 4];
    for i in (0..15).rev() {
        l[i / 4] = (l[i / 4] << 8).wrapping_add(key[i] as u32);
    }
    s[0] = P;
    for i in 1..26 {
        s[i] = s[i - 1].wrapping_add(Q);
    }
    let (mut a, mut b, mut i, mut j) = (0u32, 0u32, 0usize, 0usize);
    for _ in 0..(3 * 26) {
        s[i] = rotl(s[i].wrapping_add(a).wrapping_add(b), 3);
        a = s[i];
        l[j] = rotl(l[j].wrapping_add(a).wrapping_add(b), a.wrapping_add(b));
        b = l[j];
        i = (i + 1) % 26;
        j = (j + 1) % 4;
    }
    s
}

fn rotl(x: u32, y: u32) -> u32 {
    (x << (y & 31u32)) | x.checked_shr(32u32 - (y & 31u32)).unwrap_or(0)
}

fn rotr(x: u32, y: u32) -> u32 {
    (x >> (y & 31u32)) | x.checked_shl(32u32 - (y & 31u32)).unwrap_or(0)
}

type TranscodeFn = fn((u32, u32), [u32; 26]) -> (u32, u32);

fn compute(input: Vec<u8>, key_table: [u32; 26], fun: TranscodeFn) -> Vec<u8> {
    assert!(input.len() % 8 == 0);
    let mut output = Vec::new();
    for iblock in input.chunks_exact(8) {
        let i0 = u32::from_le_bytes([iblock[0], iblock[1], iblock[2], iblock[3]]);
        let i1 = u32::from_le_bytes([iblock[4], iblock[5], iblock[6], iblock[7]]);
        let (o0, o1) = fun((i0, i1), key_table);
        output.extend(&o0.to_le_bytes());
        output.extend(&o1.to_le_bytes());
    }
    output
}

fn encode_block(plaintext: (u32, u32), key_table: [u32; 26]) -> (u32, u32) {
    let mut a = plaintext.0.wrapping_add(key_table[0]);
    let mut b = plaintext.1.wrapping_add(key_table[1]);
    for i in 1..=12 {
        a = rotl(a ^ b, b).wrapping_add(key_table[2 * i]);
        b = rotl(b ^ a, a).wrapping_add(key_table[2 * i + 1]);
    }
    (a, b)
}

/*
 * This function should return a cipher text for a given key and plaintext
 *
 */
pub fn encode(key: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8> {
    compute(plaintext, gen_key_table(key), encode_block)
}

fn decode_block(ciphertext: (u32, u32), key_table: [u32; 26]) -> (u32, u32) {
    let mut b = ciphertext.1;
    let mut a = ciphertext.0;
    for i in (1..=12).rev() {
        b = rotr(b.wrapping_sub(key_table[2 * i + 1]), a) ^ a;
        a = rotr(a.wrapping_sub(key_table[2 * i]), b) ^ b;
    }
    (a.wrapping_sub(key_table[0]), b.wrapping_sub(key_table[1]))
}

/*
 * This function should return a plaintext for a given key and ciphertext
 *
 */
pub fn decode(key: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
    compute(ciphertext, gen_key_table(key), decode_block)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_a() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ct = vec![0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];
        let res = encode(key, pt);
        assert!(ct[..] == res[..]);
    }

    #[test]
    fn encode_b() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let ct = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
        let res = encode(key, pt);
        assert!(ct[..] == res[..]);
    }

    #[test]
    fn encode_c() {
        let key = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let pt = vec![0, 0, 0, 0, 0, 0, 0, 0];
        let ct = vec![0x21, 0xA5, 0xDB, 0xEE, 0x15, 0x4B, 0x8F, 0x6D];
        let res = encode(key, pt);
        assert!(ct[..] == res[..]);
    }

    #[test]
    fn encode_d() {
        let key = vec![
            0x91, 0x5F, 0x46, 0x19, 0xBE, 0x41, 0xB2, 0x51, 0x63, 0x55, 0xA5, 0x01, 0x10, 0xA9,
            0xCE, 0x91,
        ];
        let pt = vec![0x21, 0xA5, 0xDB, 0xEE, 0x15, 0x4B, 0x8F, 0x6D];
        let ct = vec![0xF7, 0xC0, 0x13, 0xAC, 0x5B, 0x2B, 0x89, 0x52];
        let res = encode(key, pt);
        assert!(ct[..] == res[..]);
    }

    #[test]
    fn decode_a() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
        let ct = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let res = decode(key, ct);
        assert!(pt[..] == res[..]);
    }

    #[test]
    fn decode_b() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = vec![0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
        let ct = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let res = decode(key, ct);
        assert!(pt[..] == res[..]);
    }

    #[test]
    fn decode_c() {
        let key = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let pt = vec![0, 0, 0, 0, 0, 0, 0, 0];
        let ct = vec![0x21, 0xA5, 0xDB, 0xEE, 0x15, 0x4B, 0x8F, 0x6D];
        let res = decode(key, ct);
        assert!(pt[..] == res[..]);
    }
}
