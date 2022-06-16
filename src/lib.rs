use std::{convert::TryFrom, fmt::Debug};

use num::{
    traits::{WrappingAdd, WrappingSub},
    Integer, PrimInt,
};

pub trait MagicConstants {
    fn p() -> Self;
    fn q() -> Self;
}

impl MagicConstants for u16 {
    fn p() -> Self {
        0xb7e1
    }
    fn q() -> Self {
        0x9e37
    }
}

impl MagicConstants for u32 {
    fn p() -> Self {
        0xb7e15163
    }
    fn q() -> Self {
        0x9e3779b9
    }
}

impl MagicConstants for u64 {
    fn p() -> Self {
        0xb7e151628aed2a6b
    }
    fn q() -> Self {
        0x9e3779b97f4a7c15
    }
}

// Idea from https://www.reddit.com/r/rust/comments/g0inzh/is_there_a_pub trait_for_from_le_bytes_from_be_bytes/fn9vbfj/?utm_source=reddit&utm_medium=web2x&context=3

pub trait FromLeBytes<'a> {
    type Bytes: TryFrom<&'a [u8]>;

    fn from_le_bytes(bytes: Self::Bytes) -> Self;
}

impl<'a> FromLeBytes<'a> for u32 {
    type Bytes = [u8; Self::BITS as usize / 8];

    fn from_le_bytes(bytes: Self::Bytes) -> Self {
        Self::from_le_bytes(bytes)
    }
}

pub trait ToLeBytes<'a> {
    type Bytes: AsRef<[u8]>;

    fn to_le_bytes(num: Self) -> Self::Bytes;
}

impl<'a> ToLeBytes<'a> for u32 {
    type Bytes = [u8; 4];

    fn to_le_bytes(num: Self) -> Self::Bytes {
        Self::to_le_bytes(num)
    }
}

pub trait Word<'a>:
    PrimInt + Integer + WrappingAdd + WrappingSub + FromLeBytes<'a> + ToLeBytes<'a> + MagicConstants
where
    <<Self as FromLeBytes<'a>>::Bytes as TryFrom<&'a [u8]>>::Error: Debug,
{
}

impl<
        'a,
        T: PrimInt
            + Integer
            + WrappingAdd
            + WrappingSub
            + FromLeBytes<'a>
            + ToLeBytes<'a>
            + MagicConstants,
    > Word<'a> for T
where
    <<T as FromLeBytes<'a>>::Bytes as TryFrom<&'a [u8]>>::Error: Debug,
{
}

fn gen_key_table<'a, W: Word<'a>>(key: Vec<u8>, rounds: u8) -> Vec<W>
where
    <<W as FromLeBytes<'a>>::Bytes as TryFrom<&'a [u8]>>::Error: Debug,
{
    assert!(key.len() <= 255, "key should be 0 to 255 bytes long");
    let t = 2 * rounds as usize + 2;
    let mut s = vec![W::zero(); t];
    let w = W::zero().count_zeros() as usize;
    let u = w / 8;
    let c = 1.max(Integer::div_ceil(&(key.len() * 8), &w));
    let mut l = vec![W::zero(); c];
    for i in (0..key.len()).rev() {
        l[i / u] = WrappingAdd::wrapping_add(
            &l[i / u].unsigned_shl(8),
            &W::from(key[i]).expect("W is larger than u8"),
        );
    }
    s[0] = W::from(W::p()).expect("P fits in W");
    for i in 1..t {
        s[i] = WrappingAdd::wrapping_add(&s[i - 1], &W::from(W::q()).expect("Q fits in W"));
    }
    let (mut a, mut b, mut i, mut j) = (W::zero(), W::zero(), 0, 0);
    for _ in 0..(3 * t.max(c)) {
        s[i] = WrappingAdd::wrapping_add(&WrappingAdd::wrapping_add(&s[i], &a), &b)
            .rotate_left(3 % w as u32);
        a = s[i];
        l[j] = WrappingAdd::wrapping_add(&WrappingAdd::wrapping_add(&l[j], &a), &b).rotate_left(
            (WrappingAdd::wrapping_add(&a, &b) % W::from(w).expect("w fits in W"))
                .to_u32()
                .expect("a + b % w fits in u32"),
        );
        b = l[j];
        i = (i + 1) % t;
        j = (j + 1) % c;
    }
    s
}

type TranscodeFn<W> = fn((W, W), &[W]) -> (W, W);

fn compute<'a, W: Word<'a>>(input: &'a [u8], key_table: Vec<W>, fun: TranscodeFn<W>) -> Vec<u8>
where
    <<W as FromLeBytes<'a>>::Bytes as TryFrom<&'a [u8]>>::Error: Debug,
{
    let block_bytes = W::zero().count_zeros() as usize / 4;
    assert!(
        input.len() % block_bytes == 0,
        "input should be divisible into {} byte blocks",
        block_bytes
    );
    let mut output = Vec::new();
    for iblock in input.chunks_exact(block_bytes) {
        let (first, second) = iblock.split_at(block_bytes / 2);
        let i0 = W::from_le_bytes(
            <W as FromLeBytes>::Bytes::try_from(first).expect("w == W::Bytes::len()"),
        );
        let i1 = W::from_le_bytes(
            <W as FromLeBytes>::Bytes::try_from(second).expect("w == W::Bytes::len()"),
        );
        let (o0, o1) = fun((i0, i1), &key_table);
        output.extend(W::to_le_bytes(o0).as_ref());
        output.extend(W::to_le_bytes(o1).as_ref());
    }
    output
}

fn encode_block<'a, W: Word<'a>>(plaintext: (W, W), key_table: &[W]) -> (W, W)
where
    <<W as FromLeBytes<'a>>::Bytes as TryFrom<&'a [u8]>>::Error: Debug,
{
    let w = W::from(W::zero().count_zeros()).expect("w fits in W");
    let mut a = WrappingAdd::wrapping_add(&plaintext.0, &key_table[0]);
    let mut b = WrappingAdd::wrapping_add(&plaintext.1, &key_table[1]);
    let rounds = key_table.len() / 2 - 1;

    for i in 1..=rounds {
        a = WrappingAdd::wrapping_add(
            &(a ^ b).rotate_left((b % w).to_u32().expect("b % w fits in u32")),
            &key_table[2 * i],
        );
        b = WrappingAdd::wrapping_add(
            &(b ^ a).rotate_left((a % w).to_u32().expect("a % w fits in u32")),
            &key_table[2 * i + 1],
        );
    }
    (a, b)
}

/*
 * This function should return a cipher text for a given key and plaintext
 *
 */
pub fn encode<'a, W: Word<'a>>(key: Vec<u8>, plaintext: &'a [u8]) -> Vec<u8>
where
    <<W as FromLeBytes<'a>>::Bytes as TryFrom<&'a [u8]>>::Error: Debug,
{
    compute::<W>(plaintext, gen_key_table(key, 12), encode_block)
}

fn decode_block<'a, W: Word<'a>>(ciphertext: (W, W), key_table: &[W]) -> (W, W)
where
    <<W as FromLeBytes<'a>>::Bytes as TryFrom<&'a [u8]>>::Error: Debug,
{
    let w = W::from(W::zero().count_zeros()).expect("w fits in W");
    let mut b = ciphertext.1;
    let mut a = ciphertext.0;
    let rounds = key_table.len() / 2 - 1;
    for i in (1..=rounds).rev() {
        b = WrappingSub::wrapping_sub(&b, &key_table[2 * i + 1])
            .rotate_right((a % w).to_u32().expect("a % w fits in u32"))
            ^ a;
        a = WrappingSub::wrapping_sub(&a, &key_table[2 * i])
            .rotate_right((b % w).to_u32().expect("b % w fits in u32"))
            ^ b;
    }
    (
        WrappingSub::wrapping_sub(&a, &key_table[0]),
        WrappingSub::wrapping_sub(&b, &key_table[1]),
    )
}

/*
 * This function should return a plaintext for a given key and ciphertext
 *
 */
pub fn decode<'a, W: Word<'a>>(key: Vec<u8>, ciphertext: &'a [u8]) -> Vec<u8>
where
    <<W as FromLeBytes<'a>>::Bytes as TryFrom<&'a [u8]>>::Error: Debug,
{
    compute::<W>(ciphertext, gen_key_table(key, 12), decode_block)
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
        let res = encode::<u32>(key, &pt);
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
        let res = encode::<u32>(key, &pt);
        assert!(ct[..] == res[..]);
    }

    #[test]
    fn encode_c() {
        let key = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let pt = vec![0, 0, 0, 0, 0, 0, 0, 0];
        let ct = vec![0x21, 0xA5, 0xDB, 0xEE, 0x15, 0x4B, 0x8F, 0x6D];
        let res = encode::<u32>(key, &pt);
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
        let res = encode::<u32>(key, &pt);
        assert!(ct[..] == res[..]);
    }

    #[test]
    fn encode_e() {
        let key = vec![
            0x78, 0x33, 0x48, 0xE7, 0x5A, 0xEB, 0x0F, 0x2F, 0xD7, 0xB1, 0x69, 0xBB, 0x8D, 0xC1,
            0x67, 0x87,
        ];
        let pt = vec![0xF7, 0xC0, 0x13, 0xAC, 0x5B, 0x2B, 0x89, 0x52];
        let ct = vec![0x2F, 0x42, 0xB3, 0xB7, 0x03, 0x69, 0xFC, 0x92];
        let res = encode::<u32>(key, &pt);
        assert!(ct[..] == res[..]);
    }

    #[test]
    fn encode_f() {
        let key = vec![
            0xDC, 0x49, 0xDB, 0x13, 0x75, 0xA5, 0x58, 0x4F, 0x64, 0x85, 0xB4, 0x13, 0xB5, 0xF1,
            0x2B, 0xAF,
        ];
        let pt = vec![0x2F, 0x42, 0xB3, 0xB7, 0x03, 0x69, 0xFC, 0x92];
        let ct = vec![0x65, 0xC1, 0x78, 0xB2, 0x84, 0xD1, 0x97, 0xCC];
        let res = encode::<u32>(key, &pt);
        assert!(ct[..] == res[..]);
    }

    #[test]
    fn encode_g() {
        let key = vec![
            0x52, 0x69, 0xF1, 0x49, 0xD4, 0x1B, 0xA0, 0x15, 0x24, 0x97, 0x57, 0x4D, 0x7F, 0x15,
            0x31, 0x25,
        ];
        let pt = vec![0x65, 0xC1, 0x78, 0xB2, 0x84, 0xD1, 0x97, 0xCC];
        let ct = vec![0xEB, 0x44, 0xE4, 0x15, 0xDA, 0x31, 0x98, 0x24];
        let res = encode::<u32>(key, &pt);
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
        let res = decode::<u32>(key, &ct);
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
        let res = decode::<u32>(key, &ct);
        assert!(pt[..] == res[..]);
    }

    #[test]
    fn decode_c() {
        let key = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let pt = vec![0, 0, 0, 0, 0, 0, 0, 0];
        let ct = vec![0x21, 0xA5, 0xDB, 0xEE, 0x15, 0x4B, 0x8F, 0x6D];
        let res = decode::<u32>(key, &ct);
        assert!(pt[..] == res[..]);
    }

    #[test]
    fn decode_d() {
        let key = vec![
            0x91, 0x5F, 0x46, 0x19, 0xBE, 0x41, 0xB2, 0x51, 0x63, 0x55, 0xA5, 0x01, 0x10, 0xA9,
            0xCE, 0x91,
        ];
        let pt = vec![0x21, 0xA5, 0xDB, 0xEE, 0x15, 0x4B, 0x8F, 0x6D];
        let ct = vec![0xF7, 0xC0, 0x13, 0xAC, 0x5B, 0x2B, 0x89, 0x52];
        let res = decode::<u32>(key, &ct);
        assert!(pt[..] == res[..]);
    }

    #[test]
    fn decode_e() {
        let key = vec![
            0x78, 0x33, 0x48, 0xE7, 0x5A, 0xEB, 0x0F, 0x2F, 0xD7, 0xB1, 0x69, 0xBB, 0x8D, 0xC1,
            0x67, 0x87,
        ];
        let pt = vec![0xF7, 0xC0, 0x13, 0xAC, 0x5B, 0x2B, 0x89, 0x52];
        let ct = vec![0x2F, 0x42, 0xB3, 0xB7, 0x03, 0x69, 0xFC, 0x92];
        let res = decode::<u32>(key, &ct);
        assert!(pt[..] == res[..]);
    }

    #[test]
    fn decode_f() {
        let key = vec![
            0xDC, 0x49, 0xDB, 0x13, 0x75, 0xA5, 0x58, 0x4F, 0x64, 0x85, 0xB4, 0x13, 0xB5, 0xF1,
            0x2B, 0xAF,
        ];
        let pt = vec![0x2F, 0x42, 0xB3, 0xB7, 0x03, 0x69, 0xFC, 0x92];
        let ct = vec![0x65, 0xC1, 0x78, 0xB2, 0x84, 0xD1, 0x97, 0xCC];
        let res = decode::<u32>(key, &ct);
        assert!(pt[..] == res[..]);
    }

    #[test]
    fn decode_g() {
        let key = vec![
            0x52, 0x69, 0xF1, 0x49, 0xD4, 0x1B, 0xA0, 0x15, 0x24, 0x97, 0x57, 0x4D, 0x7F, 0x15,
            0x31, 0x25,
        ];
        let pt = vec![0x65, 0xC1, 0x78, 0xB2, 0x84, 0xD1, 0x97, 0xCC];
        let ct = vec![0xEB, 0x44, 0xE4, 0x15, 0xDA, 0x31, 0x98, 0x24];
        let res = decode::<u32>(key, &ct);
        assert!(pt[..] == res[..]);
    }
}
