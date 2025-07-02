use core::fmt::Debug;
use core::ops::{Index, IndexMut};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::constants;

#[derive(Copy, Clone)]
pub struct Scalar52(pub [u64; 4]);

impl Debug for Scalar52 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Scalar52: {:?}", &self.0[..])
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Scalar52 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Index<usize> for Scalar52 {
    type Output = u64;
    fn index(&self, _index: usize) -> &u64 {
        &(self.0[_index])
    }
}

impl IndexMut<usize> for Scalar52 {
    fn index_mut(&mut self, _index: usize) -> &mut u64 {
        &mut (self.0[_index])
    }
}

/// u64 * u64 = u128 multiply helper
// 大整数相乘
#[inline(always)]
fn m(x: u64, y: u64) -> u128 {
    (x as u128) * (y as u128)
}

impl Scalar52 {
    /// The scalar \\( 0 \\).
    pub const ZERO: Scalar52 = Scalar52([0, 0, 0, 0]);

    /// 字节转域
    #[rustfmt::skip] // keep alignment of s[*] calculations
    pub fn from_bytes(bytes: &[u8; 32]) -> Scalar52 {
        ffi_sm2_z256_from_bytes(&bytes)
    }

    /// Reduce a 64 byte / 512 bit scalar mod l
    #[rustfmt::skip] // keep alignment of lo[*] and hi[*] calculations
    pub fn from_bytes_wide(bytes: &[u8; 64]) -> Scalar52 {
        let mut words = [0u64; 8];
        for i in 0..8 {
            for j in 0..8 {
                words[i] |= (bytes[(i * 8) + j] as u64) << (j * 8);
            }
        }

        let mask = (1u64 << 52) - 1;
        let mut lo = Scalar52::ZERO;
        let mut hi = Scalar52::ZERO;

        lo[0] =   words[0]                             & mask;
        lo[1] = ((words[0] >> 52) | (words[ 1] << 12)) & mask;
        lo[2] = ((words[1] >> 40) | (words[ 2] << 24)) & mask;
        lo[3] = ((words[2] >> 28) | (words[ 3] << 36)) & mask;
        lo[4] = ((words[3] >> 16) | (words[ 4] << 48)) & mask;
        hi[0] =  (words[4] >>  4)                      & mask;
        hi[1] = ((words[4] >> 56) | (words[ 5] <<  8)) & mask;
        hi[2] = ((words[5] >> 44) | (words[ 6] << 20)) & mask;
        hi[3] = ((words[6] >> 32) | (words[ 7] << 32)) & mask;
        hi[4] =   words[7] >> 20                             ;

        lo = Scalar52::montgomery_mul(&lo, &constants::R);  // (lo * R) / R = lo
        hi = Scalar52::montgomery_mul(&hi, &constants::RR); // (hi * R^2) / R = hi * R

        Scalar52::add(&hi, &lo)
    }

    /// Pack the limbs of this `Scalar52` into 32 bytes
    #[rustfmt::skip] // keep alignment of s[*] calculations
    #[allow(clippy::identity_op)]
    pub fn as_bytes(&self) -> [u8; 32] {
        ffi_sm2_z256_to_bytes(&self)
    }

    /// Compute `a + b` (mod l)
    // 标量模加
    pub fn add(a: &Scalar52, b: &Scalar52) -> Scalar52 {
        ffi_sm2_z256_modn_add(&a, &b)
    }

    /// Compute `a - b` (mod l)
    // 标量模减
    pub fn sub(a: &Scalar52, b: &Scalar52) -> Scalar52 {
        ffi_sm2_z256_modn_sub(&a, &b)
    }
   
    /// Compute `a * b` (mod l)
    // 标量模乘
    #[inline(never)]
    pub fn mul(a: &Scalar52, b: &Scalar52) -> Scalar52 {
        ffi_sm2_z256_modn_mul(&a, &b)
    }

    /// Compute `a^2` (mod l)
    /// 标量模平方
    #[inline(never)]
    #[allow(dead_code)] // XXX we don't expose square() via the Scalar API
    pub fn square(&self) -> Scalar52 {
        ffi_sm2_z256_modn_sqr(&self)
    }

    /// Compute `(a * b) / R` (mod l), where R is the Montgomery modulus 2^260
    /// 蒙哥马利模乘
    #[inline(never)]
    pub fn montgomery_mul(a: &Scalar52, b: &Scalar52) -> Scalar52 {
        let mont_a = ffi_sm2_z256_modn_to_mont(&a);
        let mont_b = ffi_sm2_z256_modn_to_mont(&b);

        let mont_value = ffi_sm2_z256_modn_mont_mul(&mont_a, &mont_b);

        let value = ffi_sm2_z256_modn_from_mont(&mont_value);
        
        Scalar52(value)
        
    }

    /// Compute `(a^2) / R` (mod l) in Montgomery form, where R is the Montgomery modulus 2^260
    // 蒙哥马利模平方
    #[inline(never)]
    pub fn montgomery_square(&self) -> Scalar52 {
        let mont_self = ffi_sm2_z256_modn_to_mont(&self);

        let mont_value = ffi_sm2_z256_modn_mont_sqr(&mont_self);
        let value = ffi_sm2_z256_modn_from_mont(&mont_value);

        Scalar52(value)
    
    }

    /// Puts a Scalar52 in to Montgomery form, i.e. computes `a*R (mod l)`
    #[inline(never)]
    pub fn as_montgomery(&self) -> Scalar52 {
        Scalar52::ffi_sm2_z256_modn_to_mont(&self)
    }

    /// Takes a Scalar52 out of Montgomery form, i.e. computes `a/R (mod l)`
    #[allow(clippy::wrong_self_convention)]
    #[inline(never)]
    pub fn from_montgomery(&self) -> Scalar52 {
        Scalar52::ffi_sm2_z256_modn_from_mont(&self)
    }
}
