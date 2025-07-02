
#![cfg_attr(feature = "digest", doc = "```")]
#![cfg_attr(not(feature = "digest"), doc = "```ignore")]

use core::borrow::Borrow;
use core::fmt::Debug;
use core::iter::{Product, Sum};
use core::ops::Index;
use core::ops::Neg;
use core::ops::{Add, AddAssign};
use core::ops::{Mul, MulAssign};
use core::ops::{Sub, SubAssign};

use cfg_if::cfg_if;

#[cfg(feature = "group")]
use group::ff::{Field, FromUniformBytes, PrimeField};
#[cfg(feature = "group-bits")]
use group::ff::{FieldBits, PrimeFieldBits};

#[cfg(any(test, feature = "group"))]
use rand_core::RngCore;

#[cfg(any(test, feature = "rand_core"))]
use rand_core::CryptoRngCore;

#[cfg(feature = "digest")]
use digest::generic_array::typenum::U64;
#[cfg(feature = "digest")]
use digest::Digest;

use subtle::Choice;
use subtle::ConditionallySelectable;
use subtle::ConstantTimeEq;
use subtle::CtOption;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::backend;
use crate::constants;
pub(crate) type UnpackedScalar = backend::serial::u64::scalar::Scalar52;


#[allow(clippy::derived_hash_with_manual_eq)]
#[derive(Copy, Clone, Hash)]
pub struct Scalar {
    pub(crate) bytes: [u8; 32],
}

impl Scalar {
    /// Construct a `Scalar` by reducing a 256-bit little-endian integer
    /// modulo the group order \\( \ell \\).
    // 把一个 256 位（32 字节）的小端字节数组，转成一个合法的标量（Scalar），其值等于输入对群阶（\\( \ell \\)）取模的结果。
    pub fn from_bytes_mod_order(bytes: [u8; 32]) -> Scalar {
        // Temporarily allow s_unreduced.bytes > 2^255 ...
        let s_unreduced = Scalar { bytes };

        // Then reduce mod the group order and return the reduced representative.
        let s = s_unreduced.reduce();
        debug_assert_eq!(0u8, s[31] >> 7);

        s
    }

    // !!!
    pub fn from_bytes_mod_order_wide(input: &[u8; 64]) -> Scalar {
        UnpackedScalar::from_bytes_wide(input).pack()
    }

    // 基于时序的XXX
    pub fn from_canonical_bytes(bytes: [u8; 32]) -> CtOption<Scalar> {
        let high_bit_unset = (bytes[31] >> 7).ct_eq(&0);
        let candidate = Scalar { bytes };
        CtOption::new(candidate, high_bit_unset & candidate.is_canonical())
    }

}

impl Debug for Scalar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Scalar{{\n\tbytes: {:?},\n}}", &self.bytes)
    }
}

impl Eq for Scalar {}
impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl Index<usize> for Scalar {
    type Output = u8;

    /// Index the bytes of the representative for this `Scalar`.  Mutation is not permitted.
    fn index(&self, _index: usize) -> &u8 {
        &(self.bytes[_index])
    }
}

// *=
// 不用改，基于Scalar52的运算
impl<'b> MulAssign<&'b Scalar> for Scalar {
    fn mul_assign(&mut self, _rhs: &'b Scalar) {
        *self = UnpackedScalar::mul(&self.unpack(), &_rhs.unpack()).pack();
    }
}

define_mul_assign_variants!(LHS = Scalar, RHS = Scalar);

// *
// 不用改，基于Scalar52的运算
impl<'a, 'b> Mul<&'b Scalar> for &'a Scalar {
    type Output = Scalar;
    fn mul(self, _rhs: &'b Scalar) -> Scalar {
        UnpackedScalar::mul(&self.unpack(), &_rhs.unpack()).pack()
    }
}

define_mul_variants!(LHS = Scalar, RHS = Scalar, Output = Scalar);

// +=
impl<'b> AddAssign<&'b Scalar> for Scalar {
    fn add_assign(&mut self, _rhs: &'b Scalar) {
        *self = *self + _rhs;
    }
}

define_add_assign_variants!(LHS = Scalar, RHS = Scalar);

// +
// 不用改，基于Scalar52的运算
impl<'a, 'b> Add<&'b Scalar> for &'a Scalar {
    type Output = Scalar;
    #[allow(non_snake_case)]
    fn add(self, _rhs: &'b Scalar) -> Scalar {
        UnpackedScalar::add(&self.unpack(), &_rhs.unpack()).pack()
    }
}

define_add_variants!(LHS = Scalar, RHS = Scalar, Output = Scalar);

// -=
impl<'b> SubAssign<&'b Scalar> for Scalar {
    fn sub_assign(&mut self, _rhs: &'b Scalar) {
        *self = *self - _rhs;
    }
}

define_sub_assign_variants!(LHS = Scalar, RHS = Scalar);

// -
// 不用改，基于Scalar52的运算
impl<'a, 'b> Sub<&'b Scalar> for &'a Scalar {
    type Output = Scalar;
    #[allow(non_snake_case)]
    fn sub(self, rhs: &'b Scalar) -> Scalar {
        UnpackedScalar::sub(&self.unpack(), &rhs.unpack()).pack()
    }
}

define_sub_variants!(LHS = Scalar, RHS = Scalar, Output = Scalar);

impl<'a> Neg for &'a Scalar {
    type Output = Scalar;
    #[allow(non_snake_case)]
    fn neg(self) -> Scalar {
        // let self_R = UnpackedScalar::mul_internal(&self.unpack(), &constants::R);
        // let self_mod_l = UnpackedScalar::montgomery_reduce(&self_R);
        // UnpackedScalar::sub(&UnpackedScalar::ZERO, &self_mod_l).pack()

        // 转字节
        let unpack_self: [u64; 4] = self.unpack();

        // 进蒙哥马利
        let mont_self = ffi_sm2_z256_modn_to_mont(&unpack_self);
        // 取反!!!
        let mont_neg = ffi_sm2_z256_modn_neg(&mont_self);
        // 转Scalar
        Scalar52(mont_neg).pack()
    }
}

impl Neg for Scalar {
    type Output = Scalar;
    fn neg(self) -> Scalar {
        -&self
    }
}

// 常量时间的条件选择，防时序攻击
impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut bytes = [0u8; 32];
        #[allow(clippy::needless_range_loop)]
        for i in 0..32 {
            bytes[i] = u8::conditional_select(&a.bytes[i], &b.bytes[i], choice);
        }
        Scalar { bytes }
    }
}

// RUST trait，迭代操作
impl<T> Product<T> for Scalar
where
    T: Borrow<Scalar>,
{
    fn product<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(Scalar::ONE, |acc, item| acc * item.borrow())
    }
}

impl<T> Sum<T> for Scalar
where
    T: Borrow<Scalar>,
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(Scalar::ZERO, |acc, item| acc + item.borrow())
    }
}

impl Default for Scalar {
    fn default() -> Scalar {
        Scalar::ZERO
    }
}

// 把小整数转成大整数标量
impl From<u8> for Scalar {
    fn from(x: u8) -> Scalar {
        let mut s_bytes = [0u8; 32];
        s_bytes[0] = x;
        Scalar { bytes: s_bytes }
    }
}

impl From<u16> for Scalar {
    fn from(x: u16) -> Scalar {
        let mut s_bytes = [0u8; 32];
        let x_bytes = x.to_le_bytes();
        s_bytes[0..x_bytes.len()].copy_from_slice(&x_bytes);
        Scalar { bytes: s_bytes }
    }
}

impl From<u32> for Scalar {
    fn from(x: u32) -> Scalar {
        let mut s_bytes = [0u8; 32];
        let x_bytes = x.to_le_bytes();
        s_bytes[0..x_bytes.len()].copy_from_slice(&x_bytes);
        Scalar { bytes: s_bytes }
    }
}

impl From<u64> for Scalar {

    fn from(x: u64) -> Scalar {
        let mut s_bytes = [0u8; 32];
        let x_bytes = x.to_le_bytes();
        s_bytes[0..x_bytes.len()].copy_from_slice(&x_bytes);
        Scalar { bytes: s_bytes }
    }
}

impl From<u128> for Scalar {
    fn from(x: u128) -> Scalar {
        let mut s_bytes = [0u8; 32];
        let x_bytes = x.to_le_bytes();
        s_bytes[0..x_bytes.len()].copy_from_slice(&x_bytes);
        Scalar { bytes: s_bytes }
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Scalar {
    // 标量0
    pub const ZERO: Self = Self { bytes: [0u8; 32] };

    // 标量1
    // !!!
    pub const ONE: Self = Self {
        bytes: [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
    };

    #[cfg(any(test, feature = "rand_core"))]
    
    // !!!
    pub fn random<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        let mut scalar_bytes = [0u8; 64];
        rng.fill_bytes(&mut scalar_bytes);
        Scalar::from_bytes_mod_order_wide(&scalar_bytes)
    }

    #[cfg(feature = "digest")]
    #[cfg_attr(feature = "digest", doc = "```")]
    #[cfg_attr(not(feature = "digest"), doc = "```ignore")]
    // 没有用
    pub fn hash_from_bytes<D>(input: &[u8]) -> Scalar
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let mut hash = D::default();
        hash.update(input);
        Scalar::from_hash(hash)
    }

    #[cfg(feature = "digest")]
    // 先不管它，只有上层sig\ver中调用了 
    pub fn from_hash<D>(hash: D) -> Scalar
    where
        D: Digest<OutputSize = U64>,
    {
        let mut output = [0u8; 64];
        output.copy_from_slice(hash.finalize().as_slice());
        Scalar::from_bytes_mod_order_wide(&output)
    }

  
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }


    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    // 乘法逆
    pub fn invert(&self) -> Scalar {
        self.unpack().invert().pack()
    }
    
    pub(crate) fn unpack(&self) -> UnpackedScalar {
        UnpackedScalar::from_bytes(&self.bytes)
    }

    // !!!
    #[allow(non_snake_case)]
    fn reduce(&self) -> Scalar {
        let mont_self = ffi_sm2_z256_modn_to_mont(&self.bytes);
        let reduce_self = ffi_sm2_z256_modn_from_mont(&mont_self);
        reduce_self.pack()
    }

    fn is_canonical(&self) -> Choice {
        self.ct_eq(&self.reduce())
    }
}

impl UnpackedScalar {
    /// Pack the limbs of this `UnpackedScalar` into a `Scalar`.
    fn pack(&self) -> Scalar {
        Scalar {
            bytes: self.as_bytes(),
        }
    }

    /// Inverts an UnpackedScalar in Montgomery form.
    #[rustfmt::skip] // keep alignment of addition chain and squarings
    #[allow(clippy::just_underscores_and_digits)]
    pub fn montgomery_invert(&self) -> UnpackedScalar {
        
        let mont_self = ffi_sm2_z256_modn_to_mont(&self);
        // 标量 蒙哥马利模逆
        let mont_inv = ff_sm2_z256_modn_mont_inv(&mont_self);
        
        mont_inv
    }

    /// Inverts an UnpackedScalar not in Montgomery form.
    pub fn invert(&self) -> UnpackedScalar {
        self.as_montgomery().montgomery_invert().from_montgomery()
    }
}


/// Read one or more u64s stored as little endian bytes.
///
/// ## Panics
/// Panics if `src.len() != 8 * dst.len()`.
fn read_le_u64_into(src: &[u8], dst: &mut [u64]) {
    assert!(
        src.len() == 8 * dst.len(),
        "src.len() = {}, dst.len() = {}",
        src.len(),
        dst.len()
    );
    for (bytes, val) in src.chunks(8).zip(dst.iter_mut()) {
        *val = u64::from_le_bytes(
            bytes
                .try_into()
                .expect("Incorrect src length, should be 8 * dst.len()"),
        );
    }
}

/// _Clamps_ the given little-endian representation of a 32-byte integer. Clamping the value puts
/// it in the range:
///
/// **n ∈ 2^254 + 8\*{0, 1, 2, 3, . . ., 2^251 − 1}**
///
/// # Explanation of clamping
///
/// For Curve25519, h = 8, and multiplying by 8 is the same as a binary left-shift by 3 bits.
/// If you take a secret scalar value between 2^251 and 2^252 – 1 and left-shift by 3 bits
/// then you end up with a 255-bit number with the most significant bit set to 1 and
/// the least-significant three bits set to 0.
///
/// The Curve25519 clamping operation takes **an arbitrary 256-bit random value** and
/// clears the most-significant bit (making it a 255-bit number), sets the next bit, and then
/// clears the 3 least-significant bits. In other words, it directly creates a scalar value that is
/// in the right form and pre-multiplied by the cofactor.
///
/// See [here](https://neilmadden.blog/2020/05/28/whats-the-curve25519-clamping-all-about/) for
/// more details.
#[must_use]
pub const fn clamp_integer(mut bytes: [u8; 32]) -> [u8; 32] {
    bytes[0] &= 0b1111_1000;
    bytes[31] &= 0b0111_1111;
    bytes[31] |= 0b0100_0000;
    bytes
}
