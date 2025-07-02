use core::fmt::Debug;
use core::ops::Neg;
use core::ops::{Add, AddAssign};
use core::ops::{Mul, MulAssign};
use core::ops::{Sub, SubAssign};

// 使用sm2_dalek中的SM2函数
use sm2_dalek::*;

use subtle::Choice;
use subtle::ConditionallySelectable;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;


// 32字节，对应uint64_t sm2_z256_t[4];
// 代表有限域上的一个元素，坐标X、Y、Z之类
#[derive(Copy, Clone)]
pub struct FieldElement51(pub(crate) [u64; 4]); 

impl Debug for FieldElement51 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "FieldElement51({:?})", &self.0[..])
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for FieldElement51 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

// a += b
impl<'b> AddAssign<&'b FieldElement51> for FieldElement51 {
    fn add_assign(&mut self, _rhs: &'b FieldElement51) {
        self.0 = ffi_sm2_z256_modp_add(&self.0, &_rhs.0)
            .expect("FFI modular addition failed");
    }
}

// c = a + b
impl<'a, 'b> Add<&'b FieldElement51> for &'a FieldElement51 {
    type Output = FieldElement51;
    fn add(self, _rhs: &'b FieldElement51) -> FieldElement51 {
        let result = ffi_sm2_z256_modp_add(&self.0, &_rhs.0)
            .expect("FFI modular addition failed");
        FieldElement51(result)
    }
}

// a -= b
impl<'b> SubAssign<&'b FieldElement51> for FieldElement51 {
    fn sub_assign(&mut self, _rhs: &'b FieldElement51) {
        self.0 = ffi_sm2_z256_modp_sub(&self.0, &_rhs.0)
            .expect("FFI modular subtraction failed");
    }
}

// c = a - b
impl<'a, 'b> Sub<&'b FieldElement51> for &'a FieldElement51 {
    type Output = FieldElement51;
    fn sub(self, _rhs: &'b FieldElement51) -> FieldElement51 {
        let result = ffi_sm2_z256_modp_sub(&self.0, &_rhs.0)
            .expect("FFI modular subtraction failed");
        FieldElement51(result)
    }
}

// a *= b
impl<'b> MulAssign<&'b FieldElement51> for FieldElement51 {
    fn mul_assign(&mut self, _rhs: &'b FieldElement51) {
        let self_mont = ffi_sm2_z256_modp_to_mont(&self.0);

        let rhs_mont = ffi_sm2_z256_modp_to_mont(&_rhs.0);

        let result_mont = ffi_sm2_z256_modp_mont_mul(&self_mont, &rhs_mont);

        self.0 = ffi_sm2_z256_modp_from_mont(&result_mont);
    }
}

// c = a * b
impl<'a, 'b> Mul<&'b FieldElement51> for &'a FieldElement51 {
    type Output = FieldElement51;

    fn mul(self, _rhs: &'b FieldElement51) -> FieldElement51 {

        let self_mont = ffi_sm2_z256_modp_to_mont(&self.0);
        let rhs_mont = ffi_sm2_z256_modp_to_mont(&_rhs.0);

        let result_mont = ffi_sm2_z256_modp_mont_mul(&self_mont, &rhs_mont);

        let result = ffi_sm2_z256_modp_from_mont(&result_mont);

        FieldElement51(result)
    }
}

// b = -a
impl<'a> Neg for &'a FieldElement51 {
    type Output = FieldElement51;

    // 这个不需要改动，直接调用下方的negate函数
    fn neg(self) -> FieldElement51 {
        let mut output = *self;
        output.negate();
        output
    }
}

// 防止时序攻击，确保执行时间不依赖于 choice 的值
// 在密码学中（例如 SM2 或 Curve25519 的实现），条件选择或交换操作必须是常量时间的，以防止时序攻击。
// 普通布尔条件（如 if）会导致时间差异，泄露敏感信息（例如私钥或标量位）
impl ConditionallySelectable for FieldElement51 {
    // 从两个 FieldElement51（a 和 b）中选择一个返回，基于 choice。
    fn conditional_select(
        a: &FieldElement51,
        b: &FieldElement51,
        choice: Choice,
    ) -> FieldElement51 {
        FieldElement51([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
        ])
    }

    // 条件性地交换两个 FieldElement51 的内容，基于 choice
    fn conditional_swap(a: &mut FieldElement51, b: &mut FieldElement51, choice: Choice) {
        u64::conditional_swap(&mut a.0[0], &mut b.0[0], choice);
        u64::conditional_swap(&mut a.0[1], &mut b.0[1], choice);
        u64::conditional_swap(&mut a.0[2], &mut b.0[2], choice);
        u64::conditional_swap(&mut a.0[3], &mut b.0[3], choice);
    }

    // 条件性地将一个 FieldElement51 的值赋给另一个，基于 choice
    fn conditional_assign(&mut self, other: &FieldElement51, choice: Choice) {
        self.0[0].conditional_assign(&other.0[0], choice);
        self.0[1].conditional_assign(&other.0[1], choice);
        self.0[2].conditional_assign(&other.0[2], choice);
        self.0[3].conditional_assign(&other.0[3], choice);
    }
}

impl FieldElement51 {
    pub(crate) const fn from_limbs(limbs: [u64; 4]) -> FieldElement51 {
        FieldElement51(limbs)
    }

    /// The scalar \\( 0 \\).
    pub const ZERO: FieldElement51 = FieldElement51::from_limbs([0, 0, 0, 0]);
    /// The scalar \\( 1 \\).
    pub const ONE: FieldElement51 = FieldElement51::from_limbs([1, 0, 0, 0]);
    /// The scalar \\( -1 \\).
    /// p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    // p[0] - 1 = 0xFFFFFFFFFFFFFFFF - 1 = 0xFFFFFFFFFFFFFFFE
    pub const MINUS_ONE: FieldElement = FieldElement([
        0xFFFFFFFFFFFFFFFE, // 低 64 位 -1
        0x00000000FFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFEFFFFFFFF,
    ]);
    

    /// 自身取反
    /// -&a
    pub fn negate(&mut self) {
        unsafe {
            let mut result = [0u64; 4];
            result = ffi_sm2_z256_modp_neg(&self.0);
            self.0 = result;
        }
    }

    // 字节数组转域
    #[rustfmt::skip]
    pub fn from_bytes(bytes: &[u8; 32]) -> FieldElement51 {
        let limbs = ffi_sm2_z256_from_bytes(&bytes);
        FieldElement51(limbs)
    }

    // 域转字节数组
    #[rustfmt::skip]
    pub fn as_bytes(&self) -> [u8; 32] {
        ffi_sm2_z256_to_bytes(&self.0)
    }

    /// Given `k > 0`, return `self^(2^k)`.
    // 也就是计算 self 的 2^k 次幂
    // 基于 SM2 FFI 的模平方实现
    #[rustfmt::skip] // keep alignment of c* calculations
    pub fn pow2k(&self, mut k: u32) -> FieldElement51 {

        debug_assert!( k > 0 );

        let mut result = self.0;
        let mut temp = [0u64; 4];

        result = ffi_sm2_z256_modp_to_mont(&result);


        while k > 0 {
            temp = ffi_sm2_z256_modp_mont_sqr(&result);
            result.copy_from_slice(&temp);
            k -= 1;
        }

        result = ffi_sm2_z256_modp_from_mont(&result);

        FieldElement51(result)
    }

    pub fn square(&self) -> FieldElement51 {
        self.pow2k(1)
    }

    // 平方
    pub fn square2(&self) -> FieldElement51 {
        let mut result = self.0;

        result = ffi_sm2_z256_modp_to_mont(&result);
    
        let squared = ffi_sm2_z256_modp_mont_sqr(&result);
    
        result = ffi_sm2_z256_modp_from_mont(&squared);
    
        FieldElement51(result)
    }
}
