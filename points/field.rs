#![allow(unused_qualifications)]

use cfg_if::cfg_if;

// 系统函数
use subtle::Choice;
use subtle::ConditionallyNegatable;
use subtle::ConditionallySelectable;
use subtle::ConstantTimeEq;

use crate::backend;
use crate::constants;

cfg_if! {
    if #[cfg(curve25519_dalek_backend = "fiat")] {
        #[cfg(curve25519_dalek_bits = "32")]
        pub(crate) type FieldElement = backend::serial::fiat_u32::field::FieldElement2625;
        #[cfg(curve25519_dalek_bits = "64")]
        pub(crate) type FieldElement = backend::serial::fiat_u64::field::FieldElement51;
    } else if #[cfg(curve25519_dalek_bits = "64")] {
        pub(crate) type FieldElement = backend::serial::u64::field::FieldElement51;
    } else {
        pub(crate) type FieldElement = backend::serial::u32::field::FieldElement2625;
    }
}

impl Eq for FieldElement {}

impl PartialEq for FieldElement {
    fn eq(&self, other: &FieldElement) -> bool {
        self.ct_eq(other).into()
    }
}

// 将FieldElement转换为字节表示（as_bytes），然后比较字节序列
// 
impl ConstantTimeEq for FieldElement {
    fn ct_eq(&self, other: &FieldElement) -> Choice {
        self.as_bytes().ct_eq(&other.as_bytes())
    }
}



// 例如这种用法
// pub struct EdwardsPoint {
//     pub(crate) X: FieldElement,
//     pub(crate) Y: FieldElement,
//     pub(crate) Z: FieldElement,
//     pub(crate) T: FieldElement,
// }

impl FieldElement {
    /// Determine if this `FieldElement` is negative, in the sense
    /// used in the ed25519 paper: `x` is negative if the low bit is
    /// set.
    ///
    /// # Return
    ///
    /// If negative, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    // 检查 FieldElement 是否为 负数
    // 根据 Ed25519 论文的定义（最低位是否为 1）
    // ristretto.rs 中 RistrettoPoint 和 CompressedRistretto 中调用
    pub(crate) fn is_negative(&self) -> Choice {
        let bytes = self.as_bytes();
        (bytes[0] & 1).into()
    }

    /// Determine if this `FieldElement` is zero.
    ///
    /// # Return
    ///
    /// If zero, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    // 检查 FieldElement 是否为零，通过与零字节序列比较
    // 只有ristretto.rs中 CompressedRistretto 的 decompress 中调用
    pub(crate) fn is_zero(&self) -> Choice {
        let zero = [0u8; 32];
        let bytes = self.as_bytes();

        bytes.ct_eq(&zero)
    }

    /// Compute (self^(2^250-1), self^11), used as a helper function
    /// within invert() and pow22523().
    // 可能可以不需要, 只有下方 代码中有调用
    // 平方和乘法算法（square-and-multiply）优化大指数幂运算，通过重复平方（square）和乘法（*）构建复杂的指数
    #[rustfmt::skip] // keep alignment of explanatory comments
    fn pow22501(&self) -> (FieldElement, FieldElement) {
        // Instead of managing which temporary variables are used
        // for what, we define as many as we need and leave stack
        // allocation to the compiler
        //
        // Each temporary variable t_i is of the form (self)^e_i.
        // Squaring t_i corresponds to multiplying e_i by 2,
        // so the pow2k function shifts e_i left by k places.
        // Multiplying t_i and t_j corresponds to adding e_i + e_j.
        //
        // Temporary t_i                      Nonzero bits of e_i
        //
        let t0  = self.square();           // 1         e_0 = 2^1
        let t1  = t0.square().square();    // 3         e_1 = 2^3
        let t2  = self * &t1;              // 3,0       e_2 = 2^3 + 2^0
        let t3  = &t0 * &t2;               // 3,1,0
        let t4  = t3.square();             // 4,2,1
        let t5  = &t2 * &t4;               // 4,3,2,1,0
        let t6  = t5.pow2k(5);             // 9,8,7,6,5
        let t7  = &t6 * &t5;               // 9,8,7,6,5,4,3,2,1,0
        let t8  = t7.pow2k(10);            // 19..10
        let t9  = &t8 * &t7;               // 19..0
        let t10 = t9.pow2k(20);            // 39..20
        let t11 = &t10 * &t9;              // 39..0
        let t12 = t11.pow2k(10);           // 49..10
        let t13 = &t12 * &t7;              // 49..0
        let t14 = t13.pow2k(50);           // 99..50
        let t15 = &t14 * &t13;             // 99..0
        let t16 = t15.pow2k(100);          // 199..100
        let t17 = &t16 * &t15;             // 199..0
        let t18 = t17.pow2k(50);           // 249..50
        let t19 = &t18 * &t13;             // 249..0

        (t19, t3)
    }

    /// Given a slice of pub(crate)lic `FieldElements`, replace each with its inverse.
    ///
    /// When an input `FieldElement` is zero, its value is unchanged.
    // 只有在 RistrettoPoint 类中 调用
    // 主要功能:  对出入的一组FieldElement 进行批量求逆操作
    // 每个非零元素 替换为 其乘法逆
    // 零元素保持不变
    #[cfg(feature = "alloc")]
    pub(crate) fn batch_invert(inputs: &mut [FieldElement]) {
        // Montgomery’s Trick and Fast Implementation of Masked AES
        // Genelle, Prouff and Quisquater
        // Section 3.2

        let n = inputs.len();
        let mut scratch = vec![FieldElement::ONE; n];

        // Keep an accumulator of all of the previous products
        let mut acc = FieldElement::ONE;

        // Pass through the input vector, recording the previous
        // products in the scratch space
        for (input, scratch) in inputs.iter().zip(scratch.iter_mut()) {
            *scratch = acc;
            // acc <- acc * input, but skipping zeros (constant-time)
            acc.conditional_assign(&(&acc * input), !input.is_zero());
        }

        // acc is nonzero because we skipped zeros in inputs
        assert!(bool::from(!acc.is_zero()));

        // Compute the inverse of all products
        acc = acc.invert();

        // Pass through the vector backwards to compute the inverses
        // in place
        for (input, scratch) in inputs.iter_mut().rev().zip(scratch.into_iter().rev()) {
            let tmp = &acc * input;
            // input <- acc * scratch, then acc <- tmp
            // Again, we skip zeros in a constant-time way
            let nz = !input.is_zero();
            input.conditional_assign(&(&acc * &scratch), nz);
            acc.conditional_assign(&tmp, nz);
        }
    }

    /// Given a nonzero field element, compute its inverse.
    ///
    /// The inverse is computed as self^(p-2), since
    /// x^(p-2)x = x^(p-1) = 1 (mod p).
    ///
    /// This function returns zero on input zero.
    //  EdwardsPoint 中调用 
    // 主要功能 是   返回 给定参数 的 乘法 逆元
    #[rustfmt::skip] // keep alignment of explanatory comments
    #[allow(clippy::let_and_return)]
    pub(crate) fn invert(&self) -> FieldElement {
        // The bits of p-2 = 2^255 -19 -2 are 11010111111...11.
        //
        //                                 nonzero bits of exponent
        let (t19, t3) = self.pow22501();   // t19: 249..0 ; t3: 3,1,0
        let t20 = t19.pow2k(5);            // 254..5
        let t21 = &t20 * &t3;              // 254..5,3,1,0

        t21
    }

    /// Raise this field element to the power (p-5)/8 = 2^252 -3.
    // 可能不需要,  只在sqrt_ratio_i 中调用
    #[rustfmt::skip] // keep alignment of explanatory comments
    #[allow(clippy::let_and_return)]
    fn pow_p58(&self) -> FieldElement {
        // The bits of (p-5)/8 are 101111.....11.
        //
        //                                 nonzero bits of exponent
        let (t19, _) = self.pow22501();    // 249..0
        let t20 = t19.pow2k(2);            // 251..2
        let t21 = self * &t20;             // 251..2,0

        t21
    }

    /// Given `FieldElements` `u` and `v`, compute either `sqrt(u/v)`
    /// or `sqrt(i*u/v)` in constant time.
    ///
    /// This function always returns the nonnegative square root.
    ///
    /// # Return
    ///
    /// - `(Choice(1), +sqrt(u/v))  ` if `v` is nonzero and `u/v` is square;
    /// - `(Choice(1), zero)        ` if `u` is zero;
    /// - `(Choice(0), zero)        ` if `v` is zero and `u` is nonzero;
    /// - `(Choice(0), +sqrt(i*u/v))` if `u/v` is nonsquare (so `i*u/v` is square).
    ///
    // sqrt_ratio_i 在 Edwords.rs中的 CompressedEdwardsY 和 ristretto.rs中 RistrettoPoint 调用
    // 传入   u(平方根分子)   和     v(平方根分母)
    // 输出 一个 元组
    //     Choice(1)  真        Choice(0)  假
    //     始终返回非负平方根 或 0
    pub(crate) fn sqrt_ratio_i(u: &FieldElement, v: &FieldElement) -> (Choice, FieldElement) {
        let v3 = &v.square() * v;
        let v7 = &v3.square() * v;
        let mut r = &(u * &v3) * &(u * &v7).pow_p58();
        let check = v * &r.square();

        let i = &constants::SQRT_M1;

        let correct_sign_sqrt = check.ct_eq(u);
        let flipped_sign_sqrt = check.ct_eq(&(-u));
        let flipped_sign_sqrt_i = check.ct_eq(&(&(-u) * i));

        let r_prime = &constants::SQRT_M1 * &r;
        r.conditional_assign(&r_prime, flipped_sign_sqrt | flipped_sign_sqrt_i);

        // Choose the nonnegative square root.
        let r_is_negative = r.is_negative();
        r.conditional_negate(r_is_negative);

        let was_nonzero_square = correct_sign_sqrt | flipped_sign_sqrt;

        (was_nonzero_square, r)
    }

    /// Attempt to compute `sqrt(1/self)` in constant time.
    ///
    /// Convenience wrapper around `sqrt_ratio_i`.
    ///
    /// This function always returns the nonnegative square root.
    ///
    /// # Return
    ///
    /// - `(Choice(1), +sqrt(1/self))  ` if `self` is a nonzero square;
    /// - `(Choice(0), zero)           ` if `self` is zero;
    /// - `(Choice(0), +sqrt(i/self))  ` if `self` is a nonzero nonsquare;
    ///
    // 这个在 RistrettoPoint中调用了
    pub(crate) fn invsqrt(&self) -> (Choice, FieldElement) {
        FieldElement::sqrt_ratio_i(&FieldElement::ONE, self)
    }
}

