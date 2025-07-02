#![allow(unused_qualifications)]

use cfg_if::cfg_if;

// 系统函数
use subtle::Choice;
use subtle::ConditionallyNegatable;
use subtle::ConditionallySelectable;
use subtle::ConstantTimeEq;

use crate::backend;
use crate::constants;

pub(crate) type FieldElement = backend::serial::u64::field::FieldElement51;

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

    pub(crate) fn is_negative(&self) -> Choice {
        let bytes = self.as_bytes();
        (bytes[0] & 1).into()
    }

    pub(crate) fn is_zero(&self) -> Choice {
        let zero = [0u8; 32];
        let bytes = self.as_bytes();

        bytes.ct_eq(&zero)
    }

    // 模逆元
    #[rustfmt::skip] // keep alignment of explanatory comments
    #[allow(clippy::let_and_return)]
    pub(crate) fn invert(&self) -> FieldElement {
        if bool::from(self.is_zero()) {
            FieldElement51([0u64; 4])
        } else {
            let result = ffi_sm2_z256_modp_mont_inv(&self.0)
                .expect("FFI modular inverse failed");
            FieldElement51(result)
        }
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
        // 边界检查

		if (sm2_z256_is_odd(y)) { // true 取反
			sm2_z256_modp_neg(P->Y, P->Y);
		}

        if bool::from(v.is_zero()) && !bool::from(u.is_zero()) {
            return (Choice::from(0), FieldElement51([0u64; 4]));
        }
        if bool::from(u.is_zero()) {
            return (Choice::from(1), FieldElement51([0u64; 4]));
        }

        // 计算 u/v = u * v^{-1}
        let v_mont = ffi_sm2_z256_modp_to_mont(&v.0).expect("FFI to Montgomery failed");
        let v_inv = FieldElement51(v_mont).invert();
        let uv = u * &v_inv;

        // 转换为 Montgomery 域
        let uv_mont = ffi_sm2_z256_modp_to_mont(&uv.0).expect("FFI to Montgomery failed");

        // 尝试 sqrt(u/v)
        match ffi_sm2_z256_modp_mont_sqrt(&uv_mont) {
            Ok(sqrt) => {
                let r = FieldElement51(ffi_sm2_z256_modp_from_mont(&sqrt).expect("FFI from Montgomery failed"));
                let r_is_negative = r.is_negative();
                let mut r = r;
                r.conditional_negate(r_is_negative);
                (Choice::from(1), r)
            }
            Err(_) => {
                // 尝试 sqrt(i*u/v)
                let i = FieldElement51::SQRT_M1();
                let iu = &i * &uv;
                let iu_mont = ffi_sm2_z256_modp_to_mont(&iu.0).expect("FFI to Montgomery failed");
                match ffi_sm2_z256_modp_mont_sqrt(&iu_mont) {
                    Ok(sqrt) => {
                        let r = FieldElement51(ffi_sm2_z256_modp_from_mont(&sqrt).expect("FFI from Montgomery failed"));
                        let r_is_negative = r.is_negative();
                        let mut r = r;
                        r.conditional_negate(r_is_negative);
                        (Choice::from(0), r)
                    }
                    Err(e) => panic!("FFI sqrt failed: {}", e),
                }
            }
        }
    }

    /// SM2 的 sqrt(-1) mod p
    pub fn SQRT_M1() -> FieldElement51 {
        // 预计算 sqrt(-1) mod p = 2^256 - 2^224 - 2^96 + 2^64 - 1
        // 或通过 FFI 计算
        let minus_one = FieldElement51([u64::MAX, u64::MAX, u64::MAX, u64::MAX - 1]); // -1 mod p
        let minus_one_mont = ffi_sm2_z256_modp_to_mont(&minus_one.0).expect("FFI to Montgomery failed");
        let sqrt_m1 = ffi_sm2_z256_modp_mont_sqrt(&minus_one_mont).expect("FFI sqrt failed");
        FieldElement51(ffi_sm2_z256_modp_from_mont(&sqrt_m1).expect("FFI from Montgomery failed"))
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

