
// 这个文件是 Rust 中 trait 系统和 模块化设计 所需
// trait 定义与实现分离 的标准模式
// 模块化设计 
// 代码复用

#![allow(non_snake_case)]

use core::borrow::Borrow;

use crate::scalar::{clamp_integer, Scalar};
use subtle::ConstantTimeEq;

// ------------------------------------------------------------------------
// Public Traits
// ------------------------------------------------------------------------

pub trait Identity {
    
    fn identity() -> Self;
}

pub trait IsIdentity {
    fn is_identity(&self) -> bool;
}

/// Implement generic identity equality testing for a point representations
/// which have constant-time equality testing and a defined identity
/// constructor.
impl<T> IsIdentity for T
where
    T: ConstantTimeEq + Identity,
{
    fn is_identity(&self) -> bool {
        self.ct_eq(&T::identity()).into()
    }
}

/// A precomputed table of basepoints, for optimising scalar multiplications.
pub trait BasepointTable {
    /// The type of point contained within this table.
    type Point;

    /// Generate a new precomputed basepoint table from the given basepoint.
    fn create(basepoint: &Self::Point) -> Self;

    /// Retrieve the original basepoint from this table.
    fn basepoint(&self) -> Self::Point;

    /// Multiply a `scalar` by this precomputed basepoint table, in constant time.
    fn mul_base(&self, scalar: &Scalar) -> Self::Point;

    /// Multiply `clamp_integer(bytes)` by this precomputed basepoint table, in constant time. For
    /// a description of clamping, see [`clamp_integer`].
    fn mul_base_clamped(&self, bytes: [u8; 32]) -> Self::Point {
        // Basepoint multiplication is defined for all values of `bytes` up to and including
        // 2^255 - 1. The limit comes from the fact that scalar.as_radix_16() doesn't work for
        // most scalars larger than 2^255.
        let s = Scalar {
            bytes: clamp_integer(bytes),
        };
        self.mul_base(&s)
    }
}


// 定义MultiscalarMul抽象接口
// 定义了如何对一组标量和一组点进行多标量乘法操作
// 主要用于 其他结构体 进行实现
pub trait MultiscalarMul {
    /// The type of point being multiplied, e.g., `RistrettoPoint`.
    type Point;

    fn multiscalar_mul<I, J>(scalars: I, points: J) -> Self::Point
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator,
        J::Item: Borrow<Self::Point>;
}


// 定义VartimeMultiscalarMul抽象接口
// 强调变时（variable-time）操作，意味着计算时间可能依赖于输入数据，
// 通常比恒定时间（constant-time）的 MultiscalarMul 更快，但在某些场景下可能不安全（例如，可能泄露信息给侧信道攻击）
pub trait VartimeMultiscalarMul {
    /// The type of point being multiplied, e.g., `RistrettoPoint`.
    type Point;

    fn optional_multiscalar_mul<I, J>(scalars: I, points: J) -> Option<Self::Point>
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator<Item = Option<Self::Point>>;

    
    fn vartime_multiscalar_mul<I, J>(scalars: I, points: J) -> Self::Point
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator,
        J::Item: Borrow<Self::Point>,
        Self::Point: Clone,
    {
        Self::optional_multiscalar_mul(
            scalars,
            points.into_iter().map(|P| Some(P.borrow().clone())),
        )
        .expect("should return some point")
    }
}

/// A trait for variable-time multiscalar multiplication with precomputation.
///
/// A general multiscalar multiplication with precomputation can be written as
/// $$
/// Q = a_1 A_1 + \cdots + a_n A_n + b_1 B_1 + \cdots + b_m B_m,
/// $$
/// where the \\(B_i\\) are *static* points, for which precomputation
/// is possible, and the \\(A_j\\) are *dynamic* points, for which
/// precomputation is not possible.
///
/// This trait has three methods for performing this computation:
///
/// * [`Self::vartime_multiscalar_mul`], which handles the special case where
///   \\(n = 0\\) and there are no dynamic points;
///
/// * [`Self::vartime_mixed_multiscalar_mul`], which takes the dynamic points as
///   already-validated `Point`s and is infallible;
///
/// * [`Self::optional_mixed_multiscalar_mul`], which takes the dynamic points
///   as `Option<Point>`s and returns an `Option<Point>`, allowing decompression
///   to be composed into the input iterators.
///
/// All methods require that the lengths of the input iterators be
/// known and matching, as if they were `ExactSizeIterator`s.  (It
/// does not require `ExactSizeIterator` only because that trait is
/// broken).
pub trait VartimePrecomputedMultiscalarMul: Sized {
    /// The type of point to be multiplied, e.g., `RistrettoPoint`.
    type Point: Clone;

    /// Given the static points \\( B_i \\), perform precomputation
    /// and return the precomputation data.
    fn new<I>(static_points: I) -> Self
    where
        I: IntoIterator,
        I::Item: Borrow<Self::Point>;

    /// Given `static_scalars`, an iterator of public scalars
    /// \\(b_i\\), compute
    /// $$
    /// Q = b_1 B_1 + \cdots + b_m B_m,
    /// $$
    /// where the \\(B_j\\) are the points that were supplied to `new`.
    ///
    /// It is an error to call this function with iterators of
    /// inconsistent lengths.
    ///
    /// The trait bound aims for maximum flexibility: the input must
    /// be convertable to iterators (`I: IntoIter`), and the
    /// iterator's items must be `Borrow<Scalar>`, to allow iterators
    /// returning either `Scalar`s or `&Scalar`s.
    fn vartime_multiscalar_mul<I>(&self, static_scalars: I) -> Self::Point
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
    {
        use core::iter;

        Self::vartime_mixed_multiscalar_mul(
            self,
            static_scalars,
            iter::empty::<Scalar>(),
            iter::empty::<Self::Point>(),
        )
    }

    /// Given `static_scalars`, an iterator of public scalars
    /// \\(b_i\\), `dynamic_scalars`, an iterator of public scalars
    /// \\(a_i\\), and `dynamic_points`, an iterator of points
    /// \\(A_i\\), compute
    /// $$
    /// Q = a_1 A_1 + \cdots + a_n A_n + b_1 B_1 + \cdots + b_m B_m,
    /// $$
    /// where the \\(B_j\\) are the points that were supplied to `new`.
    ///
    /// It is an error to call this function with iterators of
    /// inconsistent lengths.
    ///
    /// The trait bound aims for maximum flexibility: the inputs must be
    /// convertable to iterators (`I: IntoIter`), and the iterator's items
    /// must be `Borrow<Scalar>` (or `Borrow<Point>`), to allow
    /// iterators returning either `Scalar`s or `&Scalar`s.
    fn vartime_mixed_multiscalar_mul<I, J, K>(
        &self,
        static_scalars: I,
        dynamic_scalars: J,
        dynamic_points: K,
    ) -> Self::Point
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator,
        J::Item: Borrow<Scalar>,
        K: IntoIterator,
        K::Item: Borrow<Self::Point>,
    {
        Self::optional_mixed_multiscalar_mul(
            self,
            static_scalars,
            dynamic_scalars,
            dynamic_points.into_iter().map(|P| Some(P.borrow().clone())),
        )
        .expect("should return some point")
    }

    /// Given `static_scalars`, an iterator of public scalars
    /// \\(b_i\\), `dynamic_scalars`, an iterator of public scalars
    /// \\(a_i\\), and `dynamic_points`, an iterator of points
    /// \\(A_i\\), compute
    /// $$
    /// Q = a_1 A_1 + \cdots + a_n A_n + b_1 B_1 + \cdots + b_m B_m,
    /// $$
    /// where the \\(B_j\\) are the points that were supplied to `new`.
    ///
    /// If any of the dynamic points were `None`, return `None`.
    ///
    /// It is an error to call this function with iterators of
    /// inconsistent lengths.
    ///
    /// This function is particularly useful when verifying statements
    /// involving compressed points.  Accepting `Option<Point>` allows
    /// inlining point decompression into the multiscalar call,
    /// avoiding the need for temporary buffers.
    fn optional_mixed_multiscalar_mul<I, J, K>(
        &self,
        static_scalars: I,
        dynamic_scalars: J,
        dynamic_points: K,
    ) -> Option<Self::Point>
    where
        I: IntoIterator,
        I::Item: Borrow<Scalar>,
        J: IntoIterator,
        J::Item: Borrow<Scalar>,
        K: IntoIterator<Item = Option<Self::Point>>;
}

// ------------------------------------------------------------------------
// Private Traits
// ------------------------------------------------------------------------

/// Trait for checking whether a point is on the curve.
///
/// This trait is only for debugging/testing, since it should be
/// impossible for a `curve25519-dalek` user to construct an invalid
/// point.
#[allow(dead_code)]
pub(crate) trait ValidityCheck {
    /// Checks whether the point is on the curve. Not CT.
    fn is_valid(&self) -> bool;
}
